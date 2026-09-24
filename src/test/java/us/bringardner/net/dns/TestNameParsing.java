/**
 * <PRE>
 * 
 * Copyright Tony Bringarder 1998, 2025 <A href="http://bringardner.com/tony">Tony Bringardner</A>
 * 
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       <A href="http://www.apache.org/licenses/LICENSE-2.0">http://www.apache.org/licenses/LICENSE-2.0</A>
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *  </PRE>
 *   
 *   
 *	@author Tony Bringardner   
 */
package us.bringardner.net.dns;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import java.io.ByteArrayOutputStream;
import java.time.Duration;

import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.server.UDPProsessor;

/**
 * Offline tests (no network, no server) for hardened name decompression.
 * Each hostile case must fail fast with DnsFormatException, never loop,
 * overflow the stack or exhaust memory.
 */
public class TestNameParsing {

	private static final Duration FAST = Duration.ofSeconds(2);

	/** 12 byte query header: ID=0x1234, RD=1, QDCOUNT=1 */
	private static final byte [] HEADER = {
			0x12,0x34, 0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00
	};

	private static byte [] bytes(int ... v) {
		byte [] ret = new byte[v.length];
		for(int i=0; i< v.length; i++ ) {
			ret[i] = (byte)v[i];
		}
		return ret;
	}

	private static byte [] concat(byte [] ... parts) {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		for(byte [] p : parts) {
			out.write(p,0,p.length);
		}
		return out.toByteArray();
	}

	/** Parse a Name starting at offset start of buf */
	private static Name parse(byte [] buf, int start) {
		return new Name(new ByteBuffer(buf,start));
	}

	private static void assertFormatError(byte [] buf, int start) {
		assertTimeoutPreemptively(FAST, () -> {
			assertThrows(DnsFormatException.class, () -> parse(buf,start));
		});
	}

	@Test
	public void plainName() {
		byte [] buf = bytes(3,'w','w','w',7,'e','x','a','m','p','l','e',3,'c','o','m',0);
		ByteBuffer in = new ByteBuffer(buf,0);
		Name n = new Name(in);
		assertEquals("www.example.com", n.toString());
		assertEquals(buf.length, in.getReadPos(), "caller's buffer must be advanced past the name");
	}

	@Test
	public void validCompressedName() {
		// offset 0: example.com   offset 13: www + pointer to 0
		byte [] buf = bytes(7,'e','x','a','m','p','l','e',3,'c','o','m',0,
				3,'w','w','w',0xC0,0x00,
				0xAA); // trailing byte must not be consumed
		ByteBuffer in = new ByteBuffer(buf,13);
		Name n = new Name(in);
		assertEquals("www.example.com", n.toString());
		assertEquals(19, in.getReadPos(), "caller's buffer must stop right after the pointer");
	}

	@Test
	public void chainedBackwardPointers() {
		// 0: com  5: example -> 0   15: www -> 5
		byte [] buf = bytes(3,'c','o','m',0,
				7,'e','x','a','m','p','l','e',0xC0,0x00,
				3,'w','w','w',0xC0,0x05);
		assertEquals("www.example.com", parse(buf,15).toString());
	}

	@Test
	public void pointerToItself() {
		byte [] buf = concat(HEADER, bytes(0xC0,12));
		assertFormatError(buf,12);
	}

	@Test
	public void pointerForwards() {
		byte [] buf = bytes(0xC0,0x04, 0,0, 3,'c','o','m',0);
		assertFormatError(buf,0);
	}

	@Test
	public void twoPointerLoop() {
		// 0: "a" -> 4    4: "b" -> 0   (second pointer goes backwards, but into the segment it came from)
		byte [] buf = bytes(1,'a',0xC0,0x04, 1,'b',0xC0,0x00);
		assertFormatError(buf,4);
		assertFormatError(buf,0);
	}

	@Test
	public void loopBackIntoLaterSegment() {
		// 20: "x" -> 10   10: "y" -> 12 (inside the segment that starts at 10) 
		byte [] buf = new byte[32];
		byte [] a = bytes(1,'y',0xC0,12);
		System.arraycopy(a,0,buf,10,a.length);
		byte [] b = bytes(1,'x',0xC0,10);
		System.arraycopy(b,0,buf,20,b.length);
		assertFormatError(buf,20);
	}

	@Test
	public void nameTooLong() {
		// 5 labels of 63 octets = 320 octets > 255
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		for(int l=0; l< 5; l++ ) {
			out.write(63);
			for(int i=0; i< 63; i++ ) {
				out.write('a');
			}
		}
		out.write(0);
		assertFormatError(out.toByteArray(),0);
	}

	@Test
	public void maxLengthNameIsAccepted() {
		// 3 x 63 + 1 x 61 labels = 4*1 + 250 + root(1) = 255 octets exactly
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int [] sizes = {63,63,63,61};
		for(int sz : sizes) {
			out.write(sz);
			for(int i=0; i< sz; i++ ) {
				out.write('a');
			}
		}
		out.write(0);
		byte [] buf = out.toByteArray();
		assertEquals(255, buf.length);
		parse(buf,0);
	}

	@Test
	public void labelRunsPastEnd() {
		assertFormatError(bytes(10,'a','b','c'),0);
	}

	@Test
	public void missingTerminator() {
		assertFormatError(bytes(3,'c','o','m'),0);
	}

	@Test
	public void truncatedPointer() {
		assertFormatError(bytes(3,'c','o','m',0xC0),0);
	}

	@Test
	public void reservedLabelTypes() {
		assertFormatError(bytes(0x40,0),0);
		assertFormatError(bytes(0x80,0),0);
	}

	@Test
	public void wholeMessageWithLoopedQuestion() {
		// Question name is a pointer to itself, followed by QTYPE/QCLASS
		byte [] pkt = concat(HEADER, bytes(0xC0,12, 0,1, 0,1));
		assertTimeoutPreemptively(FAST, () -> {
			assertThrows(DnsFormatException.class, () -> new Message(new ByteBuffer(pkt)));
		});
	}

	@Test
	public void formatErrorReply() {
		byte [] pkt = concat(HEADER, bytes(0xC0,12, 0,1, 0,1));
		byte [] reply = UDPProsessor.buildFormatError(pkt, pkt.length);
		// ID kept, QR=1, RD kept, RCODE=1, all counts 0
		assertArrayEquals(bytes(0x12,0x34, 0x81,0x01, 0,0, 0,0, 0,0, 0,0), reply);
	}

	@Test
	public void noFormatErrorForResponsesOrRunts() {
		byte [] response = HEADER.clone();
		response[2] |= 0x80;
		assertNull(UDPProsessor.buildFormatError(response, response.length));
		assertNull(UDPProsessor.buildFormatError(new byte[5], 5));
		assertNull(UDPProsessor.buildFormatError(null, 0));
	}
}
