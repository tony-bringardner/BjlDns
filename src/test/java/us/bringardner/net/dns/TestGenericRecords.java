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

import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.resolve.Cache;

/**
 * Records of types this library has no class for (CAA, SRV, DS...) are kept
 * as generic RRs; their rdata must survive a parse / serialize round trip.
 */
public class TestGenericRecords {

	/** A response with an A record, a CAA (257) and an SRV (33) record, built as raw wire bytes. */
	private static byte [] wire() {
		ByteBuffer b = new ByteBuffer();
		Message m = new Message();
		m.setQuestion("example.test", 257, DNS.IN);
		m.setMessageTypeResponse();
		A a = new A("example.test");
		a.setAddress("10.0.0.1");
		a.setTTL(60);
		m.addAnswer(a);
		RR caa = new RR("example.test", 257, DNS.IN);
		caa.setRdata(new byte[] {0,5,'i','s','s','u','e','c','a','.','t','e','s','t'});
		caa.setTTL(300);
		m.addAnswer(caa);
		RR srv = new RR("_sip._tcp.example.test", 33, DNS.IN);
		srv.setRdata(new byte[] {0,10, 0,20, 0x13,(byte)0xc4, 3,'s','i','p',0});
		srv.setTTL(300);
		m.addAdditional(srv);
		return m.toByteArray();
	}

	@Test
	public void genericRecordsKeepTheirData() {
		byte [] w = wire();
		Message parsed = new Message(new ByteBuffer(w));
		assertEquals(2, parsed.getAnswerCount());
		RR caa = parsed.getAnswer().get(1);
		assertEquals(257, caa.getType());
		assertEquals(14, caa.getRdLength());
		assertArrayEquals(new byte[] {0,5,'i','s','s','u','e','c','a','.','t','e','s','t'}, caa.getRdata());
		assertEquals(33, parsed.getAdditional().get(0).getType());
	}

	@Test
	public void roundTripIsExact() {
		byte [] w = wire();
		// used to lose the rdata of the generic records: a corrupt message
		assertArrayEquals(w, new Message(new ByteBuffer(w)).toByteArray());
	}

	@Test
	public void throughTheResolverCache() {
		Cache c = new Cache(10);
		c.put(new Message(new ByteBuffer(wire())));
		Message out = c.get(new Section("example.test", 257, DNS.IN));
		Message client = new Message(new ByteBuffer(out.toByteArray()));
		assertEquals(2, client.getAnswerCount());
		assertArrayEquals(new byte[] {0,5,'i','s','s','u','e','c','a','.','t','e','s','t'}, client.getAnswer().get(1).getRdata());
		assertEquals(1, client.getAdditionalCount());
	}
}
