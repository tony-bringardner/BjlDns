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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

/**
 * Client-side fixes in Message: queryUDP(String) uses the given server, and
 * a query too large for UDP goes over TCP instead of being cut.
 */
public class TestCleanups {

	/** Echo a query back as a response. */
	private static byte [] answer(byte [] req, int len) {
		Message m = new Message(new ByteBuffer(java.util.Arrays.copyOf(req, len)));
		m.setMessageTypeResponse();
		m.getAdditional().clear();
		return m.toByteArray();
	}

	private static Message query(int extraTxt) {
		Message q = new Message();
		q.setQuestion("www.cleanup.test", DNS.A, DNS.IN);
		for(int i=0; i < extraTxt; i++ ) {
			Txt t = new Txt("pad"+i+".cleanup.test");
			t.setTTL(1);
			t.setText("0123456789012345678901234567890123456789");
			q.addAdditional(t);
		}
		return q;
	}

	@Test
	public void queryUdpByNameUsesThatServer() throws Exception {
		try(DatagramSocket srv = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
			srv.setSoTimeout(5000);
			Thread t = new Thread(() -> {
				try {
					byte [] buf = new byte[2048];
					DatagramPacket p = new DatagramPacket(buf, buf.length);
					srv.receive(p);
					byte [] r = answer(buf, p.getLength());
					srv.send(new DatagramPacket(r, r.length, p.getAddress(), p.getPort()));
				} catch(Exception ex) {
				}
			});
			t.start();
			Message q = query(0);
			q.setPort(srv.getLocalPort());
			// Used to ignore the argument and query svrAddress (null here)
			Message r = q.queryUDP("127.0.0.1");
			assertNotNull(r);
			assertTrue(r.isResponse());
			t.join(5000);
		}
	}

	@Test
	public void oversizedQueryUsesTcp() throws Exception {
		Message q = query(20);
		assertTrue(q.toByteArray().length > 512, "test query is over 512 bytes");
		AtomicInteger udp = new AtomicInteger();
		AtomicInteger tcp = new AtomicInteger();
		try(ServerSocket ss = new ServerSocket(0, 5, InetAddress.getLoopbackAddress());
				DatagramSocket ds = new DatagramSocket(ss.getLocalPort(), InetAddress.getLoopbackAddress())) {
			ss.setSoTimeout(5000);
			ds.setSoTimeout(5000);
			Thread u = new Thread(() -> {
				try {
					byte [] buf = new byte[4096];
					DatagramPacket p = new DatagramPacket(buf, buf.length);
					ds.receive(p);
					udp.incrementAndGet();
				} catch(Exception ex) {
				}
			});
			u.setDaemon(true);
			u.start();
			Thread t = new Thread(() -> {
				try(Socket s = ss.accept()) {
					DataInputStream in = new DataInputStream(s.getInputStream());
					int len = in.readUnsignedShort();
					byte [] req = new byte[len];
					in.readFully(req);
					tcp.incrementAndGet();
					byte [] r = answer(req, len);
					DataOutputStream out = new DataOutputStream(s.getOutputStream());
					out.writeShort(r.length);
					out.write(r);
					out.flush();
				} catch(Exception ex) {
				}
			});
			t.start();
			q.setPort(ss.getLocalPort());
			Message r = q.queryUDP(InetAddress.getLoopbackAddress());
			assertNotNull(r);
			assertTrue(r.isResponse());
			t.join(5000);
			assertEquals(1, tcp.get(), "sent over TCP");
			assertEquals(0, udp.get(), "not cut and sent over UDP");
		}
	}
}
