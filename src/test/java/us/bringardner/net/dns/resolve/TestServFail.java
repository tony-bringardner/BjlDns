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
package us.bringardner.net.dns.resolve;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.List;

import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.A;
import us.bringardner.net.dns.ByteBuffer;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.Section;
import us.bringardner.net.dns.server.DnsServer;
import us.bringardner.net.dns.server.UDPProsessor;

/**
 * Offline tests: a recursive query that can't be answered gets SERVFAIL
 * instead of silence, and recursion works over TCP. No upstream servers are
 * configured, so every cache miss fails.
 */
public class TestServFail {

	private static Message request(String name, int id) {
		Message m = new Message();
		m.setQuestion(name, DNS.A, DNS.IN);
		m.setID(id);
		m.getHeader().setRD(true);
		return m;
	}

	private static DnsServer recursiveServer() {
		DnsServer s = new DnsServer();
		s.setRecursionAvailable(true);
		return s;
	}

	private static void cacheA(String name, String ip) {
		Message m = new Message();
		m.setQuestion(name, DNS.A, DNS.IN);
		m.setMessageTypeResponse();
		A a = new A(name);
		a.setAddress(ip);
		a.setTTL(300);
		m.addAnswer(a);
		Resolver.getCache().put(m);
	}

	@Test
	public void failureMessage() {
		QueryData q = new QueryData(InetAddress.getLoopbackAddress(), 5353, request("x.fail.test", 0x3344));
		Message f = ResolverThread.failure(q, DNS.SERVER_ERROR);
		Message wire = new Message(new ByteBuffer(f.toByteArray()));
		assertEquals(0x3344, wire.getID());
		assertTrue(wire.isResponse());
		assertTrue(wire.isRecursiveDesired());
		assertTrue(wire.getHeader().getRA());
		assertTrue(!wire.getHeader().getAA());
		assertEquals(DNS.SERVER_ERROR, wire.getResponseCode());
		assertEquals("x.fail.test", wire.getFirstQuestion().getName());
		assertEquals(0, wire.getAnswerCount());
	}

	@Test
	public void fullBacklogAnswersServfail() {
		ResolverThread.clearBacklog();
		try {
			DnsServer s = recursiveServer();
			int cap = ResolverThread.getMaxBackLog();
			for(int i=0; i< cap; i++ ) {
				List<Message> r = s.query(new QueryData(InetAddress.getLoopbackAddress(), 5353, request("q"+i+".fail.test", i)));
				assertNull(r.get(0), "queued: a resolver thread answers later");
			}
			long droppedBefore = ResolverThread.getDropped();
			List<Message> r = s.query(new QueryData(InetAddress.getLoopbackAddress(), 5353, request("over.fail.test", 999)));
			Message m = r.get(0);
			assertNotNull(m, "used to be dropped silently");
			assertEquals(DNS.SERVER_ERROR, m.getResponseCode());
			assertEquals(999, m.getID());
			assertEquals(droppedBefore+1, ResolverThread.getDropped());
		} finally {
			ResolverThread.clearBacklog();
		}
	}

	@Test
	public void tcpRecursionAnswers() {
		// TCP used to get an empty NOERROR answer with RA off
		Resolver.getCache().clear();
		cacheA("www.tcp.test", "10.0.0.42");
		DnsServer s = recursiveServer();
		Message m = s.query(new QueryData(InetAddress.getLoopbackAddress(), -1, request("www.tcp.test", 0x0404))).get(0);
		assertNotNull(m);
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertEquals(0x0404, m.getID());
		assertEquals(1, m.getAnswerCount());
		assertEquals("10.0.0.42", ((A)m.getAnswer().get(0)).getAddressString());
		Resolver.getCache().clear();
	}

	@Test
	public void tcpRecursionFailureIsServfail() {
		Resolver.getCache().clear();
		DnsServer s = recursiveServer();
		Message m = s.query(new QueryData(InetAddress.getLoopbackAddress(), -1, request("nothing.tcp.test", 0x0505))).get(0);
		assertNotNull(m);
		assertEquals(DNS.SERVER_ERROR, m.getResponseCode());
		assertEquals(0x0505, m.getID());
	}

	@Test
	public void resolverThreadSendsServfailToClient() throws Exception {
		// End to end: queued UDP query, resolution fails (no servers), the
		// client must receive SERVFAIL rather than nothing.
		ResolverThread.clearBacklog();
		Resolver.getCache().clear();
		int port;
		try(DatagramSocket probe = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
			port = probe.getLocalPort();
		}
		UDPProsessor.initUDPProsessor(port, InetAddress.getLoopbackAddress(), 200);
		ResolverThread rt = new ResolverThread();
		try(DatagramSocket client = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
			client.setSoTimeout(5000);
			rt.start("TestResolverThread");
			long failedBefore = ResolverThread.getFailed();
			QueryData q = new QueryData(InetAddress.getLoopbackAddress(), client.getLocalPort(), request("nothing.udp.test", 0x0606));
			assertTrue(ResolverThread.addQuery(q));

			byte [] buf = new byte[DNS.MAXUDPLEN];
			DatagramPacket p = new DatagramPacket(buf, buf.length);
			client.receive(p);
			Message m = new Message(new ByteBuffer(java.util.Arrays.copyOf(buf, p.getLength())));
			assertEquals(0x0606, m.getID());
			assertEquals(DNS.SERVER_ERROR, m.getResponseCode());
			assertEquals("nothing.udp.test", m.getFirstQuestion().getName());
			assertEquals(failedBefore+1, ResolverThread.getFailed());
		} finally {
			rt.stop();
			UDPProsessor.getSock().close();
			ResolverThread.clearBacklog();
		}
	}
}
