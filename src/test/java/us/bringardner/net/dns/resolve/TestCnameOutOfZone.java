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

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.A;
import us.bringardner.net.dns.ByteBuffer;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.server.DnsServer;
import us.bringardner.net.dns.server.UDPProsessor;
import us.bringardner.net.dns.server.Zone;

/**
 * Offline tests: a CNAME in a local zone that points outside our zones.
 * The client must get ONE response with the original question, the CNAME
 * and (with recursion) the target's records. It used to get the CNAME alone
 * and then a second response for the target's question with the same ID.
 */
public class TestCnameOutOfZone {

	private static File dir;
	private static Zone zone;

	@BeforeAll
	public static void setup() throws IOException {
		dir = Files.createTempDirectory("cnameout").toFile();
		File f = new File(dir,"out.test.txt");
		try(FileWriter w = new FileWriter(f)) {
			w.write("@\tIN\tSOA\tns1.out.test. postmaster.out.test. (\n"
					+"\t\t\t1 ; serial\n\t\t\t3600 ; refresh\n\t\t\t1800 ; retry\n"
					+"\t\t\t1209600 ; expire\n\t\t\t300 ) ; minimum\n\n"
					+"\t\tNS\tns1\n"
					+"ns1\tIN\tA\t10.0.0.53\n"
					+"www\tIN\tA\t10.0.0.80\n"
					+"loc\tIN\tCNAME\twww.out.test.\n"
					+"ext\tIN\tCNAME\twww.remote.example.\n");
		}
		zone = new Zone(f);
	}

	@AfterAll
	public static void cleanup() {
		for(File f : dir.listFiles()) {
			f.delete();
		}
		dir.delete();
	}

	private static DnsServer server(boolean recursion) {
		DnsServer s = new DnsServer();
		s.addZone(zone);
		s.setRecursionAvailable(recursion);
		return s;
	}

	private static Message request(String name, boolean rd, int id) {
		Message m = new Message();
		m.setQuestion(name, DNS.A, DNS.IN);
		m.setID(id);
		m.getHeader().setRD(rd);
		return m;
	}

	private static void cacheRemote() {
		Resolver.getCache().clear();
		Message m = new Message();
		m.setQuestion("www.remote.example", DNS.A, DNS.IN);
		m.setMessageTypeResponse();
		A a = new A("www.remote.example");
		a.setAddress("10.9.9.9");
		a.setTTL(300);
		m.addAnswer(a);
		Resolver.getCache().put(m);
	}

	private static int count(Message m, int type) {
		int n = 0;
		for(RR rr : m.getAnswer()) {
			if( rr.getType() == type ) {
				n++;
			}
		}
		return n;
	}

	@Test
	public void localChainUnchangedAndQuestionRestored() {
		QueryData q = new QueryData(InetAddress.getLoopbackAddress(), 5353, request("loc.out.test", true, 1));
		Message m = server(true).query(q).get(0);
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertEquals(1, count(m,DNS.CNAME));
		assertEquals(1, count(m,DNS.A));
		assertEquals("loc.out.test", q.getQuestion().getName(), "request's question restored");
	}

	@Test
	public void withoutRecursionChainIsTheAnswer() {
		// Used to be NXDOMAIN (the out-of-zone target went through step2 with RA off)
		Message m = server(false).query(new QueryData(InetAddress.getLoopbackAddress(), 5353, request("ext.out.test", true, 2))).get(0);
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertEquals(1, count(m,DNS.CNAME));
		assertEquals(0, count(m,DNS.A));
	}

	@Test
	public void recursionNotDesiredChainIsTheAnswer() {
		Message m = server(true).query(new QueryData(InetAddress.getLoopbackAddress(), 5353, request("ext.out.test", false, 3))).get(0);
		assertNotNull(m, "answered now, not queued");
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertEquals(1, count(m,DNS.CNAME));
	}

	@Test
	public void tcpGetsOneCompleteAnswer() {
		cacheRemote();
		QueryData q = new QueryData(InetAddress.getLoopbackAddress(), -1, request("ext.out.test", true, 4));
		List<Message> r = server(true).query(q);
		assertEquals(1, r.size());
		Message m = r.get(0);
		assertEquals(4, m.getID());
		assertEquals("ext.out.test", m.getFirstQuestion().getName());
		assertEquals(1, count(m,DNS.CNAME));
		assertEquals(1, count(m,DNS.A));
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertTrue(!m.getHeader().getAA(), "not authoritative for the target's data");
		Resolver.getCache().clear();
	}

	@Test
	public void tcpUnresolvableTargetIsServfailWithChain() {
		Resolver.getCache().clear();
		Message m = server(true).query(new QueryData(InetAddress.getLoopbackAddress(), -1, request("ext.out.test", true, 5))).get(0);
		assertEquals(DNS.SERVER_ERROR, m.getResponseCode());
		assertEquals(1, count(m,DNS.CNAME));
	}

	@Test
	public void udpClientGetsExactlyOneCombinedResponse() throws Exception {
		ResolverThread.clearBacklog();
		cacheRemote();
		int port;
		try(DatagramSocket probe = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
			port = probe.getLocalPort();
		}
		UDPProsessor.initUDPProsessor(port, InetAddress.getLoopbackAddress(), 200);
		ResolverThread rt = new ResolverThread();
		try(DatagramSocket client = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
			client.setSoTimeout(5000);
			rt.start("TestCnameResolverThread");
			QueryData q = new QueryData(InetAddress.getLoopbackAddress(), client.getLocalPort(), request("ext.out.test", true, 0x0707));
			List<Message> now = server(true).query(q);
			assertEquals(1, now.size());
			assertNull(now.get(0), "nothing is sent until the target is resolved");

			byte [] buf = new byte[DNS.MAXUDPLEN];
			DatagramPacket p = new DatagramPacket(buf, buf.length);
			client.receive(p);
			Message m = new Message(new ByteBuffer(java.util.Arrays.copyOf(buf, p.getLength())));
			assertEquals(0x0707, m.getID());
			assertEquals("ext.out.test", m.getFirstQuestion().getName(), "the question the client asked");
			assertEquals(1, count(m,DNS.CNAME));
			assertEquals(1, count(m,DNS.A));

			client.setSoTimeout(700);
			boolean second = true;
			try {
				client.receive(new DatagramPacket(buf, buf.length));
			} catch(SocketTimeoutException ex) {
				second = false;
			}
			assertTrue(!second, "no second response");
		} finally {
			rt.stop();
			UDPProsessor.getSock().close();
			ResolverThread.clearBacklog();
			Resolver.getCache().clear();
		}
	}
}
