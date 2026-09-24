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
package us.bringardner.net.dns.server;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.file.Files;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.A;
import us.bringardner.net.dns.ByteBuffer;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.Txt;

/**
 * Offline tests for UDP response size limits (RFC 1035 4.2.1, RFC 2181 9)
 * and the client's TCP retry on TC. The end-to-end tests run the real
 * UDP and TCP processors on a loopback port.
 */
public class TestUdpTruncation {

	private static String text(char c, int n) {
		StringBuilder sb = new StringBuilder();
		for(int i=0; i< n; i++ ) {
			sb.append(c);
		}
		return sb.toString();
	}

	private static Message withTxt(int records, int size) {
		Message m = new Message();
		m.setQuestion("big.example.test", DNS.TXT, DNS.IN);
		m.setMessageTypeResponse();
		m.setID(0x2222);
		for(int i=0; i< records; i++ ) {
			Txt t = new Txt("big.example.test");
			t.setText(text((char)('a'+i), size));
			t.setTTL(60);
			m.addAnswer(t);
		}
		return m;
	}

	private static A glue(int i) {
		A a = new A("ns"+i+".example.test");
		a.setAddress("10.0.0."+(i+1));
		a.setTTL(60);
		return a;
	}

	// ------------------------------------------------------------ unit

	@Test
	public void smallMessageUnchanged() {
		Message m = withTxt(1,50);
		assertArrayEquals(m.toByteArray(), m.toByteArray(512));
	}

	@Test
	public void additionalDroppedWithoutTc() {
		Message m = withTxt(1,300);
		for(int i=0; i< 20; i++ ) {
			m.addAdditional(glue(i));
		}
		assertTrue(m.toByteArray().length > 512);
		byte [] b = m.toByteArray(512);
		assertTrue(b.length <= 512);
		Message got = new Message(new ByteBuffer(b));
		assertTrue(!got.isTruncated(), "answer is complete, TC must not be set");
		assertEquals(1, got.getAnswerCount());
		assertEquals(0, got.getAdditionalCount());
	}

	@Test
	public void oversizedAnswerSetsTc() {
		Message m = withTxt(4,200);
		byte [] b = m.toByteArray(512);
		assertTrue(b.length <= 512);
		Message got = new Message(new ByteBuffer(b));
		assertTrue(got.isTruncated());
		assertEquals(0x2222, got.getID());
		assertEquals(1, got.getQuestionCount());
		assertEquals("big.example.test", got.getFirstQuestion().getName());
		assertEquals(0, got.getAnswerCount());
	}

	@Test
	public void originalMessageNotModified() {
		Message m = withTxt(4,200);
		m.toByteArray(512);
		assertTrue(!m.isTruncated(), "TC must not leak into the (possibly cached) message");
		assertEquals(4, m.getAnswerCount());
		assertTrue(m.toByteArray().length > 512);
	}

	@Test
	public void largerLimitAllowsMore() {
		Message m = withTxt(4,200);
		Message got = new Message(new ByteBuffer(m.toByteArray(1232)));
		assertTrue(!got.isTruncated());
		assertEquals(4, got.getAnswerCount());
	}

	// ------------------------------------------------------------ end to end

	private static File dir;
	private static int port;

	@BeforeAll
	public static void startServer() throws IOException {
		dir = Files.createTempDirectory("trunc").toFile();
		File zone = new File(dir,"trunc.test.txt");
		StringBuilder z = new StringBuilder();
		z.append("@\tIN\tSOA\tns1.trunc.test. postmaster.trunc.test. (\n"
				+"\t\t\t1 ; serial\n\t\t\t3600 ; refresh\n\t\t\t1800 ; retry\n"
				+"\t\t\t1209600 ; expire\n\t\t\t300 ) ; minimum\n\n"
				+"\t\tNS\tns1\n"
				+"ns1\tIN\tA\t10.0.0.53\n"
				+"www\tIN\tA\t10.0.0.80\n");
		z.append("big\tIN\tTXT\t\""+text('a',200)+"\"\n");
		for(char c='b'; c<='d'; c++ ) {
			z.append("\t\tTXT\t\""+text(c,200)+"\"\n");
		}
		try(FileWriter w = new FileWriter(zone)) {
			w.write(z.toString());
		}

		DnsServer server = new DnsServer();
		server.addZone(new Zone(zone));
		server.setRecursionAvailable(false);

		try(DatagramSocket probe = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
			port = probe.getLocalPort();
		}
		UDPProsessor.initUDPProsessor(port, InetAddress.getLoopbackAddress(), 200);
		TCPProsessor.initTCPProsessor(port, 5, InetAddress.getLoopbackAddress(), 200);
		Thread u = new Thread(new UDPProsessor(server,0),"TestUDP");
		u.setDaemon(true);
		u.start();
		Thread t = new Thread(new TCPProsessor(server,0),"TestTCP");
		t.setDaemon(true);
		t.start();
	}

	@AfterAll
	public static void stopServer() throws Exception {
		DnsServer.setShutdown(true);
		Thread.sleep(500);
		UDPProsessor.getSock().close();
		DnsServer.setShutdown(false);
		for(File f : dir.listFiles()) {
			f.delete();
		}
		dir.delete();
	}

	private static Message query(String name, int type, boolean fallback) throws IOException {
		Message m = new Message();
		m.setServer(InetAddress.getLoopbackAddress());
		m.setPort(port);
		m.setTimeOut(2000);
		m.setRetry(2);
		m.setTcpFallback(fallback);
		m.setQuestion(name, type, DNS.IN);
		return m.queryUDP();
	}

	@Test
	public void serverTruncatesLargeUdpAnswer() throws Exception {
		Message r = query("big.trunc.test", DNS.TXT, false);
		assertTrue(r.isTruncated(), "900+ byte answer must not be sent whole over UDP");
		assertEquals(0, r.getAnswerCount());
	}

	@Test
	public void clientRetriesOverTcp() throws Exception {
		Message r = query("big.trunc.test", DNS.TXT, true);
		assertTrue(!r.isTruncated());
		assertEquals(4, r.getAnswerCount());
		assertTrue(r.toByteArray().length > 512);
	}

	@Test
	public void smallAnswerNotTruncated() throws Exception {
		Message r = query("www.trunc.test", DNS.A, false);
		assertTrue(!r.isTruncated());
		assertEquals(1, r.getAnswerCount());
	}
}
