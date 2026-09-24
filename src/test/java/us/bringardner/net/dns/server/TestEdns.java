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
import java.nio.file.Files;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.A;
import us.bringardner.net.dns.ByteBuffer;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Edns;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.Name;
import us.bringardner.net.dns.RR;

/**
 * EDNS(0) (RFC 6891): clients that send an OPT record get UDP answers up to
 * their size (at most JDns.ednsUdpSize) instead of a truncated answer and a
 * TCP retry, and an OPT record back.
 */
public class TestEdns {

	private static final int BIG_COUNT = 40;   //  40 A records: about 700 bytes
	private static File dir;
	private static DnsServer server;
	private static Thread udp;
	private static int port;
	private static String savedZoneDir;
	private static String savedMaster;

	@BeforeAll
	public static void setup() throws Exception {
		dir = Files.createTempDirectory("edns").toFile();
		try(FileWriter w = new FileWriter(new File(dir,"edns.test.txt"))) {
			w.write("@\tIN\tSOA\tns1.edns.test. postmaster.edns.test. (\n"
					+"\t\t\t1 ; serial\n\t\t\t3600 ; refresh\n\t\t\t1800 ; retry\n"
					+"\t\t\t1209600 ; expire\n\t\t\t300 ) ; minimum\n\n"
					+"\t\tNS\tns1\n"
					+"ns1\tIN\tA\t10.0.0.53\n"
					+"www\tIN\tA\t10.0.0.80\n");
			for(int i=1; i <= BIG_COUNT; i++ ) {
				w.write("big\tIN\tA\t10.1.0."+i+"\n");
			}
		}
		savedZoneDir = System.getProperty(DnsServer.PROP_ZONE_DIR);
		savedMaster = System.getProperty(DnsServer.PROP_DEFAULT_ZONE);
		System.setProperty(DnsServer.PROP_ZONE_DIR, dir.getAbsolutePath());
		System.setProperty(DnsServer.PROP_DEFAULT_ZONE, "edns.test");
		server = new DnsServer();
		server.loadZones();
		server.setRecursionAvailable(false);

		try(DatagramSocket probe = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
			port = probe.getLocalPort();
		}
		DnsServer.setShutdown(false);
		UDPProsessor.initUDPProsessor(port, InetAddress.getLoopbackAddress(), 200);
		udp = new Thread(new UDPProsessor(server,0),"TestEdnsUDP");
		udp.setDaemon(true);
		udp.start();
	}

	@AfterAll
	public static void cleanup() throws Exception {
		DnsServer.setShutdown(true);
		udp.join(3000);
		UDPProsessor.getSock().close();
		DnsServer.setShutdown(false);
		Edns.setServerUdpSize(Edns.DEFAULT_UDP_SIZE);
		restore(DnsServer.PROP_ZONE_DIR, savedZoneDir);
		restore(DnsServer.PROP_DEFAULT_ZONE, savedMaster);
		for(File f : dir.listFiles()) {
			f.delete();
		}
		dir.delete();
	}

	private static void restore(String k, String v) {
		if( v == null ) {
			System.clearProperty(k);
		} else {
			System.setProperty(k, v);
		}
	}

	private static RR opt(int size, int version) {
		RR opt = new RR("", DNS.OPT, size);
		opt.setTTL(version << 16);
		opt.setRdata(new byte[0]);
		return opt;
	}

	private static Message query(String name, RR ... opts) {
		Message q = new Message();
		q.setQuestion(name, DNS.A, DNS.IN);
		q.setID(0x4242);
		for(RR o : opts) {
			q.addAdditional(o);
		}
		return q;
	}

	/** Send over UDP, return the raw reply. */
	private static byte [] udp(Message q) throws IOException {
		byte [] data = q.toByteArray();
		try(DatagramSocket c = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
			c.setSoTimeout(3000);
			c.send(new DatagramPacket(data, data.length, InetAddress.getLoopbackAddress(), port));
			byte [] buf = new byte[8192];
			DatagramPacket p = new DatagramPacket(buf, buf.length);
			c.receive(p);
			return java.util.Arrays.copyOf(buf, p.getLength());
		}
	}

	private static RR optOf(Message m) {
		RR ret = null;
		for(RR rr : m.getAdditional()) {
			if( rr.getType() == DNS.OPT ) {
				assertNull(ret, "one OPT");
				ret = rr;
			}
		}
		return ret;
	}

	@Test
	public void rootNameIsOneZeroOctet() {
		assertEquals(1, new Name("").toByteArray().length);
		assertEquals(1, new Name(".").toByteArray().length);
		assertEquals(0, new Name(".").getLables().size());
		byte [] wire = query("www.edns.test", opt(1232, 0)).toByteArray();
		// header 12 + question (15+4) + OPT (1 + 10)
		assertEquals(12 + 15 + 4 + 11, wire.length);
		Message back = new Message(new ByteBuffer(wire));
		RR o = optOf(back);
		assertNotNull(o);
		assertEquals("", o.getName());
		assertEquals(1232, o.getDnsClass());
	}

	@Test
	public void parseRequest() {
		assertTrue(!Edns.parse(query("x.test")).isPresent());
		assertEquals(512, Edns.parse(query("x.test")).maxUdpResponse());
		Edns.Request r = Edns.parse(query("x.test", opt(4096, 0)));
		assertTrue(r.isPresent());
		assertEquals(4096, r.getUdpSize());
		assertEquals(Edns.DEFAULT_UDP_SIZE, r.maxUdpResponse(), "capped by the server size");
		assertEquals(512, Edns.parse(query("x.test", opt(100, 0))).maxUdpResponse(), "below 512 means 512");
		assertEquals(800, Edns.parse(query("x.test", opt(800, 0))).maxUdpResponse());
		assertTrue(Edns.parse(query("x.test", opt(1232, 1))).isBadVersion());
		assertTrue(Edns.parse(query("x.test", opt(1232, 0), opt(1232, 0))).isMalformed());
	}

	@Test
	public void truncationKeepsOpt() {
		Message m = new Message();
		m.setQuestion("big.edns.test", DNS.A, DNS.IN);
		m.setMessageTypeResponse();
		for(int i=1; i <= BIG_COUNT; i++ ) {
			A a = new A("big.edns.test");
			a.setAddress("10.1.0."+i);
			a.setTTL(60);
			m.addAnswer(a);
		}
		A glue = new A("ns1.edns.test");
		glue.setAddress("10.0.0.53");
		m.addAdditional(glue);
		Edns.applyToResponse(m, Edns.parse(query("big.edns.test", opt(512, 0))));

		Message tc = new Message(new ByteBuffer(m.toByteArray(512)));
		assertTrue(tc.getHeader().getTC());
		assertNotNull(optOf(tc), "OPT kept in a truncated answer");
		assertEquals(1, tc.getAdditionalCount());
	}

	@Test
	public void upstreamOptIsReplaced() {
		Message m = new Message();
		m.setQuestion("www.edns.test", DNS.A, DNS.IN);
		m.addAdditional(opt(4000, 0));
		Edns.applyToResponse(m, Edns.parse(query("www.edns.test", opt(1400, 0))));
		assertEquals(Edns.DEFAULT_UDP_SIZE, optOf(m).getDnsClass(), "our size, not the upstream's");
		Edns.applyToResponse(m, Edns.Request.NONE);
		assertNull(optOf(m), "no OPT for a client that sent none");
	}

	@Test
	public void withoutEdnsBigAnswerIsTruncated() throws IOException {
		Message r = new Message(new ByteBuffer(udp(query("big.edns.test"))));
		assertTrue(r.getHeader().getTC(), "over 512 bytes: TC as before");
		assertNull(optOf(r), "no OPT for a client without EDNS");
	}

	@Test
	public void ednsClientGetsWholeAnswerOverUdp() throws IOException {
		byte [] raw = udp(query("big.edns.test", opt(4096, 0)));
		assertTrue(raw.length > 512 && raw.length <= Edns.DEFAULT_UDP_SIZE, "size "+raw.length);
		Message r = new Message(new ByteBuffer(raw));
		assertTrue(!r.getHeader().getTC());
		assertEquals(BIG_COUNT, r.getAnswerCount());
		assertEquals(DNS.NOERROR, r.getResponseCode());
		RR o = optOf(r);
		assertNotNull(o, "OPT echoed");
		assertEquals(Edns.DEFAULT_UDP_SIZE, o.getDnsClass());
		assertEquals(0, o.getTTL(), "version 0, no extended RCODE, DO clear");
	}

	@Test
	public void clientSizeIsRespected() throws IOException {
		Message r = new Message(new ByteBuffer(udp(query("big.edns.test", opt(600, 0)))));
		assertTrue(r.getHeader().getTC(), "the answer is bigger than the client's 600");
		assertNotNull(optOf(r));
	}

	@Test
	public void serverSizeIsConfigurable() throws IOException {
		Edns.setServerUdpSize(512);
		try {
			Message r = new Message(new ByteBuffer(udp(query("big.edns.test", opt(4096, 0)))));
			assertTrue(r.getHeader().getTC());
			assertEquals(512, optOf(r).getDnsClass());
		} finally {
			Edns.setServerUdpSize(Edns.DEFAULT_UDP_SIZE);
		}
	}

	@Test
	public void unknownVersionGetsBadVers() throws IOException {
		Message r = new Message(new ByteBuffer(udp(query("www.edns.test", opt(1232, 1)))));
		assertEquals(0x4242, r.getID());
		assertEquals(0, r.getResponseCode(), "low 4 bits of BADVERS (16)");
		assertEquals(0, r.getAnswerCount());
		RR o = optOf(r);
		assertNotNull(o);
		assertEquals(1, (o.getTTL() >>> 24) & 0xff, "extended RCODE 1 -> 16 BADVERS");
	}

	@Test
	public void twoOptsIsFormErr() throws IOException {
		Message r = new Message(new ByteBuffer(udp(query("www.edns.test", opt(1232, 0), opt(1232, 0)))));
		assertEquals(DNS.FORMAT_ERROR, r.getResponseCode());
		assertNull(optOf(r));
	}

	@Test
	public void smallAnswerWithEdns() throws IOException {
		Message r = new Message(new ByteBuffer(udp(query("www.edns.test", opt(1232, 0)))));
		assertEquals(1, r.getAnswerCount());
		assertNotNull(optOf(r));
	}
}
