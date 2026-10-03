package us.bringardner.net.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileWriter;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.file.Files;
import java.util.Collections;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.A;
import us.bringardner.net.dns.ByteBuffer;
import us.bringardner.net.dns.Cname;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.Soa;
import us.bringardner.net.dns.resolve.QueryData;
import us.bringardner.net.dns.resolve.Resolver;
import us.bringardner.net.dns.resolve.ResolverThread;
import us.bringardner.net.dns.resolve.TestHooks;

/**
 * Rec #57: a recursive UDP query whose answer is cached is answered by the
 * UDP processor at once, not queued for a resolver thread. With every
 * resolver thread busy (here: the queue is full) cached names used to get
 * SERVFAIL.
 */
public class TestCacheFastPath {

	private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();
	private static File dir;
	private static DnsServer server;
	private static Thread udp;
	private static int port;
	private static String savedZoneDir;
	private static String savedMaster;

	@BeforeAll
	public static void setup() throws Exception {
		dir = Files.createTempDirectory("fastpath").toFile();
		try(FileWriter w = new FileWriter(new File(dir,"own.test.txt"))) {
			w.write("@\tIN\tSOA\tns1.own.test. postmaster.own.test. (\n"
					+"\t\t\t1 ; serial\n\t\t\t3600 ; refresh\n\t\t\t1800 ; retry\n"
					+"\t\t\t1209600 ; expire\n\t\t\t300 ) ; minimum\n\n"
					+"\t\tNS\tns1\n"
					+"ns1\tIN\tA\t10.0.0.53\n");
		}
		savedZoneDir = System.getProperty(DnsServer.PROP_ZONE_DIR);
		savedMaster = System.getProperty(DnsServer.PROP_DEFAULT_ZONE);
		System.setProperty(DnsServer.PROP_ZONE_DIR, dir.getAbsolutePath());
		System.setProperty(DnsServer.PROP_DEFAULT_ZONE, "own.test");
		server = new DnsServer();
		server.loadZones();

		try(DatagramSocket probe = new DatagramSocket(0, LOOPBACK)) {
			port = probe.getLocalPort();
		}
		DnsServer.setShutdown(false);
		UDPProsessor.initUDPProsessor(port, LOOPBACK, 200);
		udp = new Thread(new UDPProsessor(server,0),"TestCacheFastPathUDP");
		udp.setDaemon(true);
		udp.start();
	}

	@AfterAll
	public static void cleanup() throws Exception {
		DnsServer.setShutdown(true);
		udp.join(3000);
		UDPProsessor.getSock().close();
		DnsServer.setShutdown(false);
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

	@BeforeEach
	public void busy() {
		server.setRecursionAvailable(true);
		Resolver.setValidator(null);
		Resolver.reset();
		//  Every resolver thread busy: the queue is full (no threads run here)
		ResolverThread.clearBacklog();
		Message filler = new Message();
		filler.setQuestion("slow.example", DNS.A, DNS.IN);
		while( ResolverThread.addQuery(new QueryData(LOOPBACK, 9, filler)) ) {
		}
	}

	@AfterEach
	public void idle() {
		ResolverThread.clearBacklog();
		Resolver.setValidator(null);
		Resolver.reset();
		server.setRecursionAvailable(false);
	}

	/** An upstream server's authoritative answer, as the resolver caches it. */
	private static Message upstreamAnswer(String name, String ip) {
		Message m = new Message();
		m.setQuestion(name, DNS.A, DNS.IN);
		m.setMessageTypeResponse();
		m.getHeader().setAA(true);
		m.getHeader().setRA(false);
		m.getHeader().setRD(false);
		A a = new A(name);
		a.setAddress(ip);
		a.setTTL(300);
		m.addAnswer(a);
		return m;
	}

	private static Message ask(String name, int id) throws Exception {
		Message q = new Message();
		q.setQuestion(name, DNS.A, DNS.IN);
		q.setID(id);
		q.recursiveDesired(true);
		byte [] data = q.toByteArray();
		try(DatagramSocket c = new DatagramSocket(0, LOOPBACK)) {
			c.setSoTimeout(3000);
			c.send(new DatagramPacket(data, data.length, LOOPBACK, port));
			byte [] buf = new byte[4096];
			DatagramPacket p = new DatagramPacket(buf, buf.length);
			c.receive(p);
			return new Message(new ByteBuffer(java.util.Arrays.copyOf(buf, p.getLength())));
		}
	}

	@Test
	public void cachedNameIsAnsweredWhileTheResolversAreBusy() throws Exception {
		TestHooks.put(upstreamAnswer("www.cached.example", "192.0.2.7"));
		long hits = Resolver.getCacheHits();
		Message r = ask("www.cached.example", 0x1234);
		assertEquals(0x1234, r.getID());
		assertEquals(DNS.NOERROR, r.getResponseCode(), "used to be SERVFAIL (queue full)");
		assertEquals(1, r.getAnswerCount());
		assertEquals("192.0.2.7", ((A)r.getAnswer().get(0)).getAddressString());
		assertTrue(r.getAnswer().get(0).getTTL() <= 300);
		assertFalse(r.getHeader().getAA(), "not authoritative (the upstream AA used to be passed on)");
		assertTrue(r.getHeader().getRA());
		assertTrue(r.getHeader().getRD(), "RD echoed");
		assertEquals(hits+1, Resolver.getCacheHits());
		assertEquals(ResolverThread.getMaxBackLog(), ResolverThread.getBacklog(), "nothing more queued");
	}

	@Test
	public void cachedNxdomainToo() throws Exception {
		Message m = new Message();
		m.setQuestion("nope.cached.example", DNS.A, DNS.IN);
		m.setMessageTypeResponse();
		m.setResponseCode(DNS.NAME_ERROR);
		Soa soa = new Soa("cached.example");
		soa.setTTL(300);
		soa.setMinimum(300);
		m.addAuthority(soa);
		TestHooks.put(m);
		Message r = ask("nope.cached.example", 0x2345);
		assertEquals(DNS.NAME_ERROR, r.getResponseCode());
	}

	@Test
	public void uncachedStillNeedsAResolverThread() throws Exception {
		Message r = ask("www.unknown.example", 0x3456);
		assertEquals(DNS.SERVER_ERROR, r.getResponseCode(), "queue full, as before");
	}

	@Test
	public void cnameToFollowGoesToTheResolver() throws Exception {
		Message m = new Message();
		m.setQuestion("alias.cached.example", DNS.A, DNS.IN);
		m.setMessageTypeResponse();
		Cname c = new Cname("alias.cached.example");
		c.setCname("target.elsewhere.example");
		c.setTTL(300);
		m.addAnswer(c);
		TestHooks.put(m);
		Message r = ask("alias.cached.example", 0x4567);
		assertEquals(DNS.SERVER_ERROR, r.getResponseCode(), "the target still has to be resolved: queued (full here)");
	}

	@Test
	public void notValidatedYetGoesToTheResolver() throws Exception {
		Resolver.setValidator(Resolver.newValidator(Collections.emptyList()));
		TestHooks.put(upstreamAnswer("www.cached.example", "192.0.2.7"));
		Message r = ask("www.cached.example", 0x5678);
		assertEquals(DNS.SERVER_ERROR, r.getResponseCode(), "validation on and not validated: a resolver thread validates it");
	}
}
