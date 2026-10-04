package us.bringardner.net.dns.resolve;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.Section;

/**
 * Rec #55: an upstream address that fails is held off for a short, doubling
 * time (HOLD_OFF_MIN up to DEACTIVATE) instead of an hour, and when every
 * address of a zone is held off the one that comes back first is still
 * probed (at most once per PROBE_INTERVAL), so recursion recovers soon after
 * an outage ends.
 * <p>
 * Rec #56: upstream TCP has a connect timeout and the whole attempt (connect,
 * send, read) is bounded by the timeout / deadline.
 */
public class TestUpstreamOutage {

	private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();
	private int savedTimeout;
	private long savedMax;
	private long savedMin;
	private long savedProbe;

	@BeforeEach
	public void save() {
		savedTimeout = ServerA.QUERY_TIMEOUT;
		savedMax = ServerA.DEACTIVATE;
		savedMin = ServerA.HOLD_OFF_MIN;
		savedProbe = ServerA.PROBE_INTERVAL;
		ServerA.QUERY_TIMEOUT = 100;
	}

	@AfterEach
	public void restore() {
		ServerA.QUERY_TIMEOUT = savedTimeout;
		ServerA.DEACTIVATE = savedMax;
		ServerA.HOLD_OFF_MIN = savedMin;
		ServerA.PROBE_INTERVAL = savedProbe;
	}

	private static int deadPort() throws Exception {
		try(DatagramSocket s = new DatagramSocket(0, LOOPBACK)) {
			return s.getLocalPort();
		}
	}

	private static Section q(String n) {
		return new Section(n, DNS.A, DNS.IN);
	}

	private static ServerA server(int port) {
		ServerA s = new ServerA("ns.outage.test", "127.0.0.1");
		s.setPort(port);
		return s;
	}

	/** Fail s until it is held off. */
	private static void knockOut(ServerA s) {
		for(int i=0; i <= ServerA.MAX_TRIES && s.isActive(); i++ ) {
			assertNull(s.query(q("www.outage.test")));
		}
		assertFalse(s.isActive());
	}

	@Test
	public void defaultsAreShort() {
		//  Was one hour after 3 failures
		assertEquals(5_000, savedMin);
		assertEquals(600_000, savedMax);
	}

	@Test
	public void holdOffDoublesUpToTheMaximum() {
		ServerA.HOLD_OFF_MIN = 5_000;
		ServerA.DEACTIVATE = 600_000;
		assertEquals(5_000, ServerA.holdOff(1));
		assertEquals(10_000, ServerA.holdOff(2));
		assertEquals(20_000, ServerA.holdOff(3));
		assertEquals(320_000, ServerA.holdOff(7));
		assertEquals(600_000, ServerA.holdOff(8));
		assertEquals(600_000, ServerA.holdOff(1000), "no overflow");
	}

	@Test
	public void failingServerIsHeldOffBriefly() throws Exception {
		ServerA.HOLD_OFF_MIN = 200;
		ServerA.DEACTIVATE = 10_000;
		ServerA s = server(deadPort());
		long before = System.currentTimeMillis();
		knockOut(s);
		long first = s.getInactiveUntil() - before;
		assertTrue(first <= 200 + ServerA.QUERY_TIMEOUT*(ServerA.MAX_TRIES+2), "first hold-off "+first);
		Thread.sleep(first + 50);
		assertTrue(s.isActive(), "active again after the first hold-off");
		//  One more failure: twice as long
		long t = System.currentTimeMillis();
		assertNull(s.query(q("www.outage.test")));
		long second = s.getInactiveUntil() - t;
		assertTrue(second >= 400 && second <= 400 + ServerA.QUERY_TIMEOUT + 100, "second hold-off "+second);
	}

	@Test
	public void probeIsRateLimited() throws Exception {
		ServerA.PROBE_INTERVAL = 60_000;
		ServerA s = server(deadPort());
		assertTrue(s.tryProbe());
		assertFalse(s.tryProbe(), "a second probe within PROBE_INTERVAL");
	}

	@Test
	public void zoneRecoversWhileHeldOff() throws Exception {
		//  Both addresses fail and are held off for a minute (the outage) ...
		ServerA.HOLD_OFF_MIN = 60_000;
		ServerA.DEACTIVATE = 60_000;
		ServerA.PROBE_INTERVAL = 50;
		RemoteServer rs = new RemoteServer();
		rs.setName("outage.test");
		rs.addAddress("ns0.outage.test", "127.0.0.1");
		rs.addAddress("ns1.outage.test", "127.0.0.1");
		List<ServerA> list = new ArrayList<ServerA>();
		rs.iterator().forEachRemaining(list::add);
		int dead = deadPort();
		for(ServerA s : list) {
			s.setPort(dead);
			knockOut(s);
		}
		assertFalse(rs.isActive());

		//  ... then the network is back: the old code returned nothing until
		//  the hold-off (an hour) was over
		try(TestServerA.FakeUpstream up = new TestServerA.FakeUpstream()) {
			for(ServerA s : list) {
				s.setPort(up.port());
			}
			ServerA.QUERY_TIMEOUT = 2000;
			Message m = rs.resolve(q("www.outage.test"), System.currentTimeMillis()+3000);
			assertNotNull(m, "probed while held off");
			assertEquals(1, m.getAnswerCount());
			assertTrue(rs.isActive(), "an answer makes the address active again");
		}
	}

	@Test
	public void probesAreLimitedWhileTheOutageLasts() throws Exception {
		ServerA.HOLD_OFF_MIN = 60_000;
		ServerA.DEACTIVATE = 60_000;
		ServerA.PROBE_INTERVAL = 60_000;
		RemoteServer rs = new RemoteServer();
		rs.setName("outage.test");
		rs.addAddress("ns0.outage.test", "127.0.0.1");
		ServerA s = rs.iterator().next();
		s.setPort(deadPort());
		knockOut(s);
		int sent = s.getMsgSent();
		long deadline = System.currentTimeMillis()+2000;
		assertNull(rs.resolve(q("a.outage.test"), deadline));
		assertEquals(sent+1, s.getMsgSent(), "one probe");
		for(int i=0; i < 5; i++ ) {
			assertNull(rs.resolve(q("b.outage.test"), deadline));
		}
		assertEquals(sent+1, s.getMsgSent(), "no more probes within PROBE_INTERVAL");
	}

	@Test
	public void resolverRecoversWhenEveryRootIsHeldOff() throws Exception {
		ServerA.HOLD_OFF_MIN = 60_000;
		ServerA.DEACTIVATE = 60_000;
		ServerA.PROBE_INTERVAL = 50;
		RemoteServer root = new RemoteServer();
		root.setName(".");
		root.addAddress("a.root.test", "127.0.0.1");
		ServerA a = root.iterator().next();
		a.setPort(deadPort());
		knockOut(a);
		long saved = Resolver.getResolveTimeout();
		Resolver.getCache().clear();
		Resolver.setRootServersForTests(Collections.singletonList(root));
		try(TestServerA.FakeUpstream up = new TestServerA.FakeUpstream()) {
			a.setPort(up.port());
			ServerA.QUERY_TIMEOUT = 2000;
			Resolver.setResolveTimeout(3000);
			Message m = Resolver.resolve(q("www.recovered.test"));
			assertNotNull(m, "the old code skipped every inactive root: SERVFAIL for an hour");
			assertEquals(1, m.getAnswerCount());
		} finally {
			Resolver.setResolveTimeout(saved);
			Resolver.setRootServersForTests(Collections.<RemoteServer>emptyList());
			Resolver.reset();
		}
	}

	// ---- #56: TCP

	/** Accepts, reads the query, then sends one byte every 100 ms and never finishes. */
	private static ServerSocket trickler(List<Socket> open) throws IOException {
		ServerSocket ss = new ServerSocket(0, 10, LOOPBACK);
		Thread t = new Thread(() -> {
			while( !ss.isClosed() ) {
				try {
					Socket c = ss.accept();
					open.add(c);
					Thread w = new Thread(() -> {
						try {
							InputStream in = c.getInputStream();
							in.read(new byte[512]);
							OutputStream out = c.getOutputStream();
							out.write(new byte[] {0x01, 0x00});   //  "256 bytes follow"
							for(int i=0; i < 1000; i++ ) {
								Thread.sleep(100);
								out.write(0);
								out.flush();
							}
						} catch(Exception ex) {
						}
					});
					w.setDaemon(true);
					w.start();
				} catch(IOException ex) {
				}
			}
		});
		t.setDaemon(true);
		t.start();
		return ss;
	}

	@Test
	public void slowTcpAnswerIsBoundedByTheTimeout() throws Exception {
		List<Socket> open = Collections.synchronizedList(new ArrayList<Socket>());
		try(ServerSocket ss = trickler(open)) {
			Message m = new Message();
			m.setQuestion("www.slow.test", DNS.A, DNS.IN);
			m.setServer(LOOPBACK);
			m.setPort(ss.getLocalPort());
			m.setTimeOut(800);
			m.setRetry(1);
			long start = System.currentTimeMillis();
			assertThrows(IOException.class, () -> m.queryTCP(LOOPBACK));
			long took = System.currentTimeMillis()-start;
			//  Each read got a byte within 100 ms, so the old per-read timeout
			//  never fired: about 25 s for the 256 bytes
			assertTrue(took < 2000, "took "+took+" ms");
		} finally {
			for(Socket s : open) {
				s.close();
			}
		}
	}

	@Test
	public void tcpConnectIsBounded() throws Exception {
		//  A listener whose accept queue is full: further connects are not
		//  answered (dropped SYNs, as with a firewall) or refused
		List<Socket> fill = new ArrayList<Socket>();
		try(ServerSocket ss = new ServerSocket(0, 1, LOOPBACK)) {
			for(int i=0; i < 8; i++ ) {
				Socket s = new Socket();
				try {
					s.connect(ss.getLocalSocketAddress(), 200);
				} catch(IOException ex) {
				}
				fill.add(s);
			}
			Message m = new Message();
			m.setQuestion("www.blackhole.test", DNS.A, DNS.IN);
			m.setPort(ss.getLocalPort());
			m.setTimeOut(500);
			m.setRetry(2);
			long start = System.currentTimeMillis();
			try {
				m.queryTCP(LOOPBACK);
			} catch(IOException ex) {
				//  timed out or refused: both fine, as long as it was quick
			}
			long took = System.currentTimeMillis()-start;
			assertTrue(took < 2500, "took "+took+" ms");
		} finally {
			for(Socket s : fill) {
				s.close();
			}
		}
	}

	@Test
	public void deadlineCapsUdpAttempts() throws Exception {
		Message m = new Message();
		m.setQuestion("www.deadline.test", DNS.A, DNS.IN);
		m.setPort(deadPort());
		m.setTimeOut(5000);
		m.setRetry(3);
		m.setDeadline(System.currentTimeMillis()+300);
		long start = System.currentTimeMillis();
		assertThrows(IOException.class, () -> m.queryUDP(LOOPBACK));
		long took = System.currentTimeMillis()-start;
		assertTrue(took < 1000, "took "+took+" ms (3 x 5 s without the deadline)");
	}

	@Test
	public void deadlineCapsTcpAttempts() throws Exception {
		List<Socket> open = Collections.synchronizedList(new ArrayList<Socket>());
		try(ServerSocket ss = trickler(open)) {
			Message m = new Message();
			m.setQuestion("www.slow.test", DNS.A, DNS.IN);
			m.setPort(ss.getLocalPort());
			m.setTimeOut(5000);
			m.setRetry(3);
			m.setDeadline(System.currentTimeMillis()+400);
			long start = System.currentTimeMillis();
			assertThrows(IOException.class, () -> m.queryTCP(LOOPBACK));
			long took = System.currentTimeMillis()-start;
			assertTrue(took < 1500, "took "+took+" ms");
		} finally {
			for(Socket s : open) {
				s.close();
			}
		}
	}
}
