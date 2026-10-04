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
 *
 */
package us.bringardner.net.dns.resolve;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.util.Collections;
import java.util.Iterator;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.ByteBuffer;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Ds;
import us.bringardner.net.dns.Edns;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.Section;
import us.bringardner.net.dns.dnssec.DnssecKey;
import us.bringardner.net.dns.server.DnsServer;
import us.bringardner.net.dns.server.TCPProsessor;
import us.bringardner.net.dns.server.UDPProsessor;

/**
 * The resolver with validation on, over the network: it asks an
 * authoritative server (on the loopback) with DO, validates, and shapes the
 * answer for the client (AD, SERVFAIL, DNSSEC records only with DO).
 */
public class TestValidatingResolver {

	private static File dir;
	private static int port;
	private static DnssecKey anchor;

	@BeforeAll
	public static void start() throws Exception {
		dir = Files.createTempDirectory("vresolver").toFile();
		DnsServer auth = new DnsServer();
		anchor = TestValidator.hierarchy(dir, auth);
		for(int i=0; ; i++ ) {
			try(DatagramSocket probe = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
				port = probe.getLocalPort();
			}
			try(ServerSocket tcp = new ServerSocket(port, 5, InetAddress.getLoopbackAddress())) {
				break;
			} catch(java.io.IOException ex) {
				if( i > 20 ) {
					throw ex;
				}
			}
		}
		DnsServer.setShutdown(false);
		UDPProsessor.initUDPProsessor(port, InetAddress.getLoopbackAddress(), 200);
		TCPProsessor.initTCPProsessor(port, 5, InetAddress.getLoopbackAddress(), 200);
		for(int i=0; i < 2; i++ ) {
			Thread u = new Thread(new UDPProsessor(auth, i), "TestVResolverUDP"+i);
			u.setDaemon(true);
			u.start();
		}
		Thread t = new Thread(new TCPProsessor(auth, 0), "TestVResolverTCP");
		t.setDaemon(true);
		t.start();
	}

	@AfterAll
	public static void stop() throws Exception {
		Resolver.setValidator(null);
		Resolver.setRootServersForTests(Collections.<RemoteServer>emptyList());
		Resolver.reset();
		Resolver.getCache().clear();
		UDPProsessor.getSock().close();
		TCPProsessor.getServerSocket().close();
		for(File f : dir.listFiles()) {
			f.delete();
		}
		dir.delete();
	}

	@BeforeEach
	public void fresh() {
		Resolver.reset();
		Resolver.getCache().clear();
		RemoteServer root = new RemoteServer();
		root.setName(".");
		root.addAddress("ns.test", "127.0.0.1");
		for(Iterator<ServerA> it = root.iterator(); it.hasNext(); ) {
			it.next().setPort(port);
		}
		Resolver.setRootServersForTests(Collections.singletonList(root));
		Ds ds = anchor.toDs(Ds.SHA256, 0);
		Resolver.setValidator(Resolver.newValidator(Validator.parseAnchors("test. IN DS "+ds.getRdataAsString())));
	}

	/** A client's query, as the server receives it. */
	private static QueryData query(String name, int type, boolean dnssecOk, boolean cd) {
		Message q = new Message();
		q.setQuestion(name, type, DNS.IN);
		q.getHeader().setCD(cd);
		if( dnssecOk ) {
			q.addAdditional(Edns.newOpt(0, true));
		}
		return new QueryData(InetAddress.getLoopbackAddress(), 5353, new Message(new ByteBuffer(q.toByteArray())));
	}

	private static Message answer(QueryData q) {
		Resolver.Answer a = ResolverThread.resolveFor(q, q.getQuestion());
		Message m = a.msg == null ? ResolverThread.failure(q, DNS.SERVER_ERROR) : a.msg;
		ResolverThread.finish(m, q, a.result, false);
		return new Message(new ByteBuffer(m.toByteArray()));
	}

	private static long count(Message m, int type) {
		long n = 0;
		for(java.util.List<RR> s : java.util.Arrays.asList(m.getAnswer(), m.getAuthority(), m.getAdditional())) {
			n += s.stream().filter(r -> r.getType() == type).count();
		}
		return n;
	}

	@Test
	public void secureAnswerGetsAd() {
		Resolver.Answer a = Resolver.resolveValidated(new Section("www.sec.test", DNS.A, DNS.IN), false);
		assertNotNull(a.msg);
		assertEquals(Validator.Status.SECURE, a.result.status, a.result.toString());
		assertTrue(count(a.msg, DNS.RRSIG) > 0, "the upstream query asked for DNSSEC records (DO)");
		Message m = answer(query("www.sec.test", DNS.A, true, false));
		assertTrue(m.getHeader().getAD(), "AD for a DO client");
		assertTrue(count(m, DNS.RRSIG) > 0, "signatures kept for a DO client");
		m = answer(query("www.sec.test", DNS.A, false, false));
		assertFalse(m.getHeader().getAD(), "no AD for a client that asked for neither DO nor AD");
		assertEquals(0, count(m, DNS.RRSIG), "no DNSSEC records without DO");
		assertEquals(1, m.getAnswerCount());
	}

	@Test
	public void secureDenialsThroughTheResolver() {
		for(Object [] q : new Object[][] {{"nope.sec.test", DNS.A, DNS.NAME_ERROR}, {"www.sec.test", DNS.MX, DNS.NOERROR},
				{"nope.n3.test", DNS.A, DNS.NAME_ERROR}, {"x.y.wild.sec.test", DNS.A, DNS.NOERROR}}) {
			Message m = answer(query((String)q[0], (Integer)q[1], true, false));
			assertEquals((int)(Integer)q[2], m.getResponseCode(), q[0]+" "+q[1]);
			assertTrue(m.getHeader().getAD(), q[0]+" "+q[1]+" validated");
		}
		//  From the cache too (the proof is cached with the negative answer)
		Message again = answer(query("nope.sec.test", DNS.A, true, false));
		assertTrue(again.getHeader().getAD());
		assertTrue(count(again, DNS.NSEC) > 0);
	}

	@Test
	public void insecureIsPassedOnWithoutAd() {
		Message m = answer(query("www.insecure.test", DNS.A, true, false));
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertEquals(1, m.getAnswerCount());
		assertFalse(m.getHeader().getAD());
	}

	@Test
	public void bogusIsServfailUnlessCheckingDisabled() {
		Message m = answer(query("www.bogus.test", DNS.A, true, false));
		assertEquals(DNS.SERVER_ERROR, m.getResponseCode());
		assertEquals(0, m.getAnswerCount());
		long before = ResolverThread.getBogus();
		answer(query("www.bogus.test", DNS.A, true, false));
		assertEquals(before+1, ResolverThread.getBogus());
		//  CD: the client validates itself and gets the data
		m = answer(query("www.bogus.test", DNS.A, true, true));
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertEquals(1, m.getAnswerCount() - count(m, DNS.RRSIG));
		assertTrue(m.getHeader().getCD(), "CD echoed");
		assertFalse(m.getHeader().getAD());
	}

	@Test
	public void validationOff() {
		Resolver.setValidator(null);
		Resolver.Answer a = Resolver.resolveValidated(new Section("www.bogus.test", DNS.A, DNS.IN), false);
		assertNull(a.result);
		assertNotNull(a.msg);
		assertEquals(0, count(a.msg, DNS.RRSIG), "no DO upstream when not validating");
		//  NODATA comes back as such (it was taken for a referral and failed)
		Message m = Resolver.resolve(new Section("www.sec.test", DNS.MX, DNS.IN));
		assertNotNull(m, "NODATA is an answer");
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertEquals(0, m.getAnswerCount());
	}

	// ---- rec #66: the validation result is kept with the cache entry

	@Test
	public void resultIsKeptWithTheCacheEntry() {
		Section q = new Section("www.sec.test", DNS.A, DNS.IN);
		Resolver.Answer first = Resolver.resolveValidated(q, false);
		assertEquals(Validator.Status.SECURE, first.result.status);
		Cache.Hit h = Resolver.getCache().lookup(q);
		assertNotNull(h);
		assertNotNull(h.validated, "stored with the entry");
		assertEquals(Validator.Status.SECURE, h.validated.status);

		//  From now on no signature checks: compare the time for 2,000 hits
		//  with re-validating the same response 2,000 times (the old way)
		Validator v = Resolver.getValidator();
		long hits = Resolver.getCacheHits();
		long t0 = System.nanoTime();
		for(int i=0; i < 2000; i++ ) {
			Resolver.Answer a = Resolver.resolveValidated(q, false);
			assertEquals(Validator.Status.SECURE, a.result.status);
		}
		long cached = System.nanoTime()-t0;
		assertEquals(hits+2000, Resolver.getCacheHits());
		t0 = System.nanoTime();
		for(int i=0; i < 2000; i++ ) {
			assertEquals(Validator.Status.SECURE, v.validate(Resolver.getCache().get(q), q).status);
		}
		long revalidated = System.nanoTime()-t0;
		System.out.println("TestValidatingResolver: 2000 cached SECURE answers "+cached/1_000_000+" ms, re-validated "+revalidated/1_000_000+" ms");
	}

	@Test
	public void bogusIsNotKept() {
		Section q = new Section("www.bogus.test", DNS.A, DNS.IN);
		assertEquals(Validator.Status.BOGUS, Resolver.resolveValidated(q, false).result.status);
		assertNull(Resolver.getCache().lookup(q), "removed, so the next query fetches it again");
	}

	@Test
	public void cacheOnlyAnswers() {
		Section q = new Section("www.sec.test", DNS.A, DNS.IN);
		assertNull(Resolver.resolveCached(q, false), "nothing cached");
		Resolver.resolve(q);
		assertNull(Resolver.resolveCached(q, false), "cached but not validated yet: needs a resolver thread");
		Resolver.Answer raw = Resolver.resolveCached(q, true);
		assertNotNull(raw, "CD: the client validates, the cached data is enough");
		assertNull(raw.result);
		Resolver.resolveValidated(q, false);
		Resolver.Answer a = Resolver.resolveCached(q, false);
		assertNotNull(a);
		assertEquals(Validator.Status.SECURE, a.result.status);
		assertEquals(1, a.msg.getAnswerCount() - count(a.msg, DNS.RRSIG));
	}
}
