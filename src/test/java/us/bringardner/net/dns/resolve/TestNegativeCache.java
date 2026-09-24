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

import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.A;
import us.bringardner.net.dns.ByteBuffer;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.Ns;
import us.bringardner.net.dns.Section;
import us.bringardner.net.dns.Soa;

/**
 * Offline tests for negative caching (RFC 2308).
 */
public class TestNegativeCache {

	private final AtomicLong now = new AtomicLong(5_000_000L);

	private Cache newCache() {
		return new Cache(100, now::get);
	}

	private void advanceSeconds(long s) {
		now.addAndGet(s*1000L);
	}

	private static Soa soa(String zone, int ttl, int minimum) {
		Soa s = new Soa(zone);
		s.setMname("ns1."+zone);
		s.setRname("postmaster."+zone);
		s.setSerial(1);
		s.setRefreash(3600);
		s.setRetry(600);
		s.setExpire(86400);
		s.setMinimum(minimum);
		s.setTTL(ttl);
		return s;
	}

	/** Negative response as it arrives from upstream (parsed from the wire). */
	private static Message negative(String name, int type, int rcode, Soa soa) {
		Message m = new Message();
		m.setQuestion(name, type, DNS.IN);
		m.setMessageTypeResponse();
		m.setResponseCode(rcode);
		if( soa != null ) {
			m.addAuthority(soa);
		}
		return new Message(new ByteBuffer(m.toByteArray()));
	}

	private static Section q(String name, int type) {
		return new Section(name, type, DNS.IN);
	}

	@Test
	public void nxdomainIsCachedForSoaMinimum() {
		Cache c = newCache();
		c.put(negative("nope.example.test", DNS.A, DNS.NAME_ERROR, soa("example.test",3600,300)));

		Message m = c.get(q("nope.example.test", DNS.A));
		assertNotNull(m);
		assertEquals(DNS.NAME_ERROR, m.getResponseCode());
		assertEquals(0, m.getAnswerCount());
		assertEquals(1, m.getNSCount());
		assertTrue(m.getAuthority().get(0) instanceof Soa);
		assertEquals(300, m.getAuthority().get(0).getTTL(), "negative TTL = min(SOA TTL, MINIMUM)");

		advanceSeconds(120);
		assertEquals(180, c.get(q("nope.example.test", DNS.A)).getAuthority().get(0).getTTL());

		advanceSeconds(180);
		assertNull(c.get(q("nope.example.test", DNS.A)), "expired after the negative TTL");
	}

	@Test
	public void soaTtlLowerThanMinimumWins() {
		Cache c = newCache();
		c.put(negative("nope.example.test", DNS.A, DNS.NAME_ERROR, soa("example.test",60,300)));
		assertEquals(60, c.get(q("nope.example.test", DNS.A)).getAuthority().get(0).getTTL());
		advanceSeconds(60);
		assertNull(c.get(q("nope.example.test", DNS.A)));
	}

	@Test
	public void negativeTtlIsCapped() {
		long saved = Cache.getMaxNegativeTtl();
		try {
			Cache.setMaxNegativeTtl(600);
			Cache c = newCache();
			c.put(negative("nope.example.test", DNS.A, DNS.NAME_ERROR, soa("example.test",86400,86400)));
			assertEquals(600, c.get(q("nope.example.test", DNS.A)).getAuthority().get(0).getTTL());
		} finally {
			Cache.setMaxNegativeTtl(saved);
		}
	}

	@Test
	public void nxdomainAnswersEveryTypeForTheName() {
		Cache c = newCache();
		c.put(negative("Nope.Example.Test", DNS.A, DNS.NAME_ERROR, soa("example.test",3600,300)));
		Message mx = c.get(q("nope.example.test", DNS.MX));
		assertNotNull(mx, "NXDOMAIN applies to all types (RFC 2308 section 5)");
		assertEquals(DNS.NAME_ERROR, mx.getResponseCode());
		assertEquals(DNS.MX, mx.getFirstQuestion().getType(), "question is the one asked");
		assertNull(c.get(q("other.example.test", DNS.A)));
	}

	@Test
	public void nodataIsCachedPerType() {
		Cache c = newCache();
		c.put(negative("www.example.test", DNS.AAAA, DNS.NOERROR, soa("example.test",3600,300)));
		Message m = c.get(q("www.example.test", DNS.AAAA));
		assertNotNull(m);
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertEquals(0, m.getAnswerCount());
		assertNull(c.get(q("www.example.test", DNS.A)), "NODATA for AAAA says nothing about A");
	}

	@Test
	public void notCachedWithoutSoa() {
		Cache c = newCache();
		c.put(negative("nope.example.test", DNS.A, DNS.NAME_ERROR, null));
		c.put(negative("www.example.test", DNS.AAAA, DNS.NOERROR, null));
		assertEquals(0, c.size());
	}

	@Test
	public void referralIsNotCached() {
		Message m = new Message();
		m.setQuestion("www.sub.example.test", DNS.A, DNS.IN);
		m.setMessageTypeResponse();
		Ns ns = new Ns("sub.example.test");
		ns.setNs("ns1.sub.example.test");
		ns.setTTL(3600);
		m.addAuthority(ns);
		Cache c = newCache();
		c.put(m);
		assertEquals(0, c.size());
	}

	@Test
	public void otherErrorsAreNotCached() {
		Cache c = newCache();
		c.put(negative("x.example.test", DNS.A, 2 /* SERVFAIL */, soa("example.test",3600,300)));
		c.put(negative("y.example.test", DNS.A, 5 /* REFUSED */, soa("example.test",3600,300)));
		assertEquals(0, c.size());
	}

	@Test
	public void zeroTtlNotCached() {
		Cache c = newCache();
		c.put(negative("nope.example.test", DNS.A, DNS.NAME_ERROR, soa("example.test",3600,0)));
		assertEquals(0, c.size());
	}

	@Test
	public void positiveAnswerReplacesNxdomain() {
		Cache c = newCache();
		c.put(negative("new.example.test", DNS.A, DNS.NAME_ERROR, soa("example.test",3600,300)));
		Message pos = new Message();
		pos.setQuestion("new.example.test", DNS.A, DNS.IN);
		pos.setMessageTypeResponse();
		A a = new A("new.example.test");
		a.setAddress("10.0.0.7");
		a.setTTL(60);
		pos.addAnswer(a);
		c.put(pos);
		Message got = c.get(q("new.example.test", DNS.A));
		assertEquals(DNS.NOERROR, got.getResponseCode());
		assertEquals(1, got.getAnswerCount());
		assertNull(c.get(q("new.example.test", DNS.MX)), "NXDOMAIN for the name was dropped");
	}

	@Test
	public void cachedNegativeRoundTripsOnTheWire() {
		Cache c = newCache();
		c.put(negative("nope.example.test", DNS.A, DNS.NAME_ERROR, soa("example.test",3600,300)));
		Message out = c.get(q("nope.example.test", DNS.A));
		out.setID(0x1234);
		Message client = new Message(new ByteBuffer(out.toByteArray()));
		assertEquals(0x1234, client.getID());
		assertEquals(DNS.NAME_ERROR, client.getResponseCode());
		assertEquals(300, client.getAuthority().get(0).getTTL());
	}

	@Test
	public void resolverServesCachedNxdomainWithoutUpstream() {
		// No root servers are configured in tests, so a cache miss returns null;
		// a non-null NXDOMAIN proves the cached negative answer was used.
		Resolver.getCache().clear();
		Resolver.getCache().put(negative("gone.r.test", DNS.A, DNS.NAME_ERROR, soa("r.test",3600,300)));
		Message m = Resolver.resolve(q("gone.r.test", DNS.A));
		assertNotNull(m);
		assertEquals(DNS.NAME_ERROR, m.getResponseCode());
		Resolver.getCache().clear();
	}
}
