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
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.A;
import us.bringardner.net.dns.ByteBuffer;
import us.bringardner.net.dns.Cname;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.Ns;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.Section;
import us.bringardner.net.dns.Utility;

/**
 * Offline tests for the resolver cache: isolation of returned messages,
 * TTL countdown/expiry, LRU bound, key handling and concurrent use.
 */
public class TestCache {

	private final AtomicLong now = new AtomicLong(1_000_000L);

	private Cache newCache(int max) {
		return new Cache(max, now::get);
	}

	private void advanceSeconds(long s) {
		now.addAndGet(s*1000L);
	}

	private static Message response(String name, String ip, int ttl) {
		Message m = new Message();
		m.setQuestion(name, DNS.A, DNS.IN);
		m.setMessageTypeResponse();
		A a = new A(name);
		a.setAddress(ip);
		a.setTTL(ttl);
		m.addAnswer(a);
		return m;
	}

	/** Parse a message the way the resolver receives it (lazy rdata from the wire). */
	private static Message fromWire(Message m) {
		return new Message(new ByteBuffer(m.toByteArray()));
	}

	private static Section q(String name) {
		return new Section(name, DNS.A, DNS.IN);
	}

	@Test
	public void hitAndMiss() {
		Cache c = newCache(10);
		assertNull(c.get(q("www.example.com")));
		c.put(response("www.example.com","10.0.0.1",300));
		Message m = c.get(q("www.example.com"));
		assertNotNull(m);
		assertEquals("10.0.0.1", ((A)m.getAnswer().get(0)).getAddressString());
	}

	@Test
	public void returnedMessagesAreIndependent() {
		Cache c = newCache(10);
		c.put(response("www.example.com","10.0.0.1",300));

		Message m1 = c.get(q("www.example.com"));
		Message m2 = c.get(q("www.example.com"));
		assertNotSame(m1, m2);
		assertNotSame(m1.getAnswer().get(0), m2.getAnswer().get(0));

		// What ResolverThread does to a response, plus some abuse
		m1.setID(1111);
		m1.truncateOn();
		m1.getAnswer().get(0).setTTL(1);
		m1.addAnswer(new A("junk.example.com"));

		Message m3 = c.get(q("www.example.com"));
		assertEquals(1, m3.getAnswerCount());
		assertEquals(300, m3.getAnswer().get(0).getTTL());
		assertTrue(!m3.getHeader().getTC(), "TC must not leak into the cache");
		assertTrue(m3.getID() != 1111, "ID must not leak into the cache");
	}

	@Test
	public void callerChangesAfterPutDoNotAffectCache() {
		Cache c = newCache(10);
		Message orig = response("www.example.com","10.0.0.1",300);
		c.put(orig);
		orig.getAnswer().get(0).setTTL(5);
		((A)orig.getAnswer().get(0)).setAddress("10.9.9.9");
		orig.setID(42);
		Message m = c.get(q("www.example.com"));
		assertEquals(300, m.getAnswer().get(0).getTTL());
		assertEquals("10.0.0.1", ((A)m.getAnswer().get(0)).getAddressString());
	}

	@Test
	public void ttlCountsDownAndExpires() {
		Cache c = newCache(10);
		c.put(response("www.example.com","10.0.0.1",300));

		advanceSeconds(100);
		Message m = c.get(q("www.example.com"));
		assertEquals(200, m.getAnswer().get(0).getTTL());

		// TTL on the wire is the remaining TTL too
		Message wire = fromWire(m);
		assertEquals(200, wire.getAnswer().get(0).getTTL());

		advanceSeconds(199);
		assertEquals(1, c.get(q("www.example.com")).getAnswer().get(0).getTTL());

		advanceSeconds(1);
		assertNull(c.get(q("www.example.com")), "must expire when TTL runs out");
		assertEquals(0, c.size(), "expired entry removed on access");
	}

	@Test
	public void repeatedHitsDoNotExtendLifetime() {
		// The old cache reset the timer on every hit, so popular names never expired
		Cache c = newCache(10);
		c.put(response("www.example.com","10.0.0.1",10));
		for(int i=0; i< 9; i++ ) {
			advanceSeconds(1);
			assertNotNull(c.get(q("www.example.com")));
		}
		advanceSeconds(1);
		assertNull(c.get(q("www.example.com")));
	}

	@Test
	public void entryLivesForSmallestAnswerTtl() {
		Cache c = newCache(10);
		Message m = new Message();
		m.setQuestion("www.example.com", DNS.A, DNS.IN);
		Cname cn = new Cname("www.example.com");
		cn.setCname("web.example.com");
		cn.setTTL(3600);
		m.addAnswer(cn);
		A a = new A("web.example.com");
		a.setAddress("10.0.0.2");
		a.setTTL(60);
		m.addAnswer(a);
		c.put(m);

		advanceSeconds(59);
		Message hit = c.get(q("www.example.com"));
		assertEquals(2, hit.getAnswerCount());
		assertEquals(3541, hit.getAnswer().get(0).getTTL());
		assertEquals("web.example.com", ((Cname)hit.getAnswer().get(0)).getCname());
		advanceSeconds(1);
		assertNull(c.get(q("www.example.com")));
	}

	@Test
	public void expiredAuthorityAndAdditionalAreDropped() {
		Cache c = newCache(10);
		Message m = response("www.example.com","10.0.0.1",300);
		Ns ns = new Ns("example.com");
		ns.setNs("ns1.example.com");
		ns.setTTL(30);
		m.addAuthority(ns);
		A glue = new A("ns1.example.com");
		glue.setAddress("10.0.0.53");
		glue.setTTL(600);
		m.addAdditional(glue);
		c.put(m);

		advanceSeconds(31);
		Message hit = c.get(q("www.example.com"));
		assertEquals(1, hit.getAnswerCount());
		assertEquals(0, hit.getNSCount(), "NS with 30s TTL has expired");
		assertEquals(1, hit.getAdditionalCount());
		assertEquals(569, hit.getAdditional().get(0).getTTL());
	}

	@Test
	public void maxAgeCapsLifetime() {
		long saved = Cache.getDefaultMaxAge();
		try {
			Cache.setDefaultMaxAge(60_000);
			Cache c = newCache(10);
			c.put(response("www.example.com","10.0.0.1",86400));
			advanceSeconds(59);
			assertNotNull(c.get(q("www.example.com")));
			advanceSeconds(1);
			assertNull(c.get(q("www.example.com")));
		} finally {
			Cache.setDefaultMaxAge(saved);
		}
	}

	@Test
	public void notCached() {
		Cache c = newCache(10);
		c.put(null);
		c.put(new Message());
		c.put(response("zero.example.com","10.0.0.1",0));   // TTL 0 = do not cache
		Message empty = new Message();
		empty.setQuestion("none.example.com", DNS.A, DNS.IN);
		c.put(empty);                                          // no answers
		assertEquals(0, c.size());
	}

	@Test
	public void keysAreCaseInsensitive() {
		Cache c = newCache(10);
		c.put(response("WWW.Example.COM","10.0.0.1",300));
		assertNotNull(c.get(q("www.example.com")));
		assertNotNull(c.get(q("Www.EXAMPLE.com")));
		assertEquals(1, c.size());
	}

	@Test
	public void keysDoNotCollide() {
		// old key: name+type+class  => "x1"+1+1 == "x"+11+1
		assertTrue(!Cache.getKey(new Section("x1",1,1)).equals(Cache.getKey(new Section("x",11,1))));
	}

	@Test
	public void lruBound() {
		Cache c = newCache(3);
		c.put(response("a.example.com","10.0.0.1",300));
		c.put(response("b.example.com","10.0.0.2",300));
		c.put(response("c.example.com","10.0.0.3",300));
		assertNotNull(c.get(q("a.example.com")));  // a is now most recently used
		c.put(response("d.example.com","10.0.0.4",300));
		assertEquals(3, c.size());
		assertNull(c.get(q("b.example.com")), "least recently used entry evicted");
		assertNotNull(c.get(q("a.example.com")));
		assertNotNull(c.get(q("d.example.com")));

		c.setMaxEntries(1);
		assertEquals(1, c.size());
	}

	@Test
	public void sweepRemovesExpired() {
		Cache c = newCache(100);
		c.put(response("short.example.com","10.0.0.1",10));
		c.put(response("long.example.com","10.0.0.2",1000));
		advanceSeconds(11);
		assertEquals(1, c.removeExpired());
		assertEquals(1, c.size());
		assertNotNull(c.get(q("long.example.com")));
	}

	@Test
	public void unsupportedRecordTypesCanBeCached() {
		// Parsed from the wire, an unknown type becomes a generic RR; copy() used to throw
		Message m = response("www.example.com","10.0.0.1",300);
		RR caa = new RR("example.com", 257, DNS.IN);   // CAA: no specific class in this library
		caa.setRdata(new byte[] {0,5,'i','s','s','u','e'});
		caa.setTTL(300);
		m.addAdditional(caa);
		Cache c = newCache(10);
		c.put(m);
		Message hit = c.get(q("www.example.com"));
		assertEquals(1, hit.getAdditionalCount());
		assertEquals(257, hit.getAdditional().get(0).getType());
	}

	@Test
	public void optIsNeverCached() {
		Message m = response("www.example.com","10.0.0.1",300);
		RR opt = new RR("www.example.com", DNS.OPT, 4096);
		opt.setRdata(new byte[0]);
		opt.setTTL(0x8000);   // DO bit lives in the TTL field of OPT
		m.addAdditional(opt);
		Cache c = newCache(10);
		c.put(m);
		assertEquals(0, c.get(q("www.example.com")).getAdditionalCount());
	}

	@Test
	public void cachedWireResponseRoundTrips() {
		// Same path as the resolver: upstream bytes -> Message -> cache -> response bytes
		Message upstream = fromWire(response("www.example.com","10.0.0.1",300));
		Cache c = newCache(10);
		c.put(upstream);
		Message out = c.get(q("www.example.com"));
		out.setID(0x4242);
		Message client = fromWire(out);
		assertEquals(0x4242, client.getID());
		assertEquals("10.0.0.1", ((A)client.getAnswer().get(0)).getAddressString());
	}

	@Test
	public void concurrentReadersGetTheirOwnIds() throws Exception {
		// Before this change every thread shared (and re-IDed) the same cached
		// Message, so clients could receive another client's transaction ID.
		Cache c = new Cache(100);
		c.put(fromWire(response("www.example.com","10.0.0.1",300)));

		int threads = 8, loops = 3000;
		CountDownLatch start = new CountDownLatch(1);
		AtomicReference<String> failure = new AtomicReference<String>();
		List<Thread> list = new ArrayList<Thread>();
		for(int t=0; t< threads; t++ ) {
			final int base = t*loops;
			Thread th = new Thread(() -> {
				try {
					start.await();
					for(int i=0; i< loops && failure.get() == null; i++ ) {
						int id = (base+i) & 0xffff;
						Message m = c.get(q("www.example.com"));
						m.setID(id);
						byte [] data = m.toByteArray();
						int wireId = Utility.makeShort(data[0], data[1]);
						if( wireId != id ) {
							failure.compareAndSet(null,"expected ID "+id+" on the wire but got "+wireId);
						}
						if( (i % 100) == 0 ) {
							c.put(fromWire(response("www.example.com","10.0.0.1",300)));
						}
					}
				} catch(Throwable ex) {
					failure.compareAndSet(null, ex.toString());
				}
			});
			list.add(th);
			th.start();
		}
		start.countDown();
		for(Thread th : list) {
			th.join(30_000);
		}
		assertNull(failure.get(), failure.get());
	}
}
