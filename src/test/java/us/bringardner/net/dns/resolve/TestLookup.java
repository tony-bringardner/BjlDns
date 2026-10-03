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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.A;
import us.bringardner.net.dns.AAAA;
import us.bringardner.net.dns.Cname;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.Mx;
import us.bringardner.net.dns.Ptr;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.Section;
import us.bringardner.net.dns.Soa;
import us.bringardner.net.dns.Txt;
import us.bringardner.net.dns.resolve.LookupResult.Status;

/**
 * Offline tests of Lookup: answers come from a map instead of the network.
 */
public class TestLookup {

	private final Map<String, Message> answers = new HashMap<String, Message>();
	private final List<String> asked = new ArrayList<String>();
	private Function<Section, Message> saved;

	@BeforeEach
	public void setUp() {
		saved = Lookup.resolver;
		Lookup.resolver = q -> {
			String key = key(q.getName(), q.getType());
			asked.add(key);
			return answers.get(key);
		};
	}

	@AfterEach
	public void tearDown() {
		Lookup.resolver = saved;
	}

	private static String key(String name, int type) {
		return name.toLowerCase()+"/"+type;
	}

	private Message response(String name, int type, int rcode, RR ... rrs) {
		Message m = new Message();
		m.setQuestion(name, type, DNS.IN);
		m.setMessageTypeResponse();
		m.setResponseCode(rcode);
		for(RR rr : rrs) {
			rr.setTTL(300);
			m.addAnswer(rr);
		}
		answers.put(key(name, type), m);
		return m;
	}

	private static Txt txt(String name, String ... strings) {
		Txt t = new Txt(name);
		t.setStrings(Arrays.asList(strings));
		return t;
	}

	private static Cname cname(String name, String target) {
		Cname c = new Cname(name);
		c.setCname(target);
		return c;
	}

	private static A a(String name, String ip) {
		A a = new A(name);
		a.setAddress(ip);
		return a;
	}

	private static AAAA aaaa(String name, String ip) {
		AAAA a = new AAAA(name);
		a.setAddress(ip);
		return a;
	}

	private static Mx mx(String name, int pref, String exch) {
		Mx m = new Mx(name);
		m.setPref((short)pref);
		m.setExchange(exch);
		return m;
	}

	@Test
	public void txtJoinsStrings() {
		response("sel._domainkey.example.com", DNS.TXT, DNS.NOERROR,
				txt("sel._domainkey.example.com", "v=DKIM1; k=rsa; ", "p=MIIB", "IjAN"),
				txt("sel._domainkey.example.com", "second"));
		LookupResult<String> r = Lookup.txt("sel._domainkey.example.com");
		assertEquals(Status.OK, r.getStatus());
		assertTrue(r.isOk());
		assertEquals(Arrays.asList("v=DKIM1; k=rsa; p=MIIBIjAN", "second"), r.getValues());
		assertEquals("v=DKIM1; k=rsa; p=MIIBIjAN", r.getFirst());
		assertEquals(DNS.NOERROR, r.getRcode());
	}

	@Test
	public void trailingDotIgnored() {
		response("example.com", DNS.TXT, DNS.NOERROR, txt("example.com", "v=spf1 -all"));
		LookupResult<String> r = Lookup.txt("example.com.");
		assertEquals("v=spf1 -all", r.getFirst());
		assertEquals("example.com", r.getName());
	}

	@Test
	public void nxdomain() {
		response("nope.example.com", DNS.TXT, DNS.NAME_ERROR);
		LookupResult<String> r = Lookup.txt("nope.example.com");
		assertEquals(Status.NXDOMAIN, r.getStatus());
		assertTrue(r.isNotFound());
		assertTrue(r.getValues().isEmpty());
		assertNull(r.getFirst());
	}

	@Test
	public void nodataEmptyAnswer() {
		Message m = response("example.com", DNS.TXT, DNS.NOERROR);
		Soa soa = new Soa("example.com");
		m.addAuthority(soa);
		assertEquals(Status.NODATA, Lookup.txt("example.com").getStatus());
	}

	@Test
	public void nodataOtherTypesOnly() {
		//  An answer with records of other types only (e.g. a server that
		//  added an A record) is still no TXT
		response("example.com", DNS.TXT, DNS.NOERROR, a("example.com", "192.0.2.1"));
		assertEquals(Status.NODATA, Lookup.txt("example.com").getStatus());
	}

	@Test
	public void tempfailNoResponse() {
		LookupResult<String> r = Lookup.txt("timeout.example.com");
		assertEquals(Status.TEMPFAIL, r.getStatus());
		assertEquals(-1, r.getRcode());
		assertNull(r.getMessage());
	}

	@Test
	public void tempfailServfailAndRefused() {
		response("sf.example.com", DNS.TXT, DNS.SERVER_ERROR);
		response("rf.example.com", DNS.TXT, DNS.REFUSED);
		assertEquals(Status.TEMPFAIL, Lookup.txt("sf.example.com").getStatus());
		assertEquals(DNS.SERVER_ERROR, Lookup.txt("sf.example.com").getRcode());
		assertTrue(Lookup.txt("rf.example.com").isTempFail());
	}

	@Test
	public void tempfailResolverThrows() {
		Lookup.resolver = q -> { throw new IllegalStateException("boom"); };
		assertEquals(Status.TEMPFAIL, Lookup.txt("example.com").getStatus());
	}

	@Test
	public void badName() {
		assertThrows(IllegalArgumentException.class, () -> Lookup.txt(null));
		assertThrows(IllegalArgumentException.class, () -> Lookup.txt(" "));
		assertThrows(IllegalArgumentException.class, () -> Lookup.txt("."));
	}

	@Test
	public void cnameFollowedOnlyTypeReturned() {
		response("alias.example.com", DNS.TXT, DNS.NOERROR,
				cname("alias.example.com", "real.example.net"),
				txt("real.example.net", "hello"));
		LookupResult<String> r = Lookup.txt("alias.example.com");
		assertEquals(Arrays.asList("hello"), r.getValues());
	}

	@Test
	public void cnameToMissingTargetIsNxdomain() {
		//  The resolver's combined chain keeps the first RCODE (NOERROR)
		response("dangling.example.com", DNS.TXT, DNS.NOERROR, cname("dangling.example.com", "gone.example.net"));
		response("gone.example.net", DNS.TXT, DNS.NAME_ERROR);
		LookupResult<String> r = Lookup.txt("dangling.example.com");
		assertEquals(Status.NXDOMAIN, r.getStatus());
		assertTrue(asked.contains(key("gone.example.net", DNS.TXT)));
	}

	@Test
	public void cnameToTargetWithoutTypeIsNodata() {
		response("a2.example.com", DNS.TXT, DNS.NOERROR, cname("a2.example.com", "host.example.net"));
		response("host.example.net", DNS.TXT, DNS.NOERROR);
		assertEquals(Status.NODATA, Lookup.txt("a2.example.com").getStatus());
	}

	@Test
	public void cnameTargetFails() {
		response("a3.example.com", DNS.TXT, DNS.NOERROR, cname("a3.example.com", "slow.example.net"));
		assertEquals(Status.TEMPFAIL, Lookup.txt("a3.example.com").getStatus());
	}

	@Test
	public void cnameLoopIsNodata() {
		response("l1.example.com", DNS.TXT, DNS.NOERROR,
				cname("l1.example.com", "l2.example.com"),
				cname("l2.example.com", "l1.example.com"));
		assertEquals(Status.NODATA, Lookup.txt("l1.example.com").getStatus());
	}

	@Test
	public void mxSortedByPreference() {
		response("example.com", DNS.MX, DNS.NOERROR,
				mx("example.com", 20, "mx2.example.com"),
				mx("example.com", 10, "mx1.example.com"),
				mx("example.com", 20, "mx3.example.com"));
		LookupResult<Mx> r = Lookup.mx("example.com");
		assertEquals(3, r.getValues().size());
		assertEquals("mx1.example.com", r.getValues().get(0).getExchange());
		assertEquals("mx2.example.com", r.getValues().get(1).getExchange());
		assertEquals("mx3.example.com", r.getValues().get(2).getExchange());
	}

	@Test
	public void addressesBothFamilies() throws Exception {
		response("host.example.com", DNS.A, DNS.NOERROR, a("host.example.com", "192.0.2.1"));
		response("host.example.com", DNS.AAAA, DNS.NOERROR, aaaa("host.example.com", "2001:db8::1"));
		assertEquals(Arrays.asList(InetAddress.getByName("192.0.2.1")), Lookup.a("host.example.com").getValues());
		assertEquals(Arrays.asList(InetAddress.getByName("2001:db8::1")), Lookup.aaaa("host.example.com").getValues());
		LookupResult<InetAddress> r = Lookup.addresses("host.example.com");
		assertEquals(Status.OK, r.getStatus());
		assertEquals(Arrays.asList(InetAddress.getByName("192.0.2.1"), InetAddress.getByName("2001:db8::1")), r.getValues());
	}

	@Test
	public void mappedAaaaStaysIpv6() {
		response("m.example.com", DNS.AAAA, DNS.NOERROR, aaaa("m.example.com", "::ffff:192.0.2.1"));
		InetAddress a = Lookup.aaaa("m.example.com").getFirst();
		assertTrue(a instanceof Inet6Address, String.valueOf(a));
	}

	@Test
	public void addressesStatusRules() {
		//  One family found, the other failed: OK
		response("h1.example.com", DNS.A, DNS.NOERROR, a("h1.example.com", "192.0.2.1"));
		assertEquals(Status.OK, Lookup.addresses("h1.example.com").getStatus());

		//  Nothing found, one failed: TEMPFAIL
		response("h2.example.com", DNS.A, DNS.NOERROR);
		assertEquals(Status.TEMPFAIL, Lookup.addresses("h2.example.com").getStatus());

		//  Both empty: NODATA
		response("h3.example.com", DNS.A, DNS.NOERROR);
		response("h3.example.com", DNS.AAAA, DNS.NOERROR);
		assertEquals(Status.NODATA, Lookup.addresses("h3.example.com").getStatus());

		//  No such name
		response("h4.example.com", DNS.A, DNS.NAME_ERROR);
		response("h4.example.com", DNS.AAAA, DNS.NAME_ERROR);
		assertEquals(Status.NXDOMAIN, Lookup.addresses("h4.example.com").getStatus());
	}

	@Test
	public void ptrByTextAndAddress() throws Exception {
		Ptr p = new Ptr("1.2.0.192.in-addr.arpa");
		p.setPtr("mail.example.com");
		response("1.2.0.192.in-addr.arpa", DNS.PTR, DNS.NOERROR, p);
		assertEquals(Arrays.asList("mail.example.com"), Lookup.ptr("192.0.2.1").getValues());
		assertEquals(Arrays.asList("mail.example.com"), Lookup.ptr(InetAddress.getByName("192.0.2.1")).getValues());

		LookupResult<String> v6 = Lookup.ptr("2001:db8::1");
		assertEquals(Status.TEMPFAIL, v6.getStatus());
		assertTrue(asked.contains(key("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", DNS.PTR)));

		assertThrows(IllegalArgumentException.class, () -> Lookup.ptr("mail.example.com"));
	}

	@Test
	public void recordsRaw() {
		response("example.com", DNS.TXT, DNS.NOERROR, txt("example.com", "x"));
		LookupResult<RR> r = Lookup.records("example.com", DNS.TXT);
		assertTrue(r.getFirst() instanceof Txt);
		assertFalse(r.toString().isEmpty());
	}

	@Test
	public void throughResolverCache() {
		//  The real Resolver, answered from its cache (no network)
		Lookup.resolver = saved;
		Resolver.getCache().clear();
		Message m = new Message();
		m.setQuestion("cached.lookup.test", DNS.TXT, DNS.IN);
		m.setMessageTypeResponse();
		Txt t = txt("cached.lookup.test", "v=DMARC1; ", "p=reject");
		t.setTTL(300);
		m.addAnswer(t);
		Resolver.getCache().put(m);
		try {
			LookupResult<String> r = Lookup.txt("cached.lookup.test");
			assertEquals(Status.OK, r.getStatus());
			assertEquals("v=DMARC1; p=reject", r.getFirst());
		} finally {
			Resolver.getCache().clear();
		}
	}
}
