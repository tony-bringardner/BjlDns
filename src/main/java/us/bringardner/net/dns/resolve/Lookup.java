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

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import us.bringardner.net.dns.A;
import us.bringardner.net.dns.AAAA;
import us.bringardner.net.dns.Cname;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.DnsBaseClass;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.Mx;
import us.bringardner.net.dns.Ptr;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.ReverseName;
import us.bringardner.net.dns.Section;
import us.bringardner.net.dns.Txt;

/**
 * Typed lookups on top of {@link Resolver}: ask for a name and type, get the
 * values back with a status that tells "no such name", "no records of that
 * type" and "try again later" apart (see {@link LookupResult.Status}).
 * <p>
 * CNAMEs are followed by the resolver; only records of the type asked are
 * returned. Answers come from, and go into, the resolver cache, so repeated
 * lookups (an SPF check makes several) are cheap.
 * <p>
 * Example:
 * <pre>
 *   LookupResult&lt;String&gt; r = Lookup.txt("_dmarc.example.com");
 *   switch( r.getStatus() ) {
 *     case OK:       ... r.getValues() ...
 *     case NXDOMAIN:
 *     case NODATA:   ... no record ...
 *     case TEMPFAIL: ... 4xx / temperror ...
 *   }
 * </pre>
 * The resolver must have been initialized ({@link Resolver#initResolver()});
 * with no servers configured every lookup that misses the cache is TEMPFAIL.
 */
public final class Lookup {

	/** How a question is answered: the resolver, replaced by tests. */
	static volatile Function<Section, Message> resolver = Resolver::resolve;

	private static final DnsBaseClass logger = new DnsBaseClass();

	private Lookup() {
	}

	/**
	 * TXT records of a name, each one's character-strings joined (RFC 7208 3.3,
	 * RFC 6376 3.6.2.2), in answer order.
	 */
	public static LookupResult<String> txt(String name) {
		return lookup(name, DNS.TXT, rr -> (rr instanceof Txt ? (Txt)rr : new Txt(rr)).getText());
	}

	/** IPv4 addresses (A records) of a name. */
	public static LookupResult<InetAddress> a(String name) {
		return lookup(name, DNS.A, rr -> toAddress((rr instanceof A ? (A)rr : new A(rr)).getAddress()));
	}

	/** IPv6 addresses (AAAA records) of a name. */
	public static LookupResult<InetAddress> aaaa(String name) {
		return lookup(name, DNS.AAAA, rr -> toAddress((rr instanceof AAAA ? (AAAA)rr : new AAAA(rr)).getAddress()));
	}

	/**
	 * IPv4 then IPv6 addresses of a name (two queries).
	 * <p>
	 * OK if either query found addresses (even if the other failed);
	 * otherwise TEMPFAIL if either failed, else NXDOMAIN if the name does
	 * not exist, else NODATA.
	 */
	public static LookupResult<InetAddress> addresses(String name) {
		LookupResult<InetAddress> v4 = a(name);
		LookupResult<InetAddress> v6 = aaaa(name);
		List<InetAddress> all = new ArrayList<InetAddress>(v4.getValues());
		all.addAll(v6.getValues());
		LookupResult.Status st;
		LookupResult<InetAddress> from;
		if( !all.isEmpty() ) {
			st = LookupResult.Status.OK;
			from = v4.isOk() ? v4 : v6;
		} else if( v4.isTempFail() || v6.isTempFail() ) {
			st = LookupResult.Status.TEMPFAIL;
			from = v4.isTempFail() ? v4 : v6;
		} else if( v4.getStatus() == LookupResult.Status.NXDOMAIN || v6.getStatus() == LookupResult.Status.NXDOMAIN ) {
			st = LookupResult.Status.NXDOMAIN;
			from = v4.getStatus() == LookupResult.Status.NXDOMAIN ? v4 : v6;
		} else {
			st = LookupResult.Status.NODATA;
			from = v4;
		}
		return new LookupResult<InetAddress>(from.getName(), DNS.A, st, all, from.getRcode(), from.getMessage());
	}

	/** MX records of a name, lowest preference first (equal preferences keep answer order). */
	public static LookupResult<Mx> mx(String name) {
		LookupResult<Mx> r = lookup(name, DNS.MX, rr -> rr instanceof Mx ? (Mx)rr : new Mx(rr));
		if( r.getValues().size() > 1 ) {
			List<Mx> sorted = new ArrayList<Mx>(r.getValues());
			Collections.sort(sorted, Comparator.comparingInt(Mx::getPref));	//  stable
			r = new LookupResult<Mx>(r.getName(), r.getType(), r.getStatus(), sorted, r.getRcode(), r.getMessage());
		}
		return r;
	}

	/**
	 * Host names (PTR records) for an address, from its in-addr.arpa or
	 * ip6.arpa name. The names are not checked against the address
	 * (forward-confirmation, RFC 7208 5.5, is up to the caller).
	 */
	public static LookupResult<String> ptr(InetAddress addr) {
		return ptrFor(ReverseName.of(addr));
	}

	/**
	 * Host names for an address written as text ("192.0.2.1", "2001:db8::1").
	 * @throws IllegalArgumentException if the text is not an address literal
	 */
	public static LookupResult<String> ptr(String address) {
		String rev = ReverseName.of(address);
		if( rev == null ) {
			throw new IllegalArgumentException("Not an IP address: "+address);
		}
		return ptrFor(rev);
	}

	private static LookupResult<String> ptrFor(String reverseName) {
		return lookup(reverseName, DNS.PTR, rr -> (rr instanceof Ptr ? (Ptr)rr : new Ptr(rr)).getPtr());
	}

	/** The records of any type, as returned by the resolver (A, Txt, Mx... objects). */
	public static LookupResult<RR> records(String name, int type) {
		return lookup(name, type, rr -> rr);
	}

	/**
	 * Resolve name/type (class IN) and turn the response into a result.
	 * @param map record to value; a null value is skipped
	 */
	static <T> LookupResult<T> lookup(String name, int type, Function<RR, T> map) {
		String n = normalize(name);
		Message m = ask(n, type);
		if( m == null ) {
			return new LookupResult<T>(n, type, LookupResult.Status.TEMPFAIL, null, -1, null);
		}
		int rcode = m.getResponseCode();
		if( rcode == DNS.NAME_ERROR ) {
			return new LookupResult<T>(n, type, LookupResult.Status.NXDOMAIN, null, rcode, m);
		}
		if( rcode != DNS.NOERROR ) {
			return new LookupResult<T>(n, type, LookupResult.Status.TEMPFAIL, null, rcode, m);
		}

		List<T> values = new ArrayList<T>();
		for(RR rr : m.getAnswer()) {
			if( rr.getType() == type ) {
				T v;
				try {
					v = map.apply(rr);
				} catch(RuntimeException ex) {
					//  Bad rdata in one record should not hide the others
					logger.logError("Skipping unreadable "+LookupResult.typeName(type)+" record for "+n, ex);
					continue;
				}
				if( v != null ) {
					values.add(v);
				}
			}
		}
		if( !values.isEmpty() ) {
			return new LookupResult<T>(n, type, LookupResult.Status.OK, values, rcode, m);
		}

		//  A CNAME whose target does not exist: the resolver combines the chain
		//  under the first response's RCODE (NOERROR), so ask about the target
		//  (from the cache) to get its own RCODE (RFC 6604).
		String target = cnameTarget(m, n);
		if( target != null ) {
			Message t = ask(target, type);
			if( t == null ) {
				return new LookupResult<T>(n, type, LookupResult.Status.TEMPFAIL, null, -1, m);
			}
			int trc = t.getResponseCode();
			if( trc == DNS.NAME_ERROR ) {
				return new LookupResult<T>(n, type, LookupResult.Status.NXDOMAIN, null, trc, t);
			}
			if( trc != DNS.NOERROR ) {
				return new LookupResult<T>(n, type, LookupResult.Status.TEMPFAIL, null, trc, t);
			}
		}
		//  Also the result for a CNAME loop or a chain too long to follow
		return new LookupResult<T>(n, type, LookupResult.Status.NODATA, null, rcode, m);
	}

	private static Message ask(String name, int type) {
		try {
			return resolver.apply(new Section(name, type, DNS.IN));
		} catch(RuntimeException ex) {
			logger.logError("Lookup of "+name+" "+LookupResult.typeName(type)+" failed", ex);
			return null;
		}
	}

	/**
	 * The end of the CNAME chain starting at name in the answer section,
	 * or null if name has no CNAME there (or the chain loops).
	 */
	static String cnameTarget(Message m, String name) {
		Map<String, String> next = new HashMap<String, String>();
		for(RR rr : m.getAnswer()) {
			if( rr.getType() == DNS.CNAME ) {
				Cname c = rr instanceof Cname ? (Cname)rr : new Cname(rr);
				next.put(stripDot(rr.getName()).toLowerCase(), stripDot(c.getCname()));
			}
		}
		String cur = name;
		Set<String> seen = new HashSet<String>();
		String t;
		while( (t=next.get(cur.toLowerCase())) != null ) {
			if( !seen.add(cur.toLowerCase()) ) {
				return null;	//  loop
			}
			cur = t;
		}
		return cur.equalsIgnoreCase(name) || seen.contains(cur.toLowerCase()) ? null : cur;
	}

	private static String normalize(String name) {
		if( name == null ) {
			throw new IllegalArgumentException("name is null");
		}
		String n = stripDot(name.trim());
		if( n.isEmpty() ) {
			throw new IllegalArgumentException("name is empty");
		}
		return n;
	}

	private static String stripDot(String s) {
		return s.endsWith(".") ? s.substring(0, s.length()-1) : s;
	}

	/** An address from A/AAAA rdata; a mapped IPv6 address stays an Inet6Address. */
	static InetAddress toAddress(byte [] b) {
		try {
			if( b != null && b.length == 4 ) {
				return InetAddress.getByAddress(b);
			}
			if( b != null && b.length == 16 ) {
				return Inet6Address.getByAddress(null, b, (NetworkInterface)null);
			}
		} catch(UnknownHostException ex) {
			//  Only thrown for a bad length, checked above
		}
		return null;
	}
}
