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

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.LongSupplier;

import us.bringardner.net.dns.Base32Hex;
import us.bringardner.net.dns.Cname;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.DnsBaseClass;
import us.bringardner.net.dns.Dnskey;
import us.bringardner.net.dns.Ds;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.Nsec;
import us.bringardner.net.dns.Nsec3;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.Rrsig;
import us.bringardner.net.dns.Section;
import us.bringardner.net.dns.dnssec.Algorithm;
import us.bringardner.net.dns.dnssec.Canonical;
import us.bringardner.net.dns.dnssec.DnssecKey;
import us.bringardner.net.dns.dnssec.Nsec3Params;

/**
 * DNSSEC validation of the answers the resolver fetches (RFC 4033-4035,
 * RFC 5155, RFC 6840).
 * <p>
 * Trust starts at the trust anchors (by default the root zone's key signing
 * keys). For a name, the validator walks down from the anchor one label at a
 * time asking for the DS record: a signed DS leads to the child zone's
 * DNSKEY set (which must be signed by a key the DS points at); a signed
 * proof that a delegation has no DS makes everything below it insecure. With
 * the keys of the zone that holds the name, every RRset of the answer must
 * carry a valid signature (inside its validity period, by that zone), and a
 * negative answer must carry a valid NSEC or NSEC3 proof.
 * <ul>
 * <li>SECURE: everything verified (the AD bit may be set).</li>
 * <li>INSECURE: the name is under a delegation proven to be unsigned, or
 *     uses only algorithms we don't support: passed on, not marked.</li>
 * <li>BOGUS: should be signed but isn't, or doesn't verify: the client gets
 *     SERVFAIL.</li>
 * </ul>
 * Key sets and the result of each walk step are cached (bounded, with the
 * records' TTLs; failures only briefly).
 */
public final class Validator extends DnsBaseClass {

	public enum Status { SECURE, INSECURE, BOGUS }

	/** A validation result and, for INSECURE / BOGUS, why. */
	public static final class Result {
		public final Status status;
		public final String why;

		Result(Status status, String why) {
			this.status = status;
			this.why = why;
		}

		@Override
		public String toString() {
			return status+(why == null ? "" : " ("+why+")");
		}
	}

	/** The root zone's key signing keys (KSK-2017 and KSK-2024), as DS records. */
	public static final String [] ROOT_ANCHORS = {
			". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
			". IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"
	};

	/** Clock difference allowed for signature validity times (seconds). */
	static final long SKEW = 300;
	/** NSEC3 zones with more iterations are treated as insecure (RFC 9276 3.2). */
	static final int MAX_NSEC3_ITERATIONS = 150;
	/** Most CNAME hops checked in one answer. */
	static final int MAX_CHAIN = 16;
	/** How long a failure is remembered (seconds). */
	static final long BAD_TTL = 60;
	/** Longest time anything is cached (seconds). */
	static final long MAX_TTL = 3600;

	/** The keys of a zone, or why there are none we trust. */
	static final class ZoneKeys {
		final String zone;
		final Status status;
		final List<Dnskey> keys;
		final long expires;
		final String why;

		ZoneKeys(String zone, Status status, List<Dnskey> keys, long expires, String why) {
			this.zone = zone;
			this.status = status;
			this.keys = keys;
			this.expires = expires;
			this.why = why;
		}
	}

	private final Function<Section, Message> fetch;
	private final LongSupplier clock;
	//  anchor zone (lower case, no dot) -> DS records
	private final Map<String, List<Ds>> anchors;
	//  name -> keys of the zone that holds it (the result of the walk)
	private final Map<String, ZoneKeys> walks;

	/**
	 * @param fetch resolves a question with DNSSEC records (DO), not validated;
	 *        null if there is no answer
	 * @param clock seconds since 1970
	 * @param anchors trust anchors as DS records (DNSKEY anchors converted)
	 * @param maxEntries size of the cache
	 */
	public Validator(Function<Section, Message> fetch, LongSupplier clock, List<Ds> anchors, int maxEntries) {
		this.fetch = fetch;
		this.clock = clock;
		Map<String, List<Ds>> a = new LinkedHashMap<String, List<Ds>>();
		for(Ds ds : anchors) {
			a.computeIfAbsent(Canonical.key(ds.getName()), k -> new ArrayList<Ds>()).add(ds);
		}
		this.anchors = a;
		this.walks = Collections.synchronizedMap(new LinkedHashMap<String, ZoneKeys>(256, 0.75f, true) {
			private static final long serialVersionUID = 1L;
			@Override
			protected boolean removeEldestEntry(Map.Entry<String, ZoneKeys> e) {
				return size() > maxEntries;
			}
		});
	}

	/** Forget everything cached. */
	public void clear() {
		walks.clear();
	}

	// ------------------------------------------------------------ trust anchors

	/** The built in root anchors. */
	public static List<Ds> rootAnchors() {
		List<Ds> ret = new ArrayList<Ds>();
		for(String line : ROOT_ANCHORS) {
			ret.addAll(parseAnchors(line));
		}
		return ret;
	}

	/**
	 * Trust anchors from text: one record per line, "name [ttl] [IN] DS tag
	 * alg digesttype digest" or "name [ttl] [IN] DNSKEY flags 3 alg key"
	 * (like BIND's root.key / root.ds files; ';' and '#' start comments).
	 */
	public static List<Ds> parseAnchors(String text) {
		List<Ds> ret = new ArrayList<Ds>();
		for(String raw : text.split("\n")) {
			String line = raw;
			int c = line.indexOf(';');
			if( c >= 0 ) {
				line = line.substring(0, c);
			}
			line = line.replace('(', ' ').replace(')', ' ').trim();
			if( line.isEmpty() || line.startsWith("#") ) {
				continue;
			}
			List<String> t = new ArrayList<String>(Arrays.asList(line.split("\\s+")));
			int i = 1;
			while( i < t.size() && (t.get(i).matches("\\d+") || t.get(i).equalsIgnoreCase("IN")) ) {
				i++;
			}
			if( i >= t.size() ) {
				throw new IllegalArgumentException("Invalid trust anchor: "+raw);
			}
			String owner = Canonical.key(t.get(0));
			String type = t.get(i).toUpperCase();
			List<String> f = t.subList(i+1, t.size());
			if( type.equals("DS") && f.size() >= 4 ) {
				Ds ds = new Ds(owner, DNS.IN);
				ds.setKeyTag(Integer.parseInt(f.get(0)));
				ds.setAlgorithm(Integer.parseInt(f.get(1)));
				ds.setDigestType(Integer.parseInt(f.get(2)));
				ds.setDigest(String.join("", f.subList(3, f.size())));
				ret.add(ds);
			} else if( type.equals("DNSKEY") && f.size() >= 4 ) {
				Dnskey k = new Dnskey(owner, DNS.IN);
				k.setFlags(Integer.parseInt(f.get(0)));
				k.setProtocol(Integer.parseInt(f.get(1)));
				k.setAlgorithm(Integer.parseInt(f.get(2)));
				k.setKey(Base64.getDecoder().decode(String.join("", f.subList(3, f.size()))));
				ret.add(DnssecKey.ds(owner, k, Ds.SHA256, 0));
			} else {
				throw new IllegalArgumentException("Trust anchors must be DS or DNSKEY records: "+raw);
			}
		}
		return ret;
	}

	public static List<Ds> loadAnchors(File f) throws IOException {
		return parseAnchors(new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8));
	}

	// ------------------------------------------------------------ validating an answer

	/**
	 * Validate an answer to a question.
	 *
	 * @return SECURE, INSECURE or BOGUS; answers that are errors (SERVFAIL,
	 *         REFUSED...) are INSECURE: there is nothing to check
	 */
	public Result validate(Message m, Section question) {
		String qname = Canonical.key(question.getName());
		int qtype = question.getType();
		int rcode = m.getResponseCode();
		if( rcode != DNS.NOERROR && rcode != DNS.NAME_ERROR ) {
			return new Result(Status.INSECURE, "error answer, not validated");
		}
		Result worst = new Result(Status.SECURE, null);
		String name = qname;
		for(int hop=0; hop < MAX_CHAIN; hop++ ) {
			ZoneKeys zk = walk(qtype == DNS.DS && hop == 0 ? parent(name) : name);
			List<RR> atName = recordsAt(m.getAnswer(), name);
			List<RR> wanted = new ArrayList<RR>();
			RR cname = null;
			for(RR rr : atName) {
				if( rr.getType() == qtype || (qtype == DNS.QTYPE_ALL && rr.getType() != DNS.RRSIG) ) {
					wanted.add(rr);
				} else if( rr.getType() == DNS.CNAME ) {
					cname = rr;
				}
			}
			if( !wanted.isEmpty() ) {
				for(List<RR> set : bySet(wanted).values()) {
					worst = worse(worst, checkSet(set, m, zk));
				}
				return worst;
			}
			if( cname != null && qtype != DNS.CNAME ) {
				worst = worse(worst, checkSet(Collections.singletonList(cname), m, zk));
				name = Canonical.key(((Cname)cname).getCname());
				continue;
			}
			//  Nothing for the name: a negative answer
			return worse(worst, checkNegative(m, name, qtype, rcode == DNS.NAME_ERROR, zk));
		}
		return worse(worst, new Result(Status.BOGUS, "CNAME chain too long"));
	}

	private static Result worse(Result a, Result b) {
		return b.status.ordinal() > a.status.ordinal() ? b : a;
	}

	private static List<RR> recordsAt(List<RR> section, String name) {
		List<RR> ret = new ArrayList<RR>();
		for(RR rr : section) {
			if( Canonical.key(rr.getName()).equals(name) ) {
				ret.add(rr);
			}
		}
		return ret;
	}

	/** The RRsets (not RRSIG, OPT) of a list, by owner|type. */
	private static Map<String, List<RR>> bySet(List<RR> list) {
		Map<String, List<RR>> ret = new LinkedHashMap<String, List<RR>>();
		for(RR rr : list) {
			int t = rr.getType();
			if( t != DNS.RRSIG && t != DNS.OPT ) {
				ret.computeIfAbsent(Canonical.key(rr.getName())+"|"+t, k -> new ArrayList<RR>()).add(rr);
			}
		}
		return ret;
	}

	/** The RRSIGs in the message covering (owner, type). */
	private static List<Rrsig> sigsFor(Message m, String owner, int type) {
		List<Rrsig> ret = new ArrayList<Rrsig>();
		for(List<RR> section : Arrays.asList(m.getAnswer(), m.getAuthority())) {
			for(RR rr : section) {
				if( rr instanceof Rrsig && ((Rrsig)rr).getTypeCovered() == type && Canonical.key(rr.getName()).equals(owner) ) {
					ret.add((Rrsig)rr);
				}
			}
		}
		return ret;
	}

	/**
	 * Is the RRset signed by the zone? For a wildcard expansion, the proof
	 * that no closer name exists must be in the message too.
	 */
	private Result checkSet(List<RR> set, Message m, ZoneKeys zk) {
		if( zk.status != Status.SECURE ) {
			return new Result(zk.status, zk.why);
		}
		String owner = Canonical.key(set.get(0).getName());
		int type = set.get(0).getType();
		Rrsig good = verifySet(set, sigsFor(m, owner, type), zk);
		if( good == null ) {
			return new Result(Status.BOGUS, "no valid signature for "+owner+" "+typeName(type)+" by "+zk.zone);
		}
		int labels = Canonical.labelCount(owner);
		if( good.getLabels() < labels ) {
			//  A wildcard answer: prove the name itself does not exist
			String ce = lastLabels(owner, good.getLabels());
			Denial d = denial(m, zk);
			if( d.nsec3 != null ) {
				Nsec3 cover = d.nsec3Covering(nextCloser(owner, ce));
				if( cover == null ) {
					return new Result(Status.BOGUS, "wildcard answer for "+owner+" without NSEC3 proof");
				}
			} else if( d.nsecCovering(owner) == null ) {
				return new Result(Status.BOGUS, "wildcard answer for "+owner+" without NSEC proof");
			}
		}
		return new Result(Status.SECURE, null);
	}

	/** @return the first RRSIG that verifies the set with the zone's keys, or null */
	private Rrsig verifySet(List<RR> set, List<Rrsig> sigs, ZoneKeys zk) {
		long now = clock.getAsLong();
		String owner = Canonical.key(set.get(0).getName());
		int labels = Canonical.labelCount(owner);
		for(Rrsig s : sigs) {
			if( !Canonical.key(s.getSigner()).equals(zk.zone) || s.getLabels() > labels
					|| s.getInception() > now + SKEW || s.getExpiration() < now - SKEW
					|| !Algorithm.isSupported(s.getAlgorithm()) ) {
				continue;
			}
			String signed = s.getLabels() < labels ? "*."+lastLabels(owner, s.getLabels()) : owner;
			for(Dnskey k : zk.keys) {
				if( k.getKeyTag() == s.getKeyTag() && k.getAlgorithm() == s.getAlgorithm()
						&& Canonical.verify(s, signed, set, k) ) {
					return s;
				}
			}
		}
		return null;
	}

	/** The last n labels of a name. */
	static String lastLabels(String name, int n) {
		String [] l = Canonical.key(name).split("\\.");
		if( n <= 0 || l.length == 0 || name.isEmpty() ) {
			return "";
		}
		StringBuilder b = new StringBuilder();
		for(int i=Math.max(0, l.length-n); i < l.length; i++ ) {
			if( b.length() > 0 ) {
				b.append('.');
			}
			b.append(l[i]);
		}
		return b.toString();
	}

	static String parent(String name) {
		String n = Canonical.key(name);
		int dot = n.indexOf('.');
		return dot < 0 ? "" : n.substring(dot+1);
	}

	/** The name one label longer than ce, on the way to name. */
	static String nextCloser(String name, String ce) {
		String n = Canonical.key(name);
		String c = Canonical.key(ce);
		while( true ) {
			String p = parent(n);
			if( p.equals(c) || n.isEmpty() ) {
				return n;
			}
			n = p;
		}
	}

	private static String typeName(int t) {
		return t < DNS.TYPENAMES.length ? DNS.TYPENAMES[t] : "TYPE"+t;
	}

	// ------------------------------------------------------------ denial of existence

	/** The NSEC or NSEC3 records of a message whose signatures verify. */
	private final class Denial {
		final List<Nsec> nsec = new ArrayList<Nsec>();
		List<Nsec3> nsec3;
		Nsec3Params params;
		String apex;

		Nsec nsecAt(String name) {
			for(Nsec n : nsec) {
				if( Canonical.key(n.getName()).equals(name) ) {
					return n;
				}
			}
			return null;
		}

		/** An NSEC proving name does not exist (not at the parent side of a delegation above it). */
		Nsec nsecCovering(String name) {
			for(Nsec n : nsec) {
				String owner = Canonical.key(n.getName());
				String next = Canonical.key(n.getNext());
				boolean last = Canonical.compareNames(next, owner) <= 0;
				boolean covers = Canonical.compareNames(owner, name) < 0
						&& (last || Canonical.compareNames(name, next) < 0);
				boolean delegation = n.hasType(DNS.NS) && !n.hasType(DNS.SOA) && Canonical.isBelow(name, owner, false);
				if( covers && !delegation ) {
					return n;
				}
			}
			return null;
		}

		String hash(String name) {
			return params.hashLabel(name);
		}

		Nsec3 nsec3Matching(String name) {
			String h = hash(name);
			for(Nsec3 n : nsec3) {
				if( ownerLabel(n).equals(h) ) {
					return n;
				}
			}
			return null;
		}

		Nsec3 nsec3Covering(String name) {
			String h = hash(name);
			for(Nsec3 n : nsec3) {
				String owner = ownerLabel(n);
				String next = Base32Hex.encode(n.getNextHashed());
				boolean last = next.compareTo(owner) <= 0;
				boolean covers = last ? (h.compareTo(owner) > 0 || h.compareTo(next) < 0)
						: (h.compareTo(owner) > 0 && h.compareTo(next) < 0);
				if( covers ) {
					return n;
				}
			}
			return null;
		}

		/** The closest encloser of name (RFC 5155 8.3): the nearest ancestor with a matching NSEC3. */
		String closestEncloser(String name) {
			String c = parent(name);
			while( true ) {
				if( nsec3Matching(c) != null ) {
					return c;
				}
				if( c.equals(apex) || c.isEmpty() ) {
					return null;
				}
				c = parent(c);
			}
		}
	}

	private static String ownerLabel(Nsec3 n) {
		String o = Canonical.key(n.getName());
		int dot = o.indexOf('.');
		return dot < 0 ? o : o.substring(0, dot);
	}

	/** The verified NSEC / NSEC3 records of the message. */
	private Denial denial(Message m, ZoneKeys zk) {
		Denial d = new Denial();
		d.apex = zk.zone;
		for(List<RR> set : bySet(m.getAuthority()).values()) {
			int t = set.get(0).getType();
			if( t != DNS.NSEC && t != DNS.NSEC3 ) {
				continue;
			}
			String owner = Canonical.key(set.get(0).getName());
			if( verifySet(set, sigsFor(m, owner, t), zk) == null ) {
				continue;
			}
			if( t == DNS.NSEC ) {
				d.nsec.add((Nsec)set.get(0));
			} else {
				Nsec3 n = (Nsec3)set.get(0);
				if( n.getHashAlgorithm() != Nsec3Params.SHA1 || !parent(owner).equals(zk.zone) ) {
					continue;
				}
				if( d.nsec3 == null ) {
					d.nsec3 = new ArrayList<Nsec3>();
					d.params = new Nsec3Params(n.getIterations(), n.getSalt(), false);
				}
				d.nsec3.add(n);
			}
		}
		return d;
	}

	/** A negative answer (NXDOMAIN or NODATA) for name must be proven. */
	private Result checkNegative(Message m, String name, int qtype, boolean nxdomain, ZoneKeys zk) {
		if( zk.status != Status.SECURE ) {
			return new Result(zk.status, zk.why);
		}
		Denial d = denial(m, zk);
		if( d.nsec3 != null ) {
			if( d.params.getIterations() > MAX_NSEC3_ITERATIONS ) {
				return new Result(Status.INSECURE, "NSEC3 with "+d.params.getIterations()+" iterations");
			}
			return nsec3Negative(d, name, qtype, nxdomain);
		}
		if( d.nsec.isEmpty() ) {
			return new Result(Status.BOGUS, (nxdomain ? "NXDOMAIN" : "NODATA")+" for "+name+" without a valid NSEC/NSEC3 proof");
		}
		if( nxdomain ) {
			Nsec cover = d.nsecCovering(name);
			if( cover == null ) {
				return new Result(Status.BOGUS, "no NSEC proves "+name+" does not exist");
			}
			String ce = closestEncloser(name, cover);
			if( d.nsecCovering("*."+ce) == null ) {
				return new Result(Status.BOGUS, "no NSEC proves *."+ce+" does not exist");
			}
			return new Result(Status.SECURE, null);
		}
		Nsec at = d.nsecAt(name);
		if( at != null ) {
			if( at.hasType(qtype) || at.hasType(DNS.CNAME) ) {
				return new Result(Status.BOGUS, "the NSEC of "+name+" says "+typeName(qtype)+" exists");
			}
			if( qtype != DNS.DS && at.hasType(DNS.NS) && !at.hasType(DNS.SOA) ) {
				return new Result(Status.BOGUS, "NODATA from the parent side of the delegation "+name);
			}
			return new Result(Status.SECURE, null);
		}
		Nsec cover = d.nsecCovering(name);
		if( cover != null && Canonical.isBelow(cover.getNext(), name, false) ) {
			//  An empty non-terminal
			return new Result(Status.SECURE, null);
		}
		if( cover != null ) {
			//  NODATA from a wildcard
			Nsec wild = d.nsecAt("*."+closestEncloser(name, cover));
			if( wild != null && !wild.hasType(qtype) && !wild.hasType(DNS.CNAME) ) {
				return new Result(Status.SECURE, null);
			}
		}
		return new Result(Status.BOGUS, "no NSEC proves "+name+" has no "+typeName(qtype));
	}

	/** The closest encloser from an NSEC covering name: the longest ancestor of name shared with the owner or next name. */
	private static String closestEncloser(String name, Nsec cover) {
		String a = commonAncestor(name, Canonical.key(cover.getName()));
		String b = commonAncestor(name, Canonical.key(cover.getNext()));
		return a.length() >= b.length() ? a : b;
	}

	private static String commonAncestor(String name, String other) {
		String c = parent(name);
		while( !c.isEmpty() && !Canonical.isBelow(other, c, true) ) {
			c = parent(c);
		}
		return c;
	}

	private Result nsec3Negative(Denial d, String name, int qtype, boolean nxdomain) {
		if( !nxdomain ) {
			Nsec3 at = d.nsec3Matching(name);
			if( at != null ) {
				if( at.hasType(qtype) || at.hasType(DNS.CNAME) ) {
					return new Result(Status.BOGUS, "the NSEC3 of "+name+" says "+typeName(qtype)+" exists");
				}
				if( qtype != DNS.DS && at.hasType(DNS.NS) && !at.hasType(DNS.SOA) ) {
					return new Result(Status.BOGUS, "NODATA from the parent side of the delegation "+name);
				}
				return new Result(Status.SECURE, null);
			}
		}
		String ce = d.closestEncloser(name);
		if( ce == null ) {
			return new Result(Status.BOGUS, "no NSEC3 closest encloser for "+name);
		}
		Nsec3 nc = d.nsec3Covering(nextCloser(name, ce));
		if( nc == null ) {
			return new Result(Status.BOGUS, "no NSEC3 covers the next closer name of "+name);
		}
		if( (nc.getFlags() & Nsec3.FLAG_OPT_OUT) != 0 ) {
			//  An unsigned delegation may hide there (RFC 5155 9.2)
			return new Result(Status.INSECURE, "NSEC3 opt-out covers "+name);
		}
		if( nxdomain ) {
			if( d.nsec3Covering("*."+ce) == null ) {
				return new Result(Status.BOGUS, "no NSEC3 proves *."+ce+" does not exist");
			}
			return new Result(Status.SECURE, null);
		}
		Nsec3 wild = d.nsec3Matching("*."+ce);
		if( wild != null && !wild.hasType(qtype) && !wild.hasType(DNS.CNAME) ) {
			return new Result(Status.SECURE, null);
		}
		return new Result(Status.BOGUS, "no NSEC3 proves "+name+" has no "+typeName(qtype));
	}

	// ------------------------------------------------------------ the chain of trust

	/** The deepest trust anchor at or above name, or null. */
	private String anchorFor(String name) {
		String n = Canonical.key(name);
		while( true ) {
			if( anchors.containsKey(n) ) {
				return n;
			}
			if( n.isEmpty() ) {
				return null;
			}
			n = parent(n);
		}
	}

	/** The keys of the zone that holds name (SECURE), or why it is INSECURE / BOGUS. */
	ZoneKeys walk(String name) {
		String n = Canonical.key(name);
		long now = clock.getAsLong();
		ZoneKeys cached = walks.get(n);
		if( cached != null && cached.expires > now ) {
			return cached;
		}
		ZoneKeys ret;
		String anchor = anchorFor(n);
		if( anchor == null ) {
			ret = new ZoneKeys(n, Status.INSECURE, null, now+MAX_TTL, "no trust anchor for "+n);
		} else if( n.equals(anchor) ) {
			ret = keysFromDs(anchor, anchors.get(anchor), now+MAX_TTL);
		} else {
			ZoneKeys above = walk(parent(n));
			ret = above.status == Status.SECURE && !above.zone.equals(n) ? step(above, n) : above;
		}
		walks.put(n, ret);
		return ret;
	}

	/**
	 * One step down: is name a secure zone cut (DS), an unsigned delegation,
	 * or part of the zone above?
	 */
	private ZoneKeys step(ZoneKeys zone, String name) {
		long now = clock.getAsLong();
		Message m = fetch.apply(new Section(name, DNS.DS, DNS.IN));
		if( m == null ) {
			return bogus(name, "no answer for the DS of "+name, now);
		}
		List<RR> ds = new ArrayList<RR>();
		for(RR rr : m.getAnswer()) {
			if( rr.getType() == DNS.DS && Canonical.key(rr.getName()).equals(name) ) {
				ds.add(rr);
			}
		}
		if( !ds.isEmpty() ) {
			Rrsig sig = verifySet(ds, sigsFor(m, name, DNS.DS), zone);
			if( sig == null ) {
				return bogus(name, "the DS of "+name+" has no valid signature by "+zone.zone, now);
			}
			List<Ds> list = new ArrayList<Ds>();
			for(RR rr : ds) {
				list.add((Ds)rr);
			}
			return keysFromDs(name, list, Math.min(zone.expires, now+Math.min(MAX_TTL, ttl(ds))));
		}
		int rcode = m.getResponseCode();
		if( rcode != DNS.NOERROR && rcode != DNS.NAME_ERROR ) {
			return bogus(name, "error "+rcode+" for the DS of "+name, now);
		}
		//  A CNAME at the name (the zone answers it for any type): not a cut
		List<RR> cname = new ArrayList<RR>();
		for(RR rr : m.getAnswer()) {
			if( rr.getType() == DNS.CNAME && Canonical.key(rr.getName()).equals(name) ) {
				cname.add(rr);
			}
		}
		if( !cname.isEmpty() ) {
			if( verifySet(cname, sigsFor(m, name, DNS.CNAME), zone) == null ) {
				return bogus(name, "the CNAME of "+name+" has no valid signature by "+zone.zone, now);
			}
			return withExpiry(zone, Math.min(zone.expires, now+Math.min(MAX_TTL, ttl(cname))));
		}
		Denial d = denial(m, zone);
		long exp = Math.min(zone.expires, now+Math.min(MAX_TTL, negativeTtl(m)));
		if( d.nsec3 != null ) {
			if( d.params.getIterations() > MAX_NSEC3_ITERATIONS ) {
				return new ZoneKeys(name, Status.INSECURE, null, exp, "NSEC3 with too many iterations in "+zone.zone);
			}
			Nsec3 at = d.nsec3Matching(name);
			if( at != null ) {
				return cutWithoutDs(zone, name, at.hasType(DNS.NS), at.hasType(DNS.SOA), at.hasType(DNS.DS), exp);
			}
			String ce = d.closestEncloser(name);
			Nsec3 nc = ce == null ? null : d.nsec3Covering(nextCloser(name, ce));
			if( nc == null ) {
				return bogus(name, "no NSEC3 proof for the DS of "+name, now);
			}
			if( (nc.getFlags() & Nsec3.FLAG_OPT_OUT) != 0 ) {
				return new ZoneKeys(name, Status.INSECURE, null, exp, "opt-out: "+name+" may be an unsigned delegation");
			}
			//  The name does not exist: whatever is asked about it is in this zone
			return withExpiry(zone, exp);
		}
		if( d.nsec.isEmpty() ) {
			return bogus(name, "no NSEC/NSEC3 proof for the DS of "+name, now);
		}
		Nsec at = d.nsecAt(name);
		if( at != null ) {
			return cutWithoutDs(zone, name, at.hasType(DNS.NS), at.hasType(DNS.SOA), at.hasType(DNS.DS), exp);
		}
		if( d.nsecCovering(name) != null ) {
			//  An empty non-terminal, or a name that does not exist: in this zone
			return withExpiry(zone, exp);
		}
		return bogus(name, "no NSEC proof for the DS of "+name, now);
	}

	private ZoneKeys cutWithoutDs(ZoneKeys zone, String name, boolean ns, boolean soa, boolean ds, long exp) {
		if( ns && !soa ) {
			if( ds ) {
				return bogus(name, "the DS of "+name+" is denied but its NSEC says it exists", clock.getAsLong());
			}
			return new ZoneKeys(name, Status.INSECURE, null, exp, "unsigned delegation "+name);
		}
		//  Not a delegation: the name is in the zone above
		return withExpiry(zone, exp);
	}

	private static ZoneKeys withExpiry(ZoneKeys z, long exp) {
		return exp >= z.expires ? z : new ZoneKeys(z.zone, z.status, z.keys, exp, z.why);
	}

	private ZoneKeys bogus(String name, String why, long now) {
		final String w = why;
		logDebug(() -> "DNSSEC bogus: "+w);
		return new ZoneKeys(name, Status.BOGUS, null, now+BAD_TTL, why);
	}

	/**
	 * The DNSKEY set of a zone, trusted if a key in it matches a DS record
	 * (tag, algorithm and digest) and signs the set. INSECURE if no DS uses
	 * an algorithm and digest we support (RFC 4035 5.2).
	 */
	private ZoneKeys keysFromDs(String zone, List<Ds> dsList, long maxExpires) {
		long now = clock.getAsLong();
		List<Ds> usable = new ArrayList<Ds>();
		for(Ds ds : dsList) {
			if( Algorithm.isSupported(ds.getAlgorithm())
					&& (ds.getDigestType() == 1 || ds.getDigestType() == Ds.SHA256 || ds.getDigestType() == Ds.SHA384) ) {
				usable.add(ds);
			}
		}
		if( usable.isEmpty() ) {
			return new ZoneKeys(zone, Status.INSECURE, null, maxExpires, "no DS of "+zone+" uses a supported algorithm");
		}
		Message m = fetch.apply(new Section(zone, DNS.DNSKEY, DNS.IN));
		if( m == null ) {
			return bogus(zone, "no answer for the DNSKEY of "+zone, now);
		}
		List<RR> set = new ArrayList<RR>();
		for(RR rr : m.getAnswer()) {
			if( rr instanceof Dnskey && Canonical.key(rr.getName()).equals(zone) ) {
				set.add(rr);
			}
		}
		if( set.isEmpty() ) {
			return bogus(zone, zone+" has DS records but no DNSKEY", now);
		}
		List<Dnskey> keys = new ArrayList<Dnskey>();
		for(RR rr : set) {
			Dnskey k = (Dnskey)rr;
			if( (k.getFlags() & Dnskey.FLAG_ZONE) != 0 && k.getProtocol() == 3 ) {
				keys.add(k);
			}
		}
		List<Rrsig> sigs = sigsFor(m, zone, DNS.DNSKEY);
		for(Ds ds : usable) {
			for(Dnskey k : keys) {
				if( k.getKeyTag() != ds.getKeyTag() || k.getAlgorithm() != ds.getAlgorithm() || !digestMatches(zone, k, ds) ) {
					continue;
				}
				ZoneKeys single = new ZoneKeys(zone, Status.SECURE, Collections.singletonList(k), 0, null);
				if( verifySet(set, sigs, single) != null ) {
					long exp = Math.min(maxExpires, now+Math.min(MAX_TTL, ttl(set)));
					return new ZoneKeys(zone, Status.SECURE, keys, exp, null);
				}
			}
		}
		return bogus(zone, "the DNSKEY set of "+zone+" is not signed by a key its DS points to", now);
	}

	private static boolean digestMatches(String zone, Dnskey k, Ds ds) {
		try {
			byte [] d;
			if( ds.getDigestType() == 1 ) {
				java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-1");
				md.update(Canonical.nameWire(zone));
				md.update(k.rdataBytes());
				d = md.digest();
			} else {
				d = DnssecKey.ds(zone, k, ds.getDigestType(), 0).getDigest();
			}
			return Arrays.equals(d, ds.getDigest());
		} catch(Exception ex) {
			return false;
		}
	}

	private static long ttl(List<RR> set) {
		long t = Long.MAX_VALUE;
		for(RR rr : set) {
			t = Math.min(t, rr.getTTL() & 0xffffffffL);
		}
		return t == Long.MAX_VALUE ? 0 : t;
	}

	private static long negativeTtl(Message m) {
		for(RR rr : m.getAuthority()) {
			if( rr instanceof us.bringardner.net.dns.Soa ) {
				us.bringardner.net.dns.Soa s = (us.bringardner.net.dns.Soa)rr;
				return Math.min(s.getTTL() & 0xffffffffL, s.getMinimum() & 0xffffffffL);
			}
		}
		return BAD_TTL;
	}
}
