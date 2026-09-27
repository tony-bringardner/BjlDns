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
package us.bringardner.net.dns.server;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import us.bringardner.net.dns.Cname;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.Nsec3;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.Rrsig;
import us.bringardner.net.dns.dnssec.Canonical;

/**
 * Adds the DNSSEC records to an answer for a client that set the DO bit
 * (RFC 4035 3.1), for the parts of it that come from signed zones:
 * <ul>
 * <li>the RRSIGs of every RRset in the answer, authority and additional
 *     sections (glue has none);</li>
 * <li>a wildcard answer: the RRSIG of the wildcard, and the NSEC that proves
 *     no closer name exists (RFC 4035 3.1.3.3);</li>
 * <li>NXDOMAIN: the NSECs proving the name and the wildcard that could have
 *     matched don't exist (3.1.3.2);</li>
 * <li>NODATA: the NSEC of the name, which lists its types (3.1.3.1), or for
 *     an empty non-terminal or a wildcard the NSECs that show why (3.1.3.4);</li>
 * <li>a referral: the DS set, or the NSEC proving there is none (3.1.4).</li>
 * </ul>
 */
final class DnssecResponder {

	private DnssecResponder() {
	}

	/** Most CNAMEs followed to find the name a negative answer is about. */
	private static final int MAX_CHAIN = 16;

	/**
	 * The zone whose signatures cover an RRset: the closest enclosing zone,
	 * except for the DS at the apex of a zone whose parent we also serve,
	 * which belongs to the parent.
	 */
	private static Zone zoneOf(String name, int type, Function<String, Zone> zoneFor) {
		Zone z = zoneFor.apply(name);
		if( z != null && type == DNS.DS && z.isApex(name) ) {
			int dot = name.indexOf('.');
			Zone p = dot < 0 ? null : zoneFor.apply(name.substring(dot+1));
			if( p != null ) {
				z = p;
			}
		}
		return z;
	}

	/**
	 * @param zoneFor the zone we serve that a name is in (the closest
	 *        enclosing one), or null
	 */
	static void apply(Message msg, String qname, int qtype, Function<String, Zone> zoneFor) {
		if( msg == null ) {
			return;
		}
		Set<String> done = new HashSet<String>();
		List<RR> authorityAdds = new ArrayList<RR>();

		//  1. RRSIGs for the RRsets we have
		signSection(msg.getAnswer(), true, zoneFor, done, authorityAdds);
		signSection(msg.getAuthority(), false, zoneFor, done, authorityAdds);
		signSection(msg.getAdditional(), false, zoneFor, done, authorityAdds);

		//  2. Proofs of what does not exist
		String name = Canonical.key(qname);
		for(int i=0; i < MAX_CHAIN; i++ ) {
			String target = null;
			for(RR rr : msg.getAnswer()) {
				if( rr.getType() == DNS.CNAME && qtype != DNS.CNAME && Canonical.key(rr.getName()).equals(name) ) {
					target = Canonical.key(((Cname)rr).getCname());
				}
			}
			if( target == null ) {
				break;
			}
			name = target;
		}
		boolean answered = false;
		for(RR rr : msg.getAnswer()) {
			if( Canonical.key(rr.getName()).equals(name) && (rr.getType() == qtype || qtype == DNS.QTYPE_ALL) ) {
				answered = true;
			}
		}
		RR soa = null;
		RR ns = null;
		for(RR rr : msg.getAuthority()) {
			if( rr.getType() == DNS.SOA ) {
				soa = rr;
			} else if( rr.getType() == DNS.NS && ns == null ) {
				ns = rr;
			}
		}
		if( !answered && soa != null ) {
			Zone z = zoneOf(name, qtype, zoneFor);
			SignedZone sz = z == null ? null : z.getSigned();
			if( sz != null && Canonical.key(soa.getName()).equals(sz.apex) && Canonical.isBelow(name, sz.apex, true)
					&& sz.isNsec3() ) {
				nsec3Denial(sz, name, msg.getResponseCode() == DNS.NAME_ERROR, done, authorityAdds);
			} else if( sz != null && Canonical.key(soa.getName()).equals(sz.apex) && Canonical.isBelow(name, sz.apex, true) ) {
				if( msg.getResponseCode() == DNS.NAME_ERROR ) {
					addNsec(sz, sz.covering(name), done, authorityAdds);
					addNsec(sz, sz.covering("*."+sz.closestEncloser(name)), done, authorityAdds);
				} else if( sz.exists(name) ) {
					addNsec(sz, sz.nsecAt(name), done, authorityAdds);
				} else if( sz.isEmptyNonTerminal(name) ) {
					addNsec(sz, sz.covering(name), done, authorityAdds);
				} else {
					//  NODATA from a wildcard: no closer name, and the wildcard lacks the type
					String wild = "*."+sz.closestEncloser(name);
					addNsec(sz, sz.covering(name), done, authorityAdds);
					addNsec(sz, sz.nsecAt(wild), done, authorityAdds);
				}
			}
		} else if( !answered && soa == null && ns != null ) {
			//  A referral: the DS set, or proof there is none
			String cut = Canonical.key(ns.getName());
			Zone z = zoneFor.apply(cut);
			SignedZone sz = z == null ? null : z.getSigned();
			if( sz != null && !cut.equals(sz.apex) && Canonical.isBelow(cut, sz.apex, false) ) {
				List<Rrsig> dsSigs = sz.getSigs(cut, DNS.DS);
				if( dsSigs != null ) {
					if( done.add(cut+"|"+DNS.DS) ) {
						for(RR rr : z.exactRecords(cut)) {
							if( rr.getType() == DNS.DS ) {
								authorityAdds.add(rr.copy());
							}
						}
						for(Rrsig s : dsSigs) {
							authorityAdds.add(s.copy());
						}
					}
				} else if( sz.isNsec3() ) {
					//  RFC 5155 7.2.7: the NSEC3 of the delegation, without the DS bit
					//  (in an opt-out zone an unsigned delegation may have none:
					//  then the proof that it is covered by an opt-out NSEC3)
					Nsec3 at = sz.nsec3Matching(cut);
					if( at != null ) {
						addNsec(sz, at, done, authorityAdds);
					} else {
						closestProvableEncloser(sz, cut, done, authorityAdds);
					}
				} else {
					addNsec(sz, sz.nsecAt(cut), done, authorityAdds);
				}
			}
		}
		for(RR rr : authorityAdds) {
			msg.addAuthority(rr);
		}
	}

	/**
	 * NSEC3 proofs (RFC 5155 7.2): NODATA for a name that exists (or is an
	 * empty non-terminal) is its matching NSEC3; NXDOMAIN and wildcard
	 * NODATA need the closest encloser proof (the NSEC3 matching the closest
	 * encloser and the one covering the next closer name) plus the NSEC3
	 * covering (NXDOMAIN) or matching (NODATA) the wildcard.
	 */
	private static void nsec3Denial(SignedZone sz, String name, boolean nxdomain, Set<String> done, List<RR> out) {
		if( !nxdomain && (sz.exists(name) || sz.isEmptyNonTerminal(name)) ) {
			Nsec3 at = sz.nsec3Matching(name);
			if( at != null ) {
				addNsec(sz, at, done, out);
			} else {
				//  An unsigned delegation in an opt-out zone (RFC 5155 7.2.4)
				closestProvableEncloser(sz, name, done, out);
			}
			return;
		}
		String ce = sz.closestEncloser(name);
		addNsec(sz, sz.nsec3Matching(ce), done, out);
		addNsec(sz, sz.nsec3Covering(nextCloser(name, ce)), done, out);
		String wild = "*."+ce;
		addNsec(sz, nxdomain ? sz.nsec3Covering(wild) : sz.nsec3Matching(wild), done, out);
	}

	/**
	 * The closest provable encloser proof (RFC 5155 7.2.1): the NSEC3 of the
	 * nearest ancestor that has one, and the NSEC3 covering the next closer
	 * name (with the opt-out flag, for an unsigned delegation).
	 */
	private static void closestProvableEncloser(SignedZone sz, String name, Set<String> done, List<RR> out) {
		String ce = Canonical.key(name);
		Nsec3 match = null;
		while( match == null && !ce.equals(sz.apex) && ce.indexOf('.') >= 0 ) {
			ce = ce.substring(ce.indexOf('.')+1);
			match = sz.nsec3Matching(ce);
		}
		if( match == null ) {
			match = sz.nsec3Matching(sz.apex);
			ce = sz.apex;
		}
		addNsec(sz, match, done, out);
		addNsec(sz, sz.nsec3Covering(nextCloser(name, ce)), done, out);
	}

	/** The name one label longer than the closest encloser, on the way to name. */
	static String nextCloser(String name, String ce) {
		String n = Canonical.key(name);
		String c = Canonical.key(ce);
		while( true ) {
			int dot = n.indexOf('.');
			String parent = dot < 0 ? "" : n.substring(dot+1);
			if( parent.equals(c) || dot < 0 ) {
				return n;
			}
			n = parent;
		}
	}

	private static void addNsec(SignedZone sz, RR nsec, Set<String> done, List<RR> out) {
		if( nsec == null ) {
			return;
		}
		String owner = Canonical.key(nsec.getName());
		if( !done.add(owner+"|"+nsec.getType()) ) {
			return;
		}
		out.add(nsec.copy());
		List<Rrsig> sigs = sz.getSigs(owner, nsec.getType());
		if( sigs != null ) {
			for(Rrsig s : sigs) {
				out.add(s.copy());
			}
		}
	}

	private static void signSection(List<RR> section, boolean answer, Function<String, Zone> zoneFor,
			Set<String> done, List<RR> authorityAdds) {
		//  The RRsets, in order: owner|type -> records
		Map<String, List<RR>> sets = new LinkedHashMap<String, List<RR>>();
		for(RR rr : section) {
			int t = rr.getType();
			if( t == DNS.RRSIG || t == DNS.OPT || t == DNS.TSIG ) {
				continue;
			}
			sets.computeIfAbsent(Canonical.key(rr.getName())+"|"+t, k -> new ArrayList<RR>()).add(rr);
		}
		List<RR> adds = new ArrayList<RR>();
		for(Map.Entry<String, List<RR>> e : sets.entrySet()) {
			RR first = e.getValue().get(0);
			String owner = Canonical.key(first.getName());
			int type = first.getType();
			Zone z = zoneOf(owner, type, zoneFor);
			SignedZone sz = z == null ? null : z.getSigned();
			if( sz == null || !Canonical.isBelow(owner, sz.apex, true) ) {
				continue;
			}
			if( (type == DNS.NSEC || type == DNS.NSEC3) && done.contains(e.getKey()) ) {
				continue;
			}
			int ttl = Integer.MAX_VALUE;
			for(RR rr : e.getValue()) {
				ttl = Math.min(ttl, rr.getTTL());
			}
			List<Rrsig> sigs = sz.getSigs(owner, type);
			boolean wildcard = false;
			if( sigs == null && answer && !sz.exists(owner) && !sz.isEmptyNonTerminal(owner) ) {
				//  Synthesized from a wildcard: its signature, with this owner
				sigs = sz.getSigs("*."+sz.closestEncloser(owner), type);
				wildcard = sigs != null;
			}
			if( sigs == null ) {
				continue;
			}
			done.add(e.getKey());
			for(Rrsig s : sigs) {
				Rrsig c = (Rrsig)s.copy();
				c.setName(first.getName());
				c.setTTL(Math.min(ttl, s.getOrigTtl()));
				adds.add(c);
			}
			if( wildcard ) {
				//  Proof that no closer name exists
				if( sz.isNsec3() ) {
					//  RFC 5155 7.2.6: the NSEC3 covering the next closer name
					addNsec(sz, sz.nsec3Covering(nextCloser(owner, sz.closestEncloser(owner))), done, authorityAdds);
				} else {
					addNsec(sz, sz.covering(owner), done, authorityAdds);
				}
			}
		}
		section.addAll(adds);
	}
}
