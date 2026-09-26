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

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;

import us.bringardner.net.dns.Nsec;
import us.bringardner.net.dns.Nsec3;
import us.bringardner.net.dns.Rrsig;
import us.bringardner.net.dns.dnssec.Canonical;
import us.bringardner.net.dns.dnssec.Nsec3Params;

/**
 * The DNSSEC data of a signed zone (made by {@link ZoneSigner}): the RRSIGs
 * of every RRset and the NSEC or NSEC3 chain, plus what is needed to know
 * when the zone must be signed again. Never changed after it is made.
 */
public final class SignedZone {

	final Zone unsigned;
	final String apex;
	private final Map<String, List<Rrsig>> sigs;
	//  The names that own records (sort keys, Canonical.sortKey, so lookups
	//  compare plain strings)
	private final java.util.NavigableSet<String> names;
	//  NSEC: sort key -> NSEC (empty with NSEC3)
	private final NavigableMap<String, Nsec> chain;
	//  NSEC3: hash label -> NSEC3 (null with NSEC)
	private final NavigableMap<String, Nsec3> hashed;
	private final Nsec3Params nsec3;
	/** "NSEC" or "NSEC3 " + parameters. */
	final String mode;
	/** When it was signed and when the first signature expires (seconds since 1970). */
	final long signedAt;
	final long expires;
	/** Sign again from this time on (seconds since 1970). */
	final long refreshAt;
	/** Identifies the keys used; a different value means the keys changed. */
	final String keyId;
	/** The dynamic (admin port) entries that were signed with the zone. */
	final String dynamicFingerprint;
	final int rrsigCount;

	/**
	 * @param names the names that own records
	 * @param chain the NSEC records by name (NSEC), or empty
	 * @param hashed the NSEC3 records by hash label, or null (NSEC)
	 */
	SignedZone(Zone unsigned, String apex, Map<String, List<Rrsig>> sigs, java.util.Collection<String> names,
			Map<String, Nsec> chain, NavigableMap<String, Nsec3> hashed, Nsec3Params nsec3,
			long signedAt, long expires, long refreshAt, String keyId, String dynamicFingerprint, int rrsigCount) {
		this.unsigned = unsigned;
		this.apex = apex;
		this.sigs = sigs;
		java.util.TreeSet<String> keys = new java.util.TreeSet<String>();
		for(String n : names) {
			keys.add(Canonical.sortKey(n));
		}
		this.names = keys;
		java.util.TreeMap<String, Nsec> byKey = new java.util.TreeMap<String, Nsec>();
		for(Map.Entry<String, Nsec> e : chain.entrySet()) {
			byKey.put(Canonical.sortKey(e.getKey()), e.getValue());
		}
		this.chain = byKey;
		this.hashed = hashed;
		this.nsec3 = nsec3;
		this.mode = nsec3 == null ? "NSEC" : "NSEC3 "+nsec3;
		this.signedAt = signedAt;
		this.expires = expires;
		this.refreshAt = refreshAt;
		this.keyId = keyId;
		this.dynamicFingerprint = dynamicFingerprint;
		this.rrsigCount = rrsigCount;
	}

	static String sigKey(String name, int type) {
		return Canonical.key(name)+"|"+type;
	}

	/** The RRSIGs of the RRset (name, type), or null if it has none. */
	public List<Rrsig> getSigs(String name, int type) {
		return sigs.get(sigKey(name, type));
	}

	/** Every RRSIG of the zone (for a zone transfer). */
	public Map<String, List<Rrsig>> allSigs() {
		return Collections.unmodifiableMap(sigs);
	}

	/** Seconds since 1970 of the earliest signature expiration. */
	public long getExpires() {
		return expires;
	}

	public long getSignedAt() {
		return signedAt;
	}

	/** The NSEC at exactly this name, or null. */
	public Nsec nsecAt(String name) {
		return chain.get(Canonical.sortKey(name));
	}

	/** @return true if the name owns records */
	public boolean exists(String name) {
		return names.contains(Canonical.sortKey(name));
	}

	/** Is the zone signed with NSEC3 (else NSEC)? */
	public boolean isNsec3() {
		return nsec3 != null;
	}

	/** The NSEC3 parameters, or null with NSEC. */
	public Nsec3Params getNsec3Params() {
		return nsec3;
	}

	/** The NSEC3 records (for a zone transfer); empty with NSEC. */
	public java.util.Collection<Nsec3> allNsec3() {
		return hashed == null ? Collections.<Nsec3>emptyList() : Collections.unmodifiableCollection(hashed.values());
	}

	/** The NSEC3 whose owner is the hash of this name (it exists, or is an empty non-terminal), or null. */
	public Nsec3 nsec3Matching(String name) {
		return hashed == null ? null : hashed.get(nsec3.hashLabel(name));
	}

	/** The NSEC3 covering the hash of a name that does not exist. */
	public Nsec3 nsec3Covering(String name) {
		if( hashed == null ) {
			return null;
		}
		Map.Entry<String, Nsec3> e = hashed.lowerEntry(nsec3.hashLabel(name));
		if( e == null ) {
			e = hashed.lastEntry();
		}
		return e.getValue();
	}

	/**
	 * The NSEC that covers a name that does not exist: the one whose owner
	 * comes before the name and whose next name comes after it (the last one,
	 * whose next name is the apex, covers everything after it).
	 */
	public Nsec covering(String name) {
		Map.Entry<String, Nsec> e = chain.lowerEntry(Canonical.sortKey(name));
		if( e == null ) {
			e = chain.lastEntry();
		}
		return e.getValue();
	}

	/**
	 * @return true if the name owns no records but names below it do (an
	 * empty non-terminal, RFC 8020): it exists, so the answer is NODATA.
	 */
	public boolean isEmptyNonTerminal(String name) {
		return isEnt(Canonical.sortKey(name));
	}

	private boolean isEnt(String key) {
		if( names.contains(key) ) {
			return false;
		}
		//  The next name in order is below this one
		String next = names.higher(key);
		return next != null && next.startsWith(key);
	}

	/**
	 * The closest encloser of a name that does not exist (RFC 4592): its
	 * nearest ancestor in the zone that exists (owns records or is an empty
	 * non-terminal). The apex if nothing closer.
	 */
	public String closestEncloser(String name) {
		String n = Canonical.key(name);
		while( true ) {
			int dot = n.indexOf('.');
			if( dot < 0 ) {
				return apex;
			}
			n = n.substring(dot+1);
			if( !Canonical.isBelow(n, apex, true) ) {
				return apex;
			}
			String k = Canonical.sortKey(n);
			if( n.equals(apex) || names.contains(k) || isEnt(k) ) {
				return n;
			}
		}
	}

	/** Number of names that own records. */
	public int size() {
		return names.size();
	}
}
