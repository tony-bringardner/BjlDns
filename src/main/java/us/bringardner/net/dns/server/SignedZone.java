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
import us.bringardner.net.dns.Rrsig;
import us.bringardner.net.dns.dnssec.Canonical;

/**
 * The DNSSEC data of a signed zone (made by {@link ZoneSigner}): the RRSIGs
 * of every RRset and the NSEC chain, plus what is needed to know when the
 * zone must be signed again. Never changed after it is made.
 */
public final class SignedZone {

	final Zone unsigned;
	final String apex;
	private final Map<String, List<Rrsig>> sigs;
	private final NavigableMap<String, Nsec> chain;
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

	SignedZone(Zone unsigned, String apex, Map<String, List<Rrsig>> sigs, NavigableMap<String, Nsec> chain,
			long signedAt, long expires, long refreshAt, String keyId, String dynamicFingerprint, int rrsigCount) {
		this.unsigned = unsigned;
		this.apex = apex;
		this.sigs = sigs;
		this.chain = chain;
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
		return chain.get(Canonical.key(name));
	}

	/** @return true if the name owns records (has an NSEC) */
	public boolean exists(String name) {
		return chain.containsKey(Canonical.key(name));
	}

	/**
	 * The NSEC that covers a name that does not exist: the one whose owner
	 * comes before the name and whose next name comes after it (the last one,
	 * whose next name is the apex, covers everything after it).
	 */
	public Nsec covering(String name) {
		String n = Canonical.key(name);
		Map.Entry<String, Nsec> e = chain.lowerEntry(n);
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
		String n = Canonical.key(name);
		if( chain.containsKey(n) ) {
			return false;
		}
		String next = chain.higherKey(n);
		return next != null && Canonical.isBelow(next, n, false);
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
			if( n.equals(apex) || chain.containsKey(n) || isEmptyNonTerminal(n) ) {
				return n;
			}
		}
	}

	/** Number of names in the NSEC chain. */
	public int size() {
		return chain.size();
	}
}
