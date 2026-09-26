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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Dnskey;
import us.bringardner.net.dns.Name;
import us.bringardner.net.dns.Base32Hex;
import us.bringardner.net.dns.Nsec;
import us.bringardner.net.dns.Nsec3;
import us.bringardner.net.dns.Nsec3param;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.Rrsig;
import us.bringardner.net.dns.Soa;
import us.bringardner.net.dns.dnssec.Canonical;
import us.bringardner.net.dns.dnssec.DnssecKey;
import us.bringardner.net.dns.dnssec.Nsec3Params;

/**
 * Signs a zone (DNSSEC, RFC 4033-4035): adds the DNSKEY set at the apex and
 * an NSEC record at every name, and signs every authoritative RRset.
 * <ul>
 * <li>Key signing keys (flags 257) sign the DNSKEY set, zone signing keys
 *     (256) everything else. With only one kind, it signs everything (a
 *     combined signing key).</li>
 * <li>At a delegation only the DS set and the NSEC are signed; names below
 *     it (glue) are neither signed nor in the NSEC chain.</li>
 * <li>Names outside the zone's own tree (the '*.*' patterns a default zone
 *     uses for other domains) are left as they are.</li>
 * <li>Signatures are valid from an hour ago (for clocks that are behind)
 *     until now + validity; the zone should be signed again when a quarter
 *     of that is left.</li>
 * </ul>
 * The result is a new Zone: the records of the unsigned one plus DNSKEY and
 * NSEC, with the signatures in its {@link SignedZone}.
 */
public final class ZoneSigner {

	/** Default signature validity: 14 days. */
	public static final int DEFAULT_VALIDITY = 14*24*3600;
	/** Signatures start this long before the time of signing. */
	static final int INCEPTION_OFFSET = 3600;

	private ZoneSigner() {
	}

	/** What a signing produced, with warnings for the log. */
	static final class Result {
		final Zone zone;
		final List<String> warnings;

		Result(Zone zone, List<String> warnings) {
			this.zone = zone;
			this.warnings = warnings;
		}
	}

	/** A text that changes when the keys (or which of them sign) change. */
	static String keyId(List<DnssecKey> keys, long now) {
		StringBuilder b = new StringBuilder();
		for(DnssecKey k : keys) {
			b.append(k.getAlgorithm()).append('+').append(k.getKeyTag()).append(k.isKsk() ? 'K' : 'Z')
				.append(k.isPublished(now) ? 'P' : '-').append(k.isActive(now) ? 'A' : '-').append(' ');
		}
		return b.toString();
	}

	/**
	 * Sign a zone.
	 *
	 * @param unsigned the zone as loaded (and updated)
	 * @param dynamic the dynamic (admin port) entries in this zone: lower case
	 *        name -> records, which replace the zone's records at that name
	 * @param dynamicFingerprint identifies dynamic, kept with the signatures
	 * @param now seconds since 1970
	 * @param validity seconds the signatures are valid
	 * @throws IllegalArgumentException if no key can sign now
	 */
	static Result sign(Zone unsigned, Map<String, List<? extends RR>> dynamic, String dynamicFingerprint,
			List<DnssecKey> keys, long now, int validity) {
		return sign(unsigned, dynamic, dynamicFingerprint, keys, now, validity, null);
	}

	/**
	 * Sign a zone, proving what does not exist with NSEC3 (RFC 5155) when
	 * nsec3 is not null, with NSEC otherwise.
	 */
	static Result sign(Zone unsigned, Map<String, List<? extends RR>> dynamic, String dynamicFingerprint,
			List<DnssecKey> keys, long now, int validity, Nsec3Params nsec3) {
		List<String> warnings = new ArrayList<String>();
		String apex = Canonical.key(unsigned.getName());
		Soa soa = unsigned.getSoa();

		//  Which keys are in the DNSKEY set, and which sign what
		List<DnssecKey> published = new ArrayList<DnssecKey>();
		List<DnssecKey> ksks = new ArrayList<DnssecKey>();
		List<DnssecKey> zsks = new ArrayList<DnssecKey>();
		Set<Integer> signingAlgs = new HashSet<Integer>();
		for(DnssecKey k : keys) {
			if( k.isPublished(now) ) {
				published.add(k);
			}
			if( k.isActive(now) ) {
				(k.isKsk() ? ksks : zsks).add(k);
				signingAlgs.add(k.getAlgorithm());
			}
		}
		if( ksks.isEmpty() && zsks.isEmpty() ) {
			throw new IllegalArgumentException("no key of "+apex+" can sign now (none has its .private file, or none is active)");
		}
		List<DnssecKey> keySigners = ksks.isEmpty() ? zsks : ksks;
		List<DnssecKey> zoneSigners = zsks.isEmpty() ? ksks : zsks;
		for(DnssecKey k : published) {
			if( !signingAlgs.contains(k.getAlgorithm()) ) {
				warnings.add("key "+k.getKeyTag()+" of "+apex+" (algorithm "+k.getAlgorithm()
					+") is published but no active key of that algorithm signs: validators may reject the zone");
			}
		}

		//  The RRsets: name (canonical order) -> type -> records
		TreeMap<String, TreeMap<Integer, List<RR>>> sets = new TreeMap<String, TreeMap<Integer, List<RR>>>(Canonical.NAME_ORDER);
		add(sets, apex, soa);
		List<Name> names = unsigned.getNames();
		List<List<RR>> rrs = unsigned.getRrs();
		for(int i=0; i < names.size() && i < rrs.size(); i++ ) {
			String n = Canonical.key(names.get(i).toString());
			if( !Canonical.isBelow(n, apex, true) || dynamic.containsKey(n) ) {
				continue;
			}
			for(RR rr : rrs.get(i)) {
				int t = rr.getType();
				if( t == DNS.SOA || t == DNS.DNSKEY || t == DNS.RRSIG || t == DNS.NSEC || t == DNS.NSEC3 ) {
					continue;
				}
				add(sets, n, rr);
			}
		}
		for(Map.Entry<String, List<? extends RR>> e : dynamic.entrySet()) {
			if( Canonical.isBelow(e.getKey(), apex, true) ) {
				sets.remove(e.getKey());
				for(RR rr : e.getValue()) {
					add(sets, e.getKey(), rr);
				}
			}
		}

		//  The DNSKEY set
		int keyTtl = Integer.MAX_VALUE;
		for(DnssecKey k : published) {
			keyTtl = Math.min(keyTtl, k.getDnskey().getTTL());
		}
		List<RR> dnskeys = new ArrayList<RR>();
		for(DnssecKey k : published) {
			Dnskey d = k.getDnskey();
			d.setName(apex);
			d.setTTL(keyTtl);
			dnskeys.add(d);
			add(sets, apex, d);
		}

		//  Delegations, and the names below them (glue: not authoritative)
		Set<String> cuts = new HashSet<String>();
		for(Map.Entry<String, TreeMap<Integer, List<RR>>> e : sets.entrySet()) {
			if( !e.getKey().equals(apex) && e.getValue().containsKey(DNS.NS) ) {
				cuts.add(e.getKey());
			}
		}
		List<String> auth = new ArrayList<String>();
		for(String n : sets.keySet()) {
			if( !isOccluded(n, apex, cuts) ) {
				auth.add(n);
			}
		}

		//  The NSEC chain, in canonical order (or the NSEC3 chain)
		int nsecTtl = Math.min(soa.getTTL(), soa.getMinimum());
		TreeMap<String, Nsec> chain = new TreeMap<String, Nsec>(Canonical.NAME_ORDER);
		List<RR> nsecs = new ArrayList<RR>();
		TreeMap<String, Nsec3> hashed = null;
		if( nsec3 != null ) {
			hashed = nsec3Chain(sets, auth, cuts, apex, soa, nsecTtl, nsec3, nsecs);
		}
		for(int i=0; nsec3 == null && i < auth.size(); i++ ) {
			String n = auth.get(i);
			String next = i+1 < auth.size() ? auth.get(i+1) : apex;
			List<Integer> types = new ArrayList<Integer>();
			for(int t : sets.get(n).keySet()) {
				if( !cuts.contains(n) || t == DNS.NS || t == DNS.DS ) {
					types.add(t);
				}
			}
			types.add(DNS.RRSIG);
			types.add(DNS.NSEC);
			Nsec nsec = new Nsec(n, soa.getDnsClass());
			nsec.setTTL(nsecTtl);
			nsec.setNext(next);
			nsec.setTypes(types);
			chain.put(n, nsec);
			nsecs.add(nsec);
		}
		for(Map.Entry<String, Nsec> e : chain.entrySet()) {
			add(sets, e.getKey(), e.getValue());
		}

		//  Sign
		long inception = now - INCEPTION_OFFSET;
		long expiration = now + validity;
		Map<String, List<Rrsig>> sigs = new HashMap<String, List<Rrsig>>();
		int count = 0;
		for(String n : auth) {
			boolean cut = cuts.contains(n);
			for(Map.Entry<Integer, List<RR>> e : sets.get(n).entrySet()) {
				int type = e.getKey();
				if( cut && type != DNS.DS && type != DNS.NSEC ) {
					continue;
				}
				List<RR> set = e.getValue();
				int ttl = Integer.MAX_VALUE;
				for(RR rr : set) {
					ttl = Math.min(ttl, rr.getTTL());
				}
				List<Rrsig> list = new ArrayList<Rrsig>();
				for(DnssecKey k : type == DNS.DNSKEY ? keySigners : zoneSigners) {
					list.add(Canonical.sign(n, set, ttl, k, inception, expiration));
					count++;
				}
				sigs.put(SignedZone.sigKey(n, type), list);
			}
		}
		if( hashed != null ) {
			for(Nsec3 r : hashed.values()) {
				List<Rrsig> list = new ArrayList<Rrsig>();
				for(DnssecKey k : zoneSigners) {
					list.add(Canonical.sign(r.getName(), java.util.Collections.singletonList(r), r.getTTL(), k, inception, expiration));
					count++;
				}
				sigs.put(SignedZone.sigKey(r.getName(), DNS.NSEC3), list);
			}
		}

		//  The zone to serve: the unsigned records plus DNSKEY and NSEC (or
		//  NSEC3PARAM: the NSEC3 records are not names of the zone, RFC 5155 7.2.9)
		Zone ret = unsigned.copyForUpdate();
		List<RR> extra = new ArrayList<RR>(dnskeys);
		extra.addAll(nsecs);
		ret.addRecords(extra);
		long next = Long.MAX_VALUE;
		for(DnssecKey k : keys) {
			next = Math.min(next, k.nextEvent(now));
		}
		long refresh = Math.min(expiration - validity/4, next);
		ret.setSigned(new SignedZone(unsigned, apex, sigs, auth, chain, hashed, nsec3, now, expiration, refresh,
				keyId(keys, now), dynamicFingerprint, count, false));
		return new Result(ret, warnings);
	}

	/**
	 * A zone signed elsewhere (its file holds DNSKEY, RRSIG and NSEC or NSEC3
	 * records): its own signatures and chain are served as they are. Every
	 * signature is checked; bad or expired ones are reported as warnings
	 * (the zone is still served, as the signer made it).
	 */
	static Result presigned(Zone loaded, long now) {
		List<String> warnings = new ArrayList<String>();
		String apex = Canonical.key(loaded.getName());
		Soa soa = loaded.getSoa();

		//  The records by name and type (SOA included)
		TreeMap<String, TreeMap<Integer, List<RR>>> sets = new TreeMap<String, TreeMap<Integer, List<RR>>>(Canonical.NAME_ORDER);
		add(sets, apex, soa);
		List<Name> names = loaded.getNames();
		List<List<RR>> rrs = loaded.getRrs();
		for(int i=0; i < names.size() && i < rrs.size(); i++ ) {
			String n = Canonical.key(names.get(i).toString());
			if( Canonical.isBelow(n, apex, true) ) {
				for(RR rr : rrs.get(i)) {
					if( rr.getType() != DNS.SOA ) {
						add(sets, n, rr);
					}
				}
			}
		}
		Set<String> cuts = new HashSet<String>();
		for(Map.Entry<String, TreeMap<Integer, List<RR>>> e : sets.entrySet()) {
			if( !e.getKey().equals(apex) && e.getValue().containsKey(DNS.NS) ) {
				cuts.add(e.getKey());
			}
		}
		List<String> auth = new ArrayList<String>();
		TreeMap<String, Nsec> chain = new TreeMap<String, Nsec>(Canonical.NAME_ORDER);
		for(Map.Entry<String, TreeMap<Integer, List<RR>>> e : sets.entrySet()) {
			if( isOccluded(e.getKey(), apex, cuts) ) {
				continue;
			}
			auth.add(e.getKey());
			List<RR> nsec = e.getValue().get(DNS.NSEC);
			if( nsec != null ) {
				chain.put(e.getKey(), (Nsec)nsec.get(0));
			}
		}

		//  NSEC3: by hash label, with the zone's parameters
		TreeMap<String, Nsec3> hashed = null;
		Nsec3Params params = null;
		if( !loaded.getPresignedNsec3().isEmpty() ) {
			hashed = new TreeMap<String, Nsec3>();
			for(Nsec3 n : loaded.getPresignedNsec3()) {
				String o = Canonical.key(n.getName());
				hashed.put(o.substring(0, o.indexOf('.')), n);
				if( params == null ) {
					params = new Nsec3Params(n.getIterations(), n.getSalt(), false);
				}
			}
			TreeMap<Integer, List<RR>> at = sets.get(apex);
			List<RR> p = at == null ? null : at.get(DNS.NSEC3PARAM);
			if( p != null ) {
				Nsec3param np = (Nsec3param)p.get(0);
				params = new Nsec3Params(np.getIterations(), np.getSalt(), false);
			}
			if( !chain.isEmpty() ) {
				warnings.add(apex+" has both NSEC and NSEC3 records; using NSEC3");
				chain.clear();
			}
		} else if( chain.isEmpty() ) {
			warnings.add(apex+" has no NSEC or NSEC3 records: names that don't exist can't be proven");
		}

		//  The signatures, each checked
		List<Dnskey> keys = new ArrayList<Dnskey>();
		TreeMap<Integer, List<RR>> apexSets = sets.get(apex);
		if( apexSets != null && apexSets.get(DNS.DNSKEY) != null ) {
			for(RR k : apexSets.get(DNS.DNSKEY)) {
				keys.add((Dnskey)k);
			}
		} else {
			warnings.add(apex+" has no DNSKEY records at the apex");
		}
		Map<String, List<Rrsig>> sigs = new HashMap<String, List<Rrsig>>();
		long expires = Long.MAX_VALUE;
		long signedAt = Long.MAX_VALUE;
		int bad = 0;
		int expired = 0;
		String firstBad = null;
		for(Rrsig s : loaded.getPresignedSigs()) {
			String owner = Canonical.key(s.getName());
			sigs.computeIfAbsent(SignedZone.sigKey(owner, s.getTypeCovered()), k -> new ArrayList<Rrsig>()).add(s);
			expires = Math.min(expires, s.getExpiration());
			signedAt = Math.min(signedAt, s.getInception());
			if( s.getExpiration() < now ) {
				expired++;
			}
			List<? extends RR> set;
			if( s.getTypeCovered() == DNS.NSEC3 && hashed != null ) {
				Nsec3 n = hashed.get(owner.substring(0, Math.max(0, owner.indexOf('.'))));
				set = n == null ? null : java.util.Collections.singletonList(n);
			} else {
				TreeMap<Integer, List<RR>> at = sets.get(owner);
				set = at == null ? null : at.get(s.getTypeCovered());
			}
			boolean ok = false;
			if( set != null ) {
				for(Dnskey k : keys) {
					if( k.getKeyTag() == s.getKeyTag() && Canonical.verify(s, owner, set, k) ) {
						ok = true;
						break;
					}
				}
			}
			if( !ok ) {
				bad++;
				if( firstBad == null ) {
					firstBad = s.getName()+" "+us.bringardner.net.dns.Utility.TYPENAMES[Math.min(s.getTypeCovered(), 255)];
				}
			}
		}
		if( bad > 0 ) {
			warnings.add(apex+": "+bad+" signatures don't verify (the first: "+firstBad+"); validators will reject those answers");
		}
		if( expired > 0 ) {
			warnings.add(apex+": "+expired+" signatures have expired; sign the zone again");
		}

		Zone ret = loaded.copyForUpdate();
		ret.setSigned(new SignedZone(loaded, apex, sigs, auth, chain, hashed, params,
				signedAt == Long.MAX_VALUE ? now : signedAt, expires == Long.MAX_VALUE ? now : expires,
				Long.MAX_VALUE, "presigned", "", loaded.getPresignedSigs().size(), true));
		return new Result(ret, warnings);
	}

	/**
	 * The NSEC3 chain (RFC 5155 7.1): a record for every name that owns
	 * records and every empty non-terminal, owned by the hash of the name,
	 * in hash order. No opt-out. Adds the NSEC3PARAM to the apex (to sets
	 * and to extra).
	 */
	private static TreeMap<String, Nsec3> nsec3Chain(TreeMap<String, TreeMap<Integer, List<RR>>> sets, List<String> auth,
			Set<String> cuts, String apex, Soa soa, int ttl, Nsec3Params p, List<RR> extra) {
		Nsec3param param = new Nsec3param(apex, soa.getDnsClass());
		param.setIterations(p.getIterations());
		param.setSalt(p.getSalt());
		//  (TTL 0, as other signers use)
		param.setTTL(0);
		add(sets, apex, param);
		extra.add(param);

		Set<String> owners = new HashSet<String>(auth);
		List<String> all = new ArrayList<String>(auth);
		for(String n : auth) {
			String a = n;
			while( !a.equals(apex) ) {
				a = a.substring(a.indexOf('.')+1);
				if( owners.add(a) ) {
					all.add(a);
				}
			}
		}
		TreeMap<String, Nsec3> hashed = new TreeMap<String, Nsec3>();
		for(String n : all) {
			String label = p.hashLabel(n);
			List<Integer> types = new ArrayList<Integer>();
			TreeMap<Integer, List<RR>> at = sets.get(n);
			if( at != null ) {
				boolean cut = cuts.contains(n);
				for(int t : at.keySet()) {
					if( !cut || t == DNS.NS || t == DNS.DS ) {
						types.add(t);
					}
				}
				//  Signatures exist at the name unless it is a delegation without DS
				if( !cut || at.containsKey(DNS.DS) ) {
					types.add(DNS.RRSIG);
				}
			}
			Nsec3 r = new Nsec3(label+"."+apex, soa.getDnsClass());
			r.setTTL(ttl);
			r.setIterations(p.getIterations());
			r.setSalt(p.getSalt());
			r.setTypes(types);
			if( hashed.put(label, r) != null ) {
				throw new IllegalStateException("NSEC3 hash collision in "+apex+" (change the salt)");
			}
		}
		Nsec3 prev = null;
		for(Map.Entry<String, Nsec3> e : hashed.entrySet()) {
			if( prev != null ) {
				prev.setNextHashed(Base32Hex.decode(e.getKey()));
			}
			prev = e.getValue();
		}
		prev.setNextHashed(Base32Hex.decode(hashed.firstKey()));
		return hashed;
	}

	private static void add(TreeMap<String, TreeMap<Integer, List<RR>>> sets, String name, RR rr) {
		sets.computeIfAbsent(Canonical.key(name), k -> new TreeMap<Integer, List<RR>>())
			.computeIfAbsent(rr.getType(), k -> new ArrayList<RR>()).add(rr);
	}

	/** Is the name below (not at) a delegation? */
	private static boolean isOccluded(String name, String apex, Set<String> cuts) {
		String n = name;
		while( true ) {
			int dot = n.indexOf('.');
			if( dot < 0 ) {
				return false;
			}
			n = n.substring(dot+1);
			if( n.equals(apex) || !Canonical.isBelow(n, apex, false) ) {
				return false;
			}
			if( cuts.contains(n) ) {
				return true;
			}
		}
	}
}
