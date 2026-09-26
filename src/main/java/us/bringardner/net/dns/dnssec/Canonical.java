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
package us.bringardner.net.dns.dnssec;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

import us.bringardner.net.dns.ByteBuffer;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Dnskey;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.Rrsig;

/**
 * DNSSEC canonical forms (RFC 4034 6): name order, record wire form, and the
 * data an RRSIG signs.
 */
public final class Canonical {

	private Canonical() {
	}

	/** A name without the trailing dot, lower case. */
	public static String key(String name) {
		String n = name.endsWith(".") ? name.substring(0, name.length()-1) : name;
		return n.toLowerCase(Locale.ROOT);
	}

	private static String [] labels(String name) {
		String n = key(name);
		return n.isEmpty() ? new String[0] : n.split("\\.", -1);
	}

	/**
	 * Canonical DNS name order (RFC 4034 6.1): compare the labels from the
	 * right, each as lower case octets; a name sorts before its descendants.
	 */
	public static int compareNames(String a, String b) {
		String [] x = labels(a);
		String [] y = labels(b);
		int i = x.length-1;
		int j = y.length-1;
		while( i >= 0 && j >= 0 ) {
			int c = compareLabel(x[i], y[j]);
			if( c != 0 ) {
				return c;
			}
			i--;
			j--;
		}
		return Integer.compare(x.length, y.length);
	}

	private static int compareLabel(String a, String b) {
		byte [] x = a.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
		byte [] y = b.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
		int n = Math.min(x.length, y.length);
		for(int i=0; i < n; i++ ) {
			int c = Integer.compare(x[i]&0xff, y[i]&0xff);
			if( c != 0 ) {
				return c;
			}
		}
		return Integer.compare(x.length, y.length);
	}

	/**
	 * A key whose natural String order is canonical name order: the lower
	 * case labels from the right, each followed by a zero char (which sorts
	 * before any label octet, so a shorter label and an ancestor come first).
	 * Comparing keys is much cheaper than {@link #compareNames}.
	 */
	public static String sortKey(String name) {
		String [] l = labels(name);
		StringBuilder b = new StringBuilder(name.length()+2);
		for(int i=l.length-1; i >= 0; i-- ) {
			b.append(l[i]).append('\0');
		}
		return b.toString();
	}

	/** Canonical name order as a Comparator. */
	public static final Comparator<String> NAME_ORDER = Canonical::compareNames;

	/** @return true if name is ancestor or a descendant of it (or equal, when orEqual) */
	public static boolean isBelow(String name, String ancestor, boolean orEqual) {
		String n = key(name);
		String a = key(ancestor);
		if( n.equals(a) ) {
			return orEqual;
		}
		return a.isEmpty() || n.endsWith("."+a);
	}

	/** Labels of the owner for the RRSIG labels field: the root and a leading '*' not counted. */
	public static int labelCount(String owner) {
		String [] l = labels(owner);
		int n = l.length;
		if( n > 0 && l[0].equals("*") ) {
			n--;
		}
		return n;
	}

	/** The name in wire form: lower case, uncompressed. */
	public static byte [] nameWire(String name) {
		ByteBuffer b = new ByteBuffer();
		b.setCanonical(true);
		b.setName(key(name));
		return b.getByteArray();
	}

	/**
	 * A record's rdata in canonical form: names uncompressed and (for the
	 * types RFC 4034 6.2 lists) lower case.
	 */
	public static byte [] rdata(RR rr) {
		ByteBuffer b = new ByteBuffer();
		b.setCanonical(true);
		rr.toByteArray(b);
		byte [] all = b.getByteArray();
		//  owner name, then type(2) class(2) ttl(4) rdlength(2)
		int pos = 0;
		while( (all[pos]&0xff) != 0 ) {
			pos += (all[pos]&0xff)+1;
		}
		pos += 1+10;
		byte [] ret = new byte[all.length-pos];
		System.arraycopy(all, pos, ret, 0, ret.length);
		return ret;
	}

	/**
	 * The data an RRSIG signs (RFC 4034 3.1.8.1): the RRSIG rdata without the
	 * signature, then every record of the set in canonical form and order,
	 * each with the original TTL; duplicate records count once.
	 *
	 * @param owner the owner name as signed (for a wildcard, the '*' name)
	 */
	public static byte [] signedData(Rrsig sig, String owner, List<? extends RR> rrset) {
		List<byte []> datas = new ArrayList<byte []>();
		for(RR rr : rrset) {
			byte [] d = rdata(rr);
			boolean dup = false;
			for(byte [] o : datas) {
				if( java.util.Arrays.equals(o, d) ) {
					dup = true;
					break;
				}
			}
			if( !dup ) {
				datas.add(d);
			}
		}
		datas.sort(Canonical::compareBytes);
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		byte [] fixed = sig.rdataWithoutSignature();
		out.write(fixed, 0, fixed.length);
		byte [] ownerWire = nameWire(owner);
		int cls = rrset.isEmpty() ? DNS.IN : rrset.get(0).getDnsClass();
		for(byte [] d : datas) {
			out.write(ownerWire, 0, ownerWire.length);
			writeShort(out, sig.getTypeCovered());
			writeShort(out, cls);
			writeInt(out, sig.getOrigTtl());
			writeShort(out, d.length);
			out.write(d, 0, d.length);
		}
		return out.toByteArray();
	}

	/** Unsigned lexicographic byte order (RFC 4034 6.3). */
	public static int compareBytes(byte [] a, byte [] b) {
		int n = Math.min(a.length, b.length);
		for(int i=0; i < n; i++ ) {
			int c = Integer.compare(a[i]&0xff, b[i]&0xff);
			if( c != 0 ) {
				return c;
			}
		}
		return Integer.compare(a.length, b.length);
	}

	private static void writeShort(ByteArrayOutputStream out, int v) {
		out.write((v >> 8) & 0xff);
		out.write(v & 0xff);
	}

	private static void writeInt(ByteArrayOutputStream out, int v) {
		writeShort(out, v >>> 16);
		writeShort(out, v & 0xffff);
	}

	/**
	 * Sign an RRset.
	 *
	 * @param owner the RRset's owner (as in the zone; a wildcard keeps its '*')
	 * @param rrset records of one type at owner
	 * @param ttl the original TTL to sign
	 * @param inception seconds since 1970
	 * @param expiration seconds since 1970
	 */
	public static Rrsig sign(String owner, List<? extends RR> rrset, int ttl, DnssecKey key, long inception, long expiration) {
		Rrsig sig = new Rrsig(key(owner), rrset.get(0).getDnsClass());
		sig.setTTL(ttl);
		sig.setTypeCovered(rrset.get(0).getType());
		sig.setAlgorithm(key.getAlgorithm());
		sig.setLabels(labelCount(owner));
		sig.setOrigTtl(ttl);
		sig.setInception(inception);
		sig.setExpiration(expiration);
		sig.setKeyTag(key.getKeyTag());
		sig.setSigner(key.getZone());
		sig.setSignature(key.sign(signedData(sig, owner, rrset)));
		return sig;
	}

	/**
	 * Check a signature over an RRset with a key (the times are not checked).
	 *
	 * @param owner the name that was signed: for a wildcard answer, the '*' name
	 */
	public static boolean verify(Rrsig sig, String owner, List<? extends RR> rrset, Dnskey key) {
		if( key.getAlgorithm() != sig.getAlgorithm() || key.getKeyTag() != sig.getKeyTag() ) {
			return false;
		}
		return Algorithm.of(key.getAlgorithm()).verify(key.getKey(), signedData(sig, owner, rrset), sig.getSignature());
	}
}
