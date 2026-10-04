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
package us.bringardner.net.dns;

import java.util.Arrays;
import java.util.Collections;
import java.util.SortedSet;
import java.util.TreeSet;
import us.bringardner.core.util.Hex;

/**
 * The NSEC3 record (RFC 5155 3): like NSEC, but the chain is made of hashed
 * names, so it can't be walked to list the zone. The owner is the base32hex
 * hash of a name plus the zone; the record holds the hash parameters, the
 * next hash in the chain and the types at the original name.
 */
public class Nsec3 extends RR {

	/** Opt-out flag (RFC 5155 3.1.2). */
	public static final int FLAG_OPT_OUT = 0x01;

	private int hashAlgorithm;
	private int flags;
	private int iterations;
	private byte [] salt;
	private byte [] nextHashed;
	private TreeSet<Integer> types;

	public Nsec3() {
		super();
		setType(NSEC3);
		setDnsClass(IN);
		init();
	}

	public Nsec3(String name, int dnsClass) {
		super(name,NSEC3,dnsClass);
		init();
	}

	private void init() {
		hashAlgorithm = 1;
		salt = new byte[0];
		nextHashed = new byte[0];
		types = new TreeSet<Integer>();
		isBase = false;
		dirty = true;
	}

	/** An NSEC3 from a generic record read from the wire. */
	public Nsec3(RR rr) {
		super(rr);
		setFromRdata();
		isBase = false;
	}

	@Override
	public RR copy() {
		Nsec3 ret = new Nsec3();
		super.copy(ret);
		ret.hashAlgorithm = hashAlgorithm;
		ret.flags = flags;
		ret.iterations = iterations;
		ret.salt = salt;
		ret.nextHashed = nextHashed;
		ret.types = types;
		return ret;
	}

	public int getHashAlgorithm() { return hashAlgorithm; }
	public int getFlags() { return flags; }
	public int getIterations() { return iterations; }
	public byte [] getSalt() { return salt.clone(); }
	public byte [] getNextHashed() { return nextHashed.clone(); }
	public SortedSet<Integer> getTypes() { return Collections.unmodifiableSortedSet(types); }
	public boolean hasType(int type) { return types.contains(type); }

	public void setHashAlgorithm(int a) { hashAlgorithm = a & 0xff; dirty = true; }
	public void setFlags(int f) { flags = f & 0xff; dirty = true; }
	public void setIterations(int i) { iterations = i & 0xffff; dirty = true; }
	public void setSalt(byte [] s) {
		if( s.length > 255 ) {
			throw new IllegalArgumentException("NSEC3 salt longer than 255 bytes");
		}
		salt = s.clone();
		dirty = true;
	}
	public void setNextHashed(byte [] h) {
		if( h.length < 1 || h.length > 255 ) {
			throw new IllegalArgumentException("NSEC3 next hash must be 1-255 bytes");
		}
		nextHashed = h.clone();
		dirty = true;
	}
	public void setTypes(java.util.Collection<Integer> list) {
		TreeSet<Integer> t = new TreeSet<Integer>();
		for(int x : list) {
			if( x <= 0 || x > 0xffff ) {
				throw new IllegalArgumentException("Invalid type in NSEC3: "+x);
			}
			t.add(x);
		}
		types = t;
		dirty = true;
	}

	@Override
	public void setFromRdata() {
		byte [] r = rdata;
		try {
			int pos = 0;
			hashAlgorithm = r[pos++]&0xff;
			flags = r[pos++]&0xff;
			iterations = ((r[pos]&0xff) << 8) | (r[pos+1]&0xff);
			pos += 2;
			int sl = r[pos++]&0xff;
			salt = Arrays.copyOfRange(r, pos, pos+sl);
			pos += sl;
			int hl = r[pos++]&0xff;
			if( hl < 1 || pos+hl > r.length ) {
				throw new DnsFormatException("Invalid NSEC3 hash length");
			}
			nextHashed = Arrays.copyOfRange(r, pos, pos+hl);
			pos += hl;
			types = Nsec.parseBitmaps(r, pos);
		} catch(ArrayIndexOutOfBoundsException | NullPointerException ex) {
			throw new DnsFormatException("Invalid NSEC3 rdata");
		}
		if( salt.length != (r[4]&0xff) ) {
			throw new DnsFormatException("Invalid NSEC3 salt");
		}
		dirty = false;
	}

	@Override
	public void toByteArray(ByteBuffer out) {
		super.toByteArray(out);
		out.setByte((byte)hashAlgorithm);
		out.setByte((byte)flags);
		out.setShort(iterations);
		out.setByte((byte)salt.length);
		out.setBytes(salt);
		out.setByte((byte)nextHashed.length);
		out.setBytes(nextHashed);
		out.setBytes(Nsec.typeBitmaps(types));
		out.setRdLength();
	}

	/** Salt as zone file text: hex, or "-" for none. */
	public static String saltText(byte [] salt) {
		if( salt.length == 0 ) {
			return "-";
		}
		return Hex.encodeUpper(salt);
	}

	@Override
	public String getRdataAsString() {
		StringBuilder b = new StringBuilder();
		b.append(hashAlgorithm).append(' ').append(flags).append(' ').append(iterations).append(' ')
			.append(saltText(salt)).append(' ').append(Base32Hex.encode(nextHashed).toUpperCase());
		for(int t : types) {
			b.append(' ').append(Nsec.typeName(t));
		}
		return b.toString();
	}

	@Override
	public String toString() {
		return super.toString()+" "+getRdataAsString();
	}
}
