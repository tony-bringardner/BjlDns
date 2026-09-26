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

import java.util.Collections;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * The NSEC record (RFC 4034 4): the next name in the zone (in canonical
 * order) and the types that exist at this name. A chain of them proves that
 * a name, or a type at a name, does not exist.
 */
public class Nsec extends RR {

	private String next;
	private TreeSet<Integer> types;

	public Nsec() {
		super();
		setType(NSEC);
		setDnsClass(IN);
		next = "";
		types = new TreeSet<Integer>();
		isBase = false;
		dirty = true;
	}

	public Nsec(String name, int dnsClass) {
		super(name,NSEC,dnsClass);
		next = "";
		types = new TreeSet<Integer>();
		isBase = false;
		dirty = true;
	}

	/** An NSEC from a generic record read from the wire. */
	public Nsec(RR rr) {
		super(rr);
		setFromRdata();
		isBase = false;
	}

	@Override
	public RR copy() {
		Nsec ret = new Nsec();
		super.copy(ret);
		ret.next = next;
		ret.types = types;
		return ret;
	}

	/** The next owner name (no trailing dot). */
	public String getNext() { return next; }

	public SortedSet<Integer> getTypes() { return Collections.unmodifiableSortedSet(types); }

	public boolean hasType(int type) { return types.contains(type); }

	public void setNext(String next) {
		this.next = next.endsWith(".") ? next.substring(0, next.length()-1) : next;
		dirty = true;
	}

	public void setTypes(java.util.Collection<Integer> list) {
		TreeSet<Integer> t = new TreeSet<Integer>();
		for(int x : list) {
			if( x <= 0 || x > 0xffff ) {
				throw new IllegalArgumentException("Invalid type in NSEC: "+x);
			}
			t.add(x);
		}
		types = t;
		dirty = true;
	}

	/** The type bit maps field (RFC 4034 4.1.2). */
	public static byte [] typeBitmaps(java.util.Collection<Integer> list) {
		TreeSet<Integer> t = new TreeSet<Integer>(list);
		java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
		int window = -1;
		byte [] bits = null;
		int len = 0;
		for(int type : t) {
			int w = type >> 8;
			if( w != window ) {
				if( bits != null ) {
					out.write(window);
					out.write(len);
					out.write(bits, 0, len);
				}
				window = w;
				bits = new byte[32];
				len = 0;
			}
			int b = (type & 0xff);
			bits[b/8] |= (byte)(0x80 >> (b%8));
			len = Math.max(len, b/8+1);
		}
		if( bits != null ) {
			out.write(window);
			out.write(len);
			out.write(bits, 0, len);
		}
		return out.toByteArray();
	}

	@Override
	public void setFromRdata() {
		byte [] r = rdata;
		if( r == null || r.length < 1 ) {
			throw new DnsFormatException("Invalid NSEC rdata");
		}
		//  The next name is never compressed (RFC 4034 4.1.1)
		StringBuilder n = new StringBuilder();
		int pos = 0;
		while( true ) {
			if( pos >= r.length ) {
				throw new DnsFormatException("Invalid NSEC next name");
			}
			int len = r[pos++]&0xff;
			if( len == 0 ) {
				break;
			}
			if( len > 63 || pos+len > r.length ) {
				throw new DnsFormatException("Invalid NSEC next name");
			}
			if( n.length() > 0 ) {
				n.append('.');
			}
			n.append(new String(r, pos, len, java.nio.charset.StandardCharsets.ISO_8859_1));
			pos += len;
		}
		TreeSet<Integer> t = new TreeSet<Integer>();
		while( pos < r.length ) {
			if( pos+2 > r.length ) {
				throw new DnsFormatException("Invalid NSEC type bit map");
			}
			int window = r[pos++]&0xff;
			int len = r[pos++]&0xff;
			if( len < 1 || len > 32 || pos+len > r.length ) {
				throw new DnsFormatException("Invalid NSEC type bit map");
			}
			for(int i=0; i < len; i++ ) {
				int b = r[pos+i]&0xff;
				for(int bit=0; bit < 8; bit++ ) {
					if( (b & (0x80 >> bit)) != 0 ) {
						t.add(window*256 + i*8 + bit);
					}
				}
			}
			pos += len;
		}
		next = n.toString();
		types = t;
		dirty = false;
	}

	@Override
	public void toByteArray(ByteBuffer out) {
		super.toByteArray(out);
		Srv.writeUncompressed(out, out.isCanonical() ? next.toLowerCase(java.util.Locale.ROOT) : next);
		out.setBytes(typeBitmaps(types));
		out.setRdLength();
	}

	/** Type names, or TYPEnnn (RFC 3597) for those without one. */
	static String typeName(int t) {
		if( t < TYPENAMES.length && !TYPENAMES[t].isEmpty() && !Character.isDigit(TYPENAMES[t].charAt(0)) ) {
			return TYPENAMES[t];
		}
		switch(t) {
		case CAA: return "CAA";
		default: return "TYPE"+t;
		}
	}

	@Override
	public String getRdataAsString() {
		StringBuilder b = new StringBuilder(next).append('.');
		for(int t : types) {
			b.append(' ').append(typeName(t));
		}
		return b.toString();
	}

	@Override
	public String toString() {
		return super.toString()+" "+getRdataAsString();
	}
}
