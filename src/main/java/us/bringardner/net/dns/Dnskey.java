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
import java.util.Base64;

/**
 * The DNSKEY record (RFC 4034 2): a zone's public key. Flags 256 is a zone
 * signing key (ZSK), 257 a key signing key (KSK, the SEP bit set), protocol
 * is always 3, then the algorithm number and the key.
 */
public class Dnskey extends RR {

	/** Zone key flag (bit 7). */
	public static final int FLAG_ZONE = 0x100;
	/** Secure entry point flag (bit 15): a key signing key. */
	public static final int FLAG_SEP = 0x1;

	private int flags;
	private int protocol;
	private int algorithm;
	private byte [] key;

	public Dnskey() {
		super();
		setType(DNSKEY);
		setDnsClass(IN);
		protocol = 3;
		key = new byte[0];
		isBase = false;
		dirty = true;
	}

	public Dnskey(String name, int dnsClass) {
		super(name,DNSKEY,dnsClass);
		protocol = 3;
		key = new byte[0];
		isBase = false;
		dirty = true;
	}

	/** A DNSKEY from a generic record read from the wire. */
	public Dnskey(RR rr) {
		super(rr);
		setFromRdata();
		isBase = false;
	}

	@Override
	public RR copy() {
		Dnskey ret = new Dnskey();
		super.copy(ret);
		ret.flags = flags;
		ret.protocol = protocol;
		ret.algorithm = algorithm;
		ret.key = key;
		return ret;
	}

	public int getFlags() { return flags; }
	public int getProtocol() { return protocol; }
	public int getAlgorithm() { return algorithm; }
	public byte [] getKey() { return key.clone(); }

	/** @return true for a key signing key (the SEP flag is set) */
	public boolean isKsk() { return (flags & FLAG_SEP) != 0; }

	public void setFlags(int flags) { this.flags = flags & 0xffff; dirty = true; }
	public void setProtocol(int protocol) { this.protocol = protocol & 0xff; dirty = true; }
	public void setAlgorithm(int algorithm) { this.algorithm = algorithm & 0xff; dirty = true; }
	public void setKey(byte [] key) { this.key = key.clone(); dirty = true; }

	/** The rdata: flags, protocol, algorithm, key. */
	public byte [] rdataBytes() {
		byte [] ret = new byte[4+key.length];
		ret[0] = (byte)(flags >> 8);
		ret[1] = (byte)flags;
		ret[2] = (byte)protocol;
		ret[3] = (byte)algorithm;
		System.arraycopy(key, 0, ret, 4, key.length);
		return ret;
	}

	/** The key tag (RFC 4034 Appendix B) that RRSIG and DS records use to name this key. */
	public int getKeyTag() {
		return keyTag(rdataBytes());
	}

	/** RFC 4034 Appendix B (algorithm 1, RSA/MD5, is not supported and not special-cased). */
	public static int keyTag(byte [] rdata) {
		long ac = 0;
		for(int i=0; i < rdata.length; i++ ) {
			ac += (i & 1) == 0 ? (rdata[i]&0xff) << 8 : (rdata[i]&0xff);
		}
		ac += (ac >> 16) & 0xffff;
		return (int)(ac & 0xffff);
	}

	@Override
	public void setFromRdata() {
		byte [] r = rdata;
		if( r == null || r.length < 4 ) {
			throw new DnsFormatException("Invalid DNSKEY rdata");
		}
		flags = ((r[0]&0xff) << 8) | (r[1]&0xff);
		protocol = r[2]&0xff;
		algorithm = r[3]&0xff;
		key = Arrays.copyOfRange(r, 4, r.length);
		dirty = false;
	}

	@Override
	public void toByteArray(ByteBuffer out) {
		super.toByteArray(out);
		out.setBytes(rdataBytes());
		out.setRdLength();
	}

	@Override
	public String getRdataAsString() {
		return flags+" "+protocol+" "+algorithm+" "+Base64.getEncoder().encodeToString(key);
	}

	@Override
	public String toString() {
		return super.toString()+" "+getRdataAsString()+" ; key id = "+getKeyTag();
	}
}
