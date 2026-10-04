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
import us.bringardner.core.util.Hex;

/**
 * The DS record (RFC 4034 5): in the parent zone, at a delegation, the digest
 * of the child zone's key signing key. It is what links the child's
 * signatures to the parent's.
 */
public class Ds extends RR {

	/** Digest type 2: SHA-256 (RFC 4509). */
	public static final int SHA256 = 2;
	/** Digest type 4: SHA-384 (RFC 6605). */
	public static final int SHA384 = 4;

	private int keyTag;
	private int algorithm;
	private int digestType;
	private byte [] digest;

	public Ds() {
		super();
		setType(DS);
		setDnsClass(IN);
		digest = new byte[0];
		isBase = false;
		dirty = true;
	}

	public Ds(String name, int dnsClass) {
		super(name,DS,dnsClass);
		digest = new byte[0];
		isBase = false;
		dirty = true;
	}

	/** A DS from a generic record read from the wire. */
	public Ds(RR rr) {
		super(rr);
		setFromRdata();
		isBase = false;
	}

	@Override
	public RR copy() {
		Ds ret = new Ds();
		super.copy(ret);
		ret.keyTag = keyTag;
		ret.algorithm = algorithm;
		ret.digestType = digestType;
		ret.digest = digest;
		return ret;
	}

	public int getKeyTag() { return keyTag; }
	public int getAlgorithm() { return algorithm; }
	public int getDigestType() { return digestType; }
	public byte [] getDigest() { return digest.clone(); }

	public void setKeyTag(int keyTag) { this.keyTag = keyTag & 0xffff; dirty = true; }
	public void setAlgorithm(int algorithm) { this.algorithm = algorithm & 0xff; dirty = true; }
	public void setDigestType(int digestType) { this.digestType = digestType & 0xff; dirty = true; }
	public void setDigest(byte [] digest) { this.digest = digest.clone(); dirty = true; }

	/** The digest from hex text (white space allowed, as zone files split long digests). */
	public void setDigest(String hex) {
		String h = hex.replaceAll("\\s", "");
		if( h.isEmpty() || (h.length() & 1) != 0 || !h.matches("[0-9A-Fa-f]+") ) {
			throw new IllegalArgumentException("Invalid DS digest '"+hex+"'");
		}
		byte [] d = new byte[h.length()/2];
		for(int i=0; i < d.length; i++ ) {
			d[i] = (byte)Integer.parseInt(h.substring(2*i, 2*i+2), 16);
		}
		setDigest(d);
	}

	public String getDigestHex() {
		return Hex.encodeUpper(digest);
	}

	@Override
	public void setFromRdata() {
		byte [] r = rdata;
		if( r == null || r.length < 5 ) {
			throw new DnsFormatException("Invalid DS rdata");
		}
		keyTag = ((r[0]&0xff) << 8) | (r[1]&0xff);
		algorithm = r[2]&0xff;
		digestType = r[3]&0xff;
		digest = Arrays.copyOfRange(r, 4, r.length);
		dirty = false;
	}

	@Override
	public void toByteArray(ByteBuffer out) {
		super.toByteArray(out);
		out.setShort(keyTag);
		out.setByte((byte)algorithm);
		out.setByte((byte)digestType);
		out.setBytes(digest);
		out.setRdLength();
	}

	@Override
	public String getRdataAsString() {
		return keyTag+" "+algorithm+" "+digestType+" "+getDigestHex();
	}

	@Override
	public String toString() {
		return super.toString()+" "+getRdataAsString();
	}
}
