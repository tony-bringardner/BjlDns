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

import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.TimeZone;

/**
 * The RRSIG record (RFC 4034 3): the signature over one RRset (all the
 * records of one type at one name) made with one zone key.
 */
public class Rrsig extends RR {

	private int typeCovered;
	private int algorithm;
	private int labels;
	private int origTtl;
	private int expiration;
	private int inception;
	private int keyTag;
	private String signer;
	private byte [] signature;

	public Rrsig() {
		super();
		setType(RRSIG);
		setDnsClass(IN);
		signer = "";
		signature = new byte[0];
		isBase = false;
		dirty = true;
	}

	public Rrsig(String name, int dnsClass) {
		super(name,RRSIG,dnsClass);
		signer = "";
		signature = new byte[0];
		isBase = false;
		dirty = true;
	}

	/** An RRSIG from a generic record read from the wire. */
	public Rrsig(RR rr) {
		super(rr);
		setFromRdata();
		isBase = false;
	}

	@Override
	public RR copy() {
		Rrsig ret = new Rrsig();
		super.copy(ret);
		ret.typeCovered = typeCovered;
		ret.algorithm = algorithm;
		ret.labels = labels;
		ret.origTtl = origTtl;
		ret.expiration = expiration;
		ret.inception = inception;
		ret.keyTag = keyTag;
		ret.signer = signer;
		ret.signature = signature;
		return ret;
	}

	public int getTypeCovered() { return typeCovered; }
	public int getAlgorithm() { return algorithm; }
	public int getLabels() { return labels; }
	public int getOrigTtl() { return origTtl; }
	/** Seconds since 1970 (unsigned 32 bit). */
	public long getExpiration() { return expiration & 0xffffffffL; }
	/** Seconds since 1970 (unsigned 32 bit). */
	public long getInception() { return inception & 0xffffffffL; }
	public int getKeyTag() { return keyTag; }
	public String getSigner() { return signer; }
	public byte [] getSignature() { return signature.clone(); }

	public void setTypeCovered(int t) { typeCovered = t & 0xffff; dirty = true; }
	public void setAlgorithm(int a) { algorithm = a & 0xff; dirty = true; }
	public void setLabels(int l) { labels = l & 0xff; dirty = true; }
	public void setOrigTtl(int t) { origTtl = t; dirty = true; }
	public void setExpiration(long secs) { expiration = (int)secs; dirty = true; }
	public void setInception(long secs) { inception = (int)secs; dirty = true; }
	public void setKeyTag(int t) { keyTag = t & 0xffff; dirty = true; }
	public void setSigner(String s) {
		signer = s.endsWith(".") ? s.substring(0, s.length()-1) : s;
		dirty = true;
	}
	public void setSignature(byte [] s) { signature = s.clone(); dirty = true; }

	/**
	 * The rdata without the signature, signer name in canonical form: the
	 * first part of what is signed (RFC 4034 3.1.8.1).
	 */
	public byte [] rdataWithoutSignature() {
		ByteBuffer b = new ByteBuffer();
		b.setCanonical(true);
		writeFixed(b, signer.toLowerCase(java.util.Locale.ROOT));
		return b.getByteArray();
	}

	private void writeFixed(ByteBuffer out, String signerName) {
		out.setShort(typeCovered);
		out.setByte((byte)algorithm);
		out.setByte((byte)labels);
		out.setInt(origTtl);
		out.setInt(expiration);
		out.setInt(inception);
		out.setShort(keyTag);
		//  Never compressed (RFC 4034 3.1.7)
		Srv.writeUncompressed(out, signerName);
	}

	@Override
	public void setFromRdata() {
		byte [] r = rdata;
		if( r == null || r.length < 19 ) {
			throw new DnsFormatException("Invalid RRSIG rdata");
		}
		ByteBuffer in = new ByteBuffer(r);
		typeCovered = in.nextShort();
		algorithm = in.next();
		labels = in.next();
		origTtl = in.nextInt();
		expiration = in.nextInt();
		inception = in.nextInt();
		keyTag = in.nextShort();
		StringBuilder n = new StringBuilder();
		int pos = 18;
		while( true ) {
			if( pos >= r.length ) {
				throw new DnsFormatException("Invalid RRSIG signer name");
			}
			int len = r[pos++]&0xff;
			if( len == 0 ) {
				break;
			}
			if( len > 63 || pos+len > r.length ) {
				throw new DnsFormatException("Invalid RRSIG signer name");
			}
			if( n.length() > 0 ) {
				n.append('.');
			}
			n.append(new String(r, pos, len, java.nio.charset.StandardCharsets.ISO_8859_1));
			pos += len;
		}
		signer = n.toString();
		signature = Arrays.copyOfRange(r, pos, r.length);
		dirty = false;
	}

	@Override
	public void toByteArray(ByteBuffer out) {
		super.toByteArray(out);
		writeFixed(out, out.isCanonical() ? signer.toLowerCase(java.util.Locale.ROOT) : signer);
		out.setBytes(signature);
		out.setRdLength();
	}

	/** YYYYMMDDHHmmSS in UTC (RFC 4034 3.2). */
	public static String timeString(long secs) {
		SimpleDateFormat f = new SimpleDateFormat("yyyyMMddHHmmss");
		f.setTimeZone(TimeZone.getTimeZone("UTC"));
		return f.format(new Date(secs*1000));
	}

	@Override
	public String getRdataAsString() {
		return Nsec.typeName(typeCovered)+" "+algorithm+" "+labels+" "+(origTtl & 0xffffffffL)+" "
				+timeString(getExpiration())+" "+timeString(getInception())+" "+keyTag+" "+signer+". "
				+Base64.getEncoder().encodeToString(signature);
	}

	@Override
	public String toString() {
		return super.toString()+" "+getRdataAsString();
	}
}
