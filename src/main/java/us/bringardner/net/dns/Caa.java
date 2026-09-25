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

import java.nio.charset.StandardCharsets;

/**
 * The DNS CAA resource record (RFC 8659): which certificate authorities may
 * issue certificates for a domain. Flags, tag (e.g. issue, issuewild, iodef)
 * and value.
 */
public class Caa extends RR {

	private int flags;
	private String tag = "";
	private byte [] value = new byte[0];

	public Caa() {
		super();
		setType(CAA);
		setDnsClass(IN);
		isBase = false;
		dirty = true;
	}

	public Caa(String name) {
		this(name, IN);
	}

	public Caa(String name, int dnsClass) {
		super(name,CAA,dnsClass);
		isBase = false;
		dirty = true;
	}

	/** A CAA record from a generic record read from the wire. */
	public Caa(RR rr) {
		super(rr);
		//  Again: the field initializers ran after super() had parsed the rdata
		setFromRdata();
		isBase = false;
	}

	@Override
	public RR copy() {
		Caa ret = new Caa();
		super.copy(ret);
		ret.flags = flags;
		ret.tag = tag;
		ret.value = value;
		return ret;
	}

	public int getFlags() { return flags; }
	public String getTag() { return tag; }
	public String getValue() { return new String(value, StandardCharsets.UTF_8); }

	/** @return true if the issuer-critical flag (128) is set */
	public boolean isCritical() { return (flags & 0x80) != 0; }

	public void setFlags(int flags) {
		if( flags < 0 || flags > 255 ) {
			throw new IllegalArgumentException("CAA flags must be 0-255: "+flags);
		}
		this.flags = flags;
		dirty = true;
	}

	/** The tag: 1-15 ASCII letters and digits (RFC 8659 4.1). */
	public void setTag(String tag) {
		if( tag == null || !tag.matches("[A-Za-z0-9]{1,15}") ) {
			throw new IllegalArgumentException("Invalid CAA tag: '"+tag+"'");
		}
		this.tag = tag;
		dirty = true;
	}

	public void setValue(String value) {
		this.value = (value == null ? "" : value).getBytes(StandardCharsets.UTF_8);
		dirty = true;
	}

	@Override
	public void setFromRdata() {
		byte [] r = rdata;
		if( r == null || r.length < 2 || 2 + (r[1]&0xff) > r.length ) {
			throw new DnsFormatException("Invalid CAA rdata");
		}
		flags = r[0]&0xff;
		int len = r[1]&0xff;
		tag = new String(r, 2, len, StandardCharsets.US_ASCII);
		value = java.util.Arrays.copyOfRange(r, 2+len, r.length);
		dirty = false;
	}

	@Override
	public void toByteArray(ByteBuffer out) {
		super.toByteArray(out);
		byte [] t = tag.getBytes(StandardCharsets.US_ASCII);
		out.setByte((byte)flags);
		out.setByte((byte)t.length);
		out.setBytes(t);
		out.setBytes(value);
		out.setRdLength();
	}

	@Override
	public String getRdataAsString() {
		return flags+" "+tag+" \""+getValue().replace("\\","\\\\").replace("\"","\\\"")+"\"";
	}

	@Override
	public String toString() {
		return super.toString()+" flags="+flags+" tag="+tag+" value="+getValue();
	}
}
