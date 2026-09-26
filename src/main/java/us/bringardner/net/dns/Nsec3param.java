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

/**
 * The NSEC3PARAM record (RFC 5155 4): at the apex of a zone signed with
 * NSEC3, the hash parameters its NSEC3 chain uses.
 */
public class Nsec3param extends RR {

	private int hashAlgorithm;
	private int flags;
	private int iterations;
	private byte [] salt;

	public Nsec3param() {
		super();
		setType(NSEC3PARAM);
		setDnsClass(IN);
		hashAlgorithm = 1;
		salt = new byte[0];
		isBase = false;
		dirty = true;
	}

	public Nsec3param(String name, int dnsClass) {
		super(name,NSEC3PARAM,dnsClass);
		hashAlgorithm = 1;
		salt = new byte[0];
		isBase = false;
		dirty = true;
	}

	/** An NSEC3PARAM from a generic record read from the wire. */
	public Nsec3param(RR rr) {
		super(rr);
		setFromRdata();
		isBase = false;
	}

	@Override
	public RR copy() {
		Nsec3param ret = new Nsec3param();
		super.copy(ret);
		ret.hashAlgorithm = hashAlgorithm;
		ret.flags = flags;
		ret.iterations = iterations;
		ret.salt = salt;
		return ret;
	}

	public int getHashAlgorithm() { return hashAlgorithm; }
	public int getFlags() { return flags; }
	public int getIterations() { return iterations; }
	public byte [] getSalt() { return salt.clone(); }

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

	@Override
	public void setFromRdata() {
		byte [] r = rdata;
		if( r == null || r.length < 5 || r.length != 5+(r[4]&0xff) ) {
			throw new DnsFormatException("Invalid NSEC3PARAM rdata");
		}
		hashAlgorithm = r[0]&0xff;
		flags = r[1]&0xff;
		iterations = ((r[2]&0xff) << 8) | (r[3]&0xff);
		salt = Arrays.copyOfRange(r, 5, r.length);
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
		out.setRdLength();
	}

	@Override
	public String getRdataAsString() {
		return hashAlgorithm+" "+flags+" "+iterations+" "+Nsec3.saltText(salt);
	}

	@Override
	public String toString() {
		return super.toString()+" "+getRdataAsString();
	}
}
