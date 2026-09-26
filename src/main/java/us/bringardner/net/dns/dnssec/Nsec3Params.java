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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import us.bringardner.net.dns.Base32Hex;
import us.bringardner.net.dns.Nsec3;

/**
 * The NSEC3 hash parameters of a zone (RFC 5155): SHA-1 (the only hash
 * defined), iterations and salt. RFC 9276 recommends 0 extra iterations
 * and no salt, the defaults here; validators may treat zones with many
 * iterations as unsigned, so more than 100 are refused.
 */
public final class Nsec3Params {

	/** Hash algorithm 1: SHA-1. */
	public static final int SHA1 = 1;
	/** Most extra iterations accepted (RFC 9276 3.2). */
	public static final int MAX_ITERATIONS = 100;
	/** Iterations 0, no salt (RFC 9276). */
	public static final Nsec3Params DEFAULT = new Nsec3Params(0, new byte[0]);

	private final int iterations;
	private final byte [] salt;

	public Nsec3Params(int iterations, byte [] salt) {
		this(iterations, salt, true);
	}

	/**
	 * @param strict limit iterations to MAX_ITERATIONS (false for the
	 *        parameters of a zone signed elsewhere, which we only serve)
	 */
	public Nsec3Params(int iterations, byte [] salt, boolean strict) {
		if( iterations < 0 || iterations > (strict ? MAX_ITERATIONS : 0xffff) ) {
			throw new IllegalArgumentException("NSEC3 iterations must be 0-"+MAX_ITERATIONS+" (RFC 9276 recommends 0): "+iterations);
		}
		if( salt.length > 255 ) {
			throw new IllegalArgumentException("NSEC3 salt longer than 255 bytes");
		}
		this.iterations = iterations;
		this.salt = salt.clone();
	}

	/**
	 * @param salt hex, or "-" / empty for none
	 */
	public static Nsec3Params parse(int iterations, String salt) {
		String s = salt == null ? "" : salt.trim();
		if( s.equals("-") ) {
			s = "";
		}
		if( (s.length() & 1) != 0 || !s.matches("[0-9A-Fa-f]*") ) {
			throw new IllegalArgumentException("NSEC3 salt must be hex or '-': '"+salt+"'");
		}
		byte [] b = new byte[s.length()/2];
		for(int i=0; i < b.length; i++ ) {
			b[i] = (byte)Integer.parseInt(s.substring(2*i, 2*i+2), 16);
		}
		return new Nsec3Params(iterations, b);
	}

	public int getIterations() {
		return iterations;
	}

	public byte [] getSalt() {
		return salt.clone();
	}

	/** The hash of a name: IH(salt, name, iterations) of RFC 5155 5. */
	public byte [] hash(String name) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-1");
			md.update(Canonical.nameWire(name));
			md.update(salt);
			byte [] h = md.digest();
			for(int i=0; i < iterations; i++ ) {
				md.update(h);
				md.update(salt);
				h = md.digest();
			}
			return h;
		} catch(NoSuchAlgorithmException ex) {
			throw new IllegalStateException(ex);
		}
	}

	/** The hash as the first label of an NSEC3 owner (lower case base32hex). */
	public String hashLabel(String name) {
		return Base32Hex.encode(hash(name));
	}

	/** Text identifying the parameters: "1 0 iterations salt". */
	@Override
	public String toString() {
		return SHA1+" 0 "+iterations+" "+Nsec3.saltText(salt);
	}

	@Override
	public boolean equals(Object o) {
		return o instanceof Nsec3Params && o.toString().equals(toString());
	}

	@Override
	public int hashCode() {
		return toString().hashCode();
	}
}
