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

/**
 * Base32 with the extended hex alphabet (RFC 4648 7), lower case and
 * without padding, as NSEC3 owner names and next hashes use it (RFC 5155).
 */
public final class Base32Hex {

	private static final String ALPHABET = "0123456789abcdefghijklmnopqrstuv";

	private Base32Hex() {
	}

	public static String encode(byte [] data) {
		StringBuilder b = new StringBuilder((data.length*8+4)/5);
		int buffer = 0;
		int bits = 0;
		for(byte x : data) {
			buffer = (buffer << 8) | (x & 0xff);
			bits += 8;
			while( bits >= 5 ) {
				b.append(ALPHABET.charAt((buffer >> (bits-5)) & 0x1f));
				bits -= 5;
			}
		}
		if( bits > 0 ) {
			b.append(ALPHABET.charAt((buffer << (5-bits)) & 0x1f));
		}
		return b.toString();
	}

	/** @throws IllegalArgumentException for a character outside the alphabet */
	public static byte [] decode(String text) {
		String t = text.toLowerCase(java.util.Locale.ROOT);
		while( t.endsWith("=") ) {
			t = t.substring(0, t.length()-1);
		}
		java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
		int buffer = 0;
		int bits = 0;
		for(int i=0; i < t.length(); i++ ) {
			int v = ALPHABET.indexOf(t.charAt(i));
			if( v < 0 ) {
				throw new IllegalArgumentException("Invalid base32hex '"+text+"'");
			}
			buffer = (buffer << 5) | v;
			bits += 5;
			if( bits >= 8 ) {
				out.write((buffer >> (bits-8)) & 0xff);
				bits -= 8;
			}
		}
		return out.toByteArray();
	}
}
