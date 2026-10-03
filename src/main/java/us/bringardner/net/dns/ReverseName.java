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
 */
package us.bringardner.net.dns;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.UnknownHostException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reverse lookup names (RFC 1035 3.5, RFC 3596 2.5): the in-addr.arpa
 * or ip6.arpa name to query for the PTR records of an address.
 * <p>
 * Nothing here sends a DNS query; text is only accepted as an address literal.
 */
public final class ReverseName {

	private static final Pattern IPV4 = Pattern.compile("([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})");
	private static final Pattern IPV6_CHARS = Pattern.compile("[0-9A-Fa-f:.]+");

	private ReverseName() {
	}

	/**
	 * The reverse name of an address: a.b.c.d gives d.c.b.a.in-addr.arpa,
	 * an IPv6 address gives its 32 nibbles, lowest first, then ip6.arpa.
	 * No trailing dot.
	 */
	public static String of(InetAddress addr) {
		if( addr == null ) {
			throw new IllegalArgumentException("addr is null");
		}
		return fromBytes(addr.getAddress());
	}

	/**
	 * The reverse name of an address written as text ("192.0.2.1", "2001:db8::1"),
	 * or null if the text is not an IPv4 or IPv6 literal. A host name is never
	 * looked up.
	 * <p>
	 * An IPv4-mapped IPv6 literal (::ffff:a.b.c.d) gives the ip6.arpa name,
	 * as it was written as IPv6; use {@link #of(InetAddress)} or convert it
	 * first to get the in-addr.arpa name.
	 */
	public static String of(String text) {
		if( text == null ) {
			return null;
		}
		text = text.trim();
		Matcher m = IPV4.matcher(text);
		if( m.matches() ) {
			byte [] a = new byte[4];
			for(int i=0; i < 4; i++ ) {
				int b = Integer.parseInt(m.group(i+1));
				if( b > 255 ) {
					return null;
				}
				a[i] = (byte)b;
			}
			return fromBytes(a);
		}
		//  A zone id (fe80::1%en0) is not part of the address
		int pct = text.indexOf('%');
		String lit = pct >= 0 ? text.substring(0, pct) : text;
		if( lit.startsWith("[") && lit.endsWith("]") ) {
			lit = lit.substring(1, lit.length()-1);
		}
		if( lit.indexOf(':') >= 0 && IPV6_CHARS.matcher(lit).matches() ) {
			byte [] a;
			try {
				//  Only hex digits, ':' and '.' so this is parsed, never looked up
				a = InetAddress.getByName(lit).getAddress();
			} catch(UnknownHostException ex) {
				return null;
			}
			if( a.length == 4 ) {
				//  ::ffff:a.b.c.d (Java makes it an IPv4 address); keep it IPv6
				byte [] mapped = new byte[16];
				mapped[10] = (byte)0xff;
				mapped[11] = (byte)0xff;
				System.arraycopy(a, 0, mapped, 12, 4);
				a = mapped;
			}
			return fromBytes(a);
		}
		return null;
	}

	/** True if the name is under in-addr.arpa or ip6.arpa (case insensitive, trailing dot allowed). */
	public static boolean isReverseName(String name) {
		if( name == null ) {
			return false;
		}
		String n = name.toLowerCase();
		if( n.endsWith(".") ) {
			n = n.substring(0, n.length()-1);
		}
		return n.endsWith(".in-addr.arpa") || n.endsWith(".ip6.arpa");
	}

	/**
	 * The address a reverse name stands for, or null if it is not a complete
	 * in-addr.arpa (4 labels) or ip6.arpa (32 nibbles) name.
	 */
	public static InetAddress toAddress(String name) {
		if( !isReverseName(name) ) {
			return null;
		}
		String n = name.toLowerCase();
		if( n.endsWith(".") ) {
			n = n.substring(0, n.length()-1);
		}
		try {
			if( n.endsWith(".in-addr.arpa") ) {
				String [] p = n.substring(0, n.length()-".in-addr.arpa".length()).split("\\.", -1);
				if( p.length != 4 ) {
					return null;
				}
				byte [] a = new byte[4];
				for(int i=0; i < 4; i++ ) {
					if( !p[i].matches("[0-9]{1,3}") ) {
						return null;
					}
					int b = Integer.parseInt(p[i]);
					if( b > 255 ) {
						return null;
					}
					a[3-i] = (byte)b;
				}
				return InetAddress.getByAddress(a);
			}
			String [] p = n.substring(0, n.length()-".ip6.arpa".length()).split("\\.", -1);
			if( p.length != 32 ) {
				return null;
			}
			byte [] a = new byte[16];
			for(int i=0; i < 32; i++ ) {
				if( p[i].length() != 1 ) {
					return null;
				}
				int d = Character.digit(p[i].charAt(0), 16);
				if( d < 0 ) {
					return null;
				}
				int idx = 15 - i/2;
				if( i % 2 == 0 ) {
					a[idx] |= d;		//  low nibble comes first
				} else {
					a[idx] |= d << 4;
				}
			}
			//  getByAddress would turn a mapped address into an Inet4Address
			return Inet6Address.getByAddress(null, a, (NetworkInterface)null);
		} catch(UnknownHostException ex) {
			return null;
		}
	}

	private static String fromBytes(byte [] a) {
		StringBuilder sb = new StringBuilder(a.length == 4 ? 29 : 73);
		if( a.length == 4 ) {
			for(int i=3; i >= 0; i-- ) {
				sb.append(a[i] & 0xff).append('.');
			}
			return sb.append("in-addr.arpa").toString();
		}
		if( a.length != 16 ) {
			throw new IllegalArgumentException("Not an IPv4 or IPv6 address ("+a.length+" bytes)");
		}
		for(int i=15; i >= 0; i-- ) {
			sb.append(Character.forDigit(a[i] & 0xf, 16)).append('.');
			sb.append(Character.forDigit((a[i] >> 4) & 0xf, 16)).append('.');
		}
		return sb.append("ip6.arpa").toString();
	}

}
