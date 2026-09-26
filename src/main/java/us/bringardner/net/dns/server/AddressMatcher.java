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
package us.bringardner.net.dns.server;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A list of addresses and networks (CIDR), e.g.
 * "192.0.2.10, 10.0.0.0/8, 2001:db8::/32". Used for the zone transfer
 * allow-list. Only address literals are accepted (never a host name lookup).
 */
public final class AddressMatcher {

	/** Matches nothing. */
	public static final AddressMatcher NONE = new AddressMatcher(Collections.<byte[]>emptyList(), Collections.<Integer>emptyList(), "");

	private final List<byte[]> networks;
	private final List<Integer> prefixes;
	private final String text;

	private AddressMatcher(List<byte[]> networks, List<Integer> prefixes, String text) {
		this.networks = networks;
		this.prefixes = prefixes;
		this.text = text;
	}

	/**
	 * @param list comma or space separated addresses / networks; null or empty matches nothing
	 * @throws IllegalArgumentException for an entry that is not an address or network
	 */
	public static AddressMatcher parse(String list) {
		if( list == null || list.trim().isEmpty() ) {
			return NONE;
		}
		List<byte[]> nets = new ArrayList<byte[]>();
		List<Integer> prefixes = new ArrayList<Integer>();
		for(String item : list.trim().split("[,\\s]+")) {
			if( item.isEmpty() ) {
				continue;
			}
			String addr = item;
			int prefix = -1;
			int slash = item.indexOf('/');
			if( slash >= 0 ) {
				addr = item.substring(0, slash);
				String p = item.substring(slash+1);
				if( !p.matches("[0-9]{1,3}") ) {
					throw new IllegalArgumentException("Invalid prefix length in '"+item+"'");
				}
				prefix = Integer.parseInt(p);
			}
			byte [] b = literal(addr, item);
			if( prefix < 0 ) {
				prefix = b.length*8;
			}
			if( prefix > b.length*8 ) {
				throw new IllegalArgumentException("Prefix too long in '"+item+"'");
			}
			nets.add(b);
			prefixes.add(prefix);
		}
		return new AddressMatcher(Collections.unmodifiableList(nets), Collections.unmodifiableList(prefixes), list.trim());
	}

	private static byte [] literal(String addr, String item) {
		if( !addr.matches("[0-9A-Fa-f:.]+") || !(addr.indexOf(':') >= 0 || addr.matches("[0-9]{1,3}(\\.[0-9]{1,3}){3}")) ) {
			throw new IllegalArgumentException("Not an IP address: '"+item+"'");
		}
		try {
			return InetAddress.getByName(addr).getAddress();
		} catch(UnknownHostException e) {
			throw new IllegalArgumentException("Not an IP address: '"+item+"'");
		}
	}

	/** @return true if the address is in one of the networks */
	public boolean matches(InetAddress a) {
		if( a == null ) {
			return false;
		}
		byte [] b = a.getAddress();
		for(int i=0; i < networks.size(); i++ ) {
			byte [] n = networks.get(i);
			if( n.length == b.length && samePrefix(n, b, prefixes.get(i)) ) {
				return true;
			}
		}
		return false;
	}

	private static boolean samePrefix(byte [] a, byte [] b, int bits) {
		int full = bits / 8;
		for(int i=0; i < full; i++ ) {
			if( a[i] != b[i] ) {
				return false;
			}
		}
		int rest = bits % 8;
		if( rest == 0 ) {
			return true;
		}
		int mask = (0xff << (8-rest)) & 0xff;
		return (a[full] & mask) == (b[full] & mask);
	}

	public boolean isEmpty() {
		return networks.isEmpty();
	}

	@Override
	public String toString() {
		return text;
	}
}
