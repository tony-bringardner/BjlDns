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

/**
 * A list of addresses and networks (CIDR), e.g.
 * "192.0.2.10, 10.0.0.0/8, 2001:db8::/32". Used for the zone transfer
 * allow-list. Only address literals are accepted (never a host name lookup).
 *
 * @deprecated moved to bjl_core: use {@link us.bringardner.core.util.AddressMatcher}, which this
 *  now delegates to. Kept so code that uses this class still compiles; it will be removed.
 */
@Deprecated
public final class AddressMatcher {

	/** Matches nothing. */
	public static final AddressMatcher NONE = new AddressMatcher(us.bringardner.core.util.AddressMatcher.NONE);

	private final us.bringardner.core.util.AddressMatcher delegate;

	private AddressMatcher(us.bringardner.core.util.AddressMatcher delegate) {
		this.delegate = delegate;
	}

	/**
	 * @param list comma or space separated addresses / networks; null or empty matches nothing
	 * @throws IllegalArgumentException for an entry that is not an address or network
	 */
	public static AddressMatcher parse(String list) {
		us.bringardner.core.util.AddressMatcher m = us.bringardner.core.util.AddressMatcher.parse(list);
		return m.isEmpty() ? NONE : new AddressMatcher(m);
	}

	/** @return true if the address is in one of the networks */
	public boolean matches(InetAddress a) {
		return delegate.matches(a);
	}

	public boolean isEmpty() {
		return delegate.isEmpty();
	}

	/** @return the bjl_core matcher this delegates to */
	public us.bringardner.core.util.AddressMatcher toCoreMatcher() {
		return delegate;
	}

	@Override
	public String toString() {
		return delegate.toString();
	}
}
