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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.Inet6Address;
import java.net.InetAddress;

import org.junit.jupiter.api.Test;

public class TestReverseName {

	//  RFC 3596 2.5 example
	private static final String V6 = "4321:0:1:2:3:4:567:89ab";
	private static final String V6_REV = "b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.ip6.arpa";

	@Test
	public void ipv4Text() {
		assertEquals("1.2.0.192.in-addr.arpa", ReverseName.of("192.0.2.1"));
		assertEquals("1.2.0.192.in-addr.arpa", ReverseName.of(" 192.0.2.1 "));
		assertEquals("0.0.0.0.in-addr.arpa", ReverseName.of("0.0.0.0"));
	}

	@Test
	public void ipv4Address() throws Exception {
		assertEquals("255.2.0.192.in-addr.arpa", ReverseName.of(InetAddress.getByName("192.0.2.255")));
	}

	@Test
	public void ipv6() throws Exception {
		assertEquals(V6_REV, ReverseName.of(V6));
		assertEquals(V6_REV, ReverseName.of("[" + V6 + "]"));
		assertEquals(V6_REV, ReverseName.of(V6.toUpperCase()));
		assertEquals(V6_REV, ReverseName.of(InetAddress.getByName(V6)));
		assertEquals("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa", ReverseName.of("fe80::1%en0"));
	}

	@Test
	public void mappedTextStaysIpv6() {
		String r = ReverseName.of("::ffff:192.0.2.1");
		assertEquals("1.0.2.0.0.0.0.c.f.f.f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", r);
	}

	@Test
	public void notAnAddress() {
		assertNull(ReverseName.of((String)null));
		assertNull(ReverseName.of(""));
		assertNull(ReverseName.of("mail.example.com"));
		assertNull(ReverseName.of("256.1.1.1"));
		assertNull(ReverseName.of("1.2.3"));
		assertNull(ReverseName.of("1.2.3.4.5"));
		assertNull(ReverseName.of("12:zz::1"));
		assertNull(ReverseName.of("1::2::3"));
	}

	@Test
	public void isReverseName() {
		assertTrue(ReverseName.isReverseName("1.2.0.192.in-addr.arpa"));
		assertTrue(ReverseName.isReverseName("1.2.0.192.IN-ADDR.ARPA."));
		assertTrue(ReverseName.isReverseName(V6_REV));
		assertFalse(ReverseName.isReverseName("in-addr.arpa"));
		assertFalse(ReverseName.isReverseName("example.com"));
		assertFalse(ReverseName.isReverseName(null));
	}

	@Test
	public void toAddressRoundTrip() throws Exception {
		assertEquals(InetAddress.getByName("192.0.2.1"), ReverseName.toAddress("1.2.0.192.in-addr.arpa."));
		assertEquals(InetAddress.getByName(V6), ReverseName.toAddress(V6_REV.toUpperCase()));
		InetAddress mapped = ReverseName.toAddress(ReverseName.of("::ffff:192.0.2.1"));
		assertTrue(mapped instanceof Inet6Address);
	}

	@Test
	public void toAddressPartial() {
		assertNull(ReverseName.toAddress("2.0.192.in-addr.arpa"));
		assertNull(ReverseName.toAddress("300.2.0.192.in-addr.arpa"));
		assertNull(ReverseName.toAddress("x.2.0.192.in-addr.arpa"));
		assertNull(ReverseName.toAddress("0.1.ip6.arpa"));
		assertNull(ReverseName.toAddress("example.com"));
	}
}
