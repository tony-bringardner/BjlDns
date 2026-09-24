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
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

/**
 * Offline tests for A.setAddress / getAddressString.
 */
public class TestAAddress {

	private static String roundTrip(String ip) {
		A a = new A("host.example.com");
		a.setAddress(ip);
		return a.getAddressString();
	}

	@Test
	public void acceptsZeroOctets() {
		assertEquals("10.0.0.1", roundTrip("10.0.0.1"));
		assertEquals("192.0.2.10", roundTrip("192.0.2.10"));
		assertEquals("0.0.0.0", roundTrip("0.0.0.0"));
	}

	@Test
	public void acceptsFullRange() {
		assertEquals("255.255.255.255", roundTrip("255.255.255.255"));
		assertEquals("127.0.0.1", roundTrip(" 127.0.0.1 "));
	}

	@Test
	public void wireRoundTrip() {
		A a = new A("host.example.com");
		a.setAddress("10.0.200.0");
		a.setTTL(60);
		Message m = new Message();
		m.setQuestion("host.example.com", DNS.A, DNS.IN);
		m.addAnswer(a);
		Message back = new Message(new ByteBuffer(m.toByteArray()));
		assertEquals("10.0.200.0", ((A)back.getAnswer().get(0)).getAddressString());
	}

	@Test
	public void rejectsBadAddresses() {
		String [] bad = {
				"256.1.1.1", "1.2.3.-1", "1.2.3", "1.2.3.4.5", "1.2.3.4.", ".1.2.3",
				"1..2.3", "a.b.c.d", "1.2.3.4x", "", " ", "1.2.3.0004", "+1.2.3.4"
		};
		for(String ip : bad) {
			assertThrows(IllegalArgumentException.class, () -> roundTrip(ip), ip);
		}
		assertThrows(IllegalArgumentException.class, () -> roundTrip(null));
	}
}
