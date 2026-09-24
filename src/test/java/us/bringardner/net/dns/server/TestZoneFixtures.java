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
package us.bringardner.net.dns.server;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;

import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.DNS;

/** The zone files used by TestDns must load. */
public class TestZoneFixtures {

	@Test
	public void fixtureZonesLoad() throws Exception {
		for(String z : new String[] {"foo.com","bar.com"}) {
			Zone zone = new Zone(new File("src/test/java/resources/TestFiles/zones/"+z+".txt"));
			assertNotNull(zone.getSoa(), z+" SOA");
			assertNotNull(zone.getMatchingRR("ns1."+z, DNS.A), z+" ns1 A record");
		}
	}
}
