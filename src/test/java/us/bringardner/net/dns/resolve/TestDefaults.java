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
package us.bringardner.net.dns.resolve;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.server.DnsServer;

/**
 * Defaults that were too small or wasteful, and the overload warning.
 */
public class TestDefaults {

	@Test
	public void backlogDefault() {
		if( System.getProperty("Resolver.maxBacklog") == null ) {
			assertEquals(ResolverThread.DEFAULT_MAX_BACKLOG, ResolverThread.getMaxBackLog());
			assertEquals(200, ResolverThread.getMaxBackLog(), "was 20");
		}
	}

	@Test
	public void oneTcpAcceptor() {
		if( System.getProperty(DnsServer.PROP_TCP_PROC_COUNT) == null ) {
			assertEquals(1, new DnsServer().getTcpProcCount(), "was 4");
		}
	}

	@Test
	public void backlogFullIsLoggedAtMostEveryTenSeconds() {
		ResolverThread.resetBacklogWarning();
		String first = ResolverThread.backlogFullWarning();
		assertNotNull(first);
		assertTrue(first.contains("Resolver.maxBacklog"), first);
		for(int i=0; i < 1000; i++ ) {
			assertNull(ResolverThread.backlogFullWarning(), "no message per query");
		}
	}
}
