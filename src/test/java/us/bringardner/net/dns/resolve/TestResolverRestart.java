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
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * initResolver() called again (every DnsServer that starts calls it) must not
 * leave the earlier resolver threads running where shutDown() can't reach them.
 */
public class TestResolverRestart {

	private static int liveResolverThreads() {
		int n = 0;
		for(Thread t : Thread.getAllStackTraces().keySet()) {
			if( t.isAlive() && t.getName().startsWith("ResolverThread") ) {
				n++;
			}
		}
		return n;
	}

	@Test
	public void secondInitStopsTheFirstThreads() throws Exception {
		String saved = System.getProperty("JDns.resolvers");
		System.setProperty("JDns.resolvers", "3");
		try {
			Resolver.initResolver();
			Resolver.initResolver();
			Resolver.initResolver();
			assertEquals(3, Resolver.getResolvers().length);
			Resolver.shutDown();
			assertTrue(Resolver.awaitShutdown(5000), "the current threads stopped");
			long end = System.currentTimeMillis()+5000;
			while( liveResolverThreads() > 0 && System.currentTimeMillis() < end ) {
				Thread.sleep(20);
			}
			assertEquals(0, liveResolverThreads(), "no resolver thread left running");
		} finally {
			if( saved == null ) {
				System.clearProperty("JDns.resolvers");
			} else {
				System.setProperty("JDns.resolvers", saved);
			}
		}
	}
}
