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
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import java.time.Duration;

import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.A;
import us.bringardner.net.dns.Cname;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.Section;

/**
 * Offline tests: Resolver.resolve() must not recurse forever on CNAME loops.
 * The resolver cache is pre-loaded so no upstream query is ever sent
 * (and with no root servers configured a cache miss just returns null).
 */
public class TestCnameLoopsResolver {

	private static void cacheCname(String name, String target) {
		Message m = new Message();
		m.setQuestion(name, DNS.A, DNS.IN);
		m.setMessageTypeResponse();
		Cname c = new Cname(name);
		c.setCname(target);
		c.setTTL(300);
		m.addAnswer(c);
		Resolver.getCache().put(m);
	}

	private static void cacheA(String name, String ip) {
		Message m = new Message();
		m.setQuestion(name, DNS.A, DNS.IN);
		m.setMessageTypeResponse();
		A a = new A(name);
		a.setAddress(ip);
		a.setTTL(300);
		m.addAnswer(a);
		Resolver.getCache().put(m);
	}

	private static int count(Message m, int type) {
		int ret = 0;
		for(RR rr : m.getAnswer()) {
			if( rr.getType() == type ) {
				ret++;
			}
		}
		return ret;
	}

	private static Message resolve(String name) {
		return assertTimeoutPreemptively(Duration.ofSeconds(5),
				() -> Resolver.resolve(new Section(name,DNS.A,DNS.IN)));
	}

	@Test
	public void normalChainCombined() {
		Resolver.getCache().clear();
		cacheCname("www.r.test","web.r.test");
		cacheA("web.r.test","10.0.0.80");
		Message m = resolve("www.r.test");
		assertNotNull(m);
		assertEquals(1, count(m,DNS.CNAME));
		assertEquals(1, count(m,DNS.A));
	}

	@Test
	public void twoNameLoopTerminates() {
		Resolver.getCache().clear();
		cacheCname("a.r.test","b.r.test");
		cacheCname("b.r.test","a.r.test");
		Message m = resolve("a.r.test");
		assertNotNull(m);
		assertEquals(0, count(m,DNS.A));
		// and again, now served from the combined cache entry
		assertNotNull(resolve("a.r.test"));
		assertNotNull(resolve("b.r.test"));
	}

	@Test
	public void selfLoopTerminates() {
		Resolver.getCache().clear();
		cacheCname("self.r.test","SELF.r.test");
		Message m = resolve("self.r.test");
		assertEquals(1, count(m,DNS.CNAME));
	}

	@Test
	public void longChainIsCut() {
		Resolver.getCache().clear();
		for(int i=1; i< 20; i++ ) {
			cacheCname("c"+i+".r.test","c"+(i+1)+".r.test");
		}
		cacheA("c20.r.test","10.0.0.20");
		Message m = resolve("c1.r.test");
		assertNotNull(m);
		assertEquals(QueryData.MAX_CNAME_CHAIN+1, count(m,DNS.CNAME));
		assertEquals(0, count(m,DNS.A));
	}
}
