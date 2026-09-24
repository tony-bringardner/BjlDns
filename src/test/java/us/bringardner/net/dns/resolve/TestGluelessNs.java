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
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.Collections;

import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.A;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.Ns;
import us.bringardner.net.dns.Section;

/**
 * Offline tests: name servers that come without glue are looked up through
 * our own resolver when first used, never with the OS resolver, and a lookup
 * that needs itself gives up instead of recursing.
 */
public class TestGluelessNs {

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

	@Test
	public void noLookupWhenCreated() {
		// used to call InetAddress.getByName(name) in the constructor
		ServerA s = new ServerA("localhost", null);
		assertNull(s.getAddress(), "no OS lookup (localhost would have resolved)");
		assertEquals("localhost", s.getName());
	}

	@Test
	public void addressComesFromOurResolverOnFirstUse() throws Exception {
		Resolver.getCache().clear();
		try(TestServerA.FakeUpstream up = new TestServerA.FakeUpstream()) {
			cacheA("ns1.glue.test", "127.0.0.1");
			ServerA s = new ServerA("ns1.glue.test", null);
			s.setPort(up.port());
			Message m = s.query(new Section("www.glue.test", DNS.A, DNS.IN));
			assertNotNull(m, "answered by the upstream found through the cache");
			assertEquals("127.0.0.1", s.getAddress().getHostAddress());
			// cached on the ServerA: works even after the cache is cleared
			Resolver.getCache().clear();
			assertNotNull(s.query(new Section("www2.glue.test", DNS.A, DNS.IN)));
		} finally {
			Resolver.getCache().clear();
		}
	}

	@Test
	public void unknownAddressCountsAsFailure() {
		Resolver.getCache().clear();
		Resolver.setRootServersForTests(Collections.<RemoteServer>emptyList());
		ServerA s = new ServerA("ns1.nowhere.test", null);
		for(int i=0; i<= ServerA.MAX_TRIES; i++ ) {
			assertNull(s.query(new Section("www.nowhere.test", DNS.A, DNS.IN)));
		}
		assertTrue(!s.isActive(), "deactivated like any unreachable server");
	}

	@Test
	public void selfReferencingLookupEnds() {
		// The only root server is glueless ns.loop.test: finding its address
		// needs a query to itself. It must give up, not recurse forever.
		Resolver.getCache().clear();
		RemoteServer root = new RemoteServer();
		root.setName(".");
		root.addAddress("ns.loop.test", null);
		Resolver.setRootServersForTests(Collections.singletonList(root));
		try {
			Message m = assertTimeoutPreemptively(Duration.ofSeconds(10),
					() -> Resolver.resolve(new Section("www.loop.test", DNS.A, DNS.IN)));
			assertNull(m);
		} finally {
			Resolver.setRootServersForTests(Collections.<RemoteServer>emptyList());
			Resolver.getCache().clear();
		}
	}

	@Test
	public void gluelessServersMergeByName() {
		Resolver.reset();
		Message ref = new Message();
		ref.setQuestion("www.sub.test", DNS.A, DNS.IN);
		ref.setMessageTypeResponse();
		Ns ns = new Ns("sub.test");
		ns.setNs("ns1.other.test");   // no glue
		ns.setTTL(3600);
		ref.addAuthority(ns);
		RemoteServer first = Resolver.addServer(new RemoteServer(ref));
		for(int i=0; i< 5; i++ ) {
			Resolver.addServer(new RemoteServer(ref));
		}
		assertEquals(1, first.getAddressCount(), "the same glueless server is not added again");
		Resolver.reset();
	}
}
