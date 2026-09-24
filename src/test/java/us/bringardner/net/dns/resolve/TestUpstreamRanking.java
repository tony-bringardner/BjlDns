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

import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Section;

/**
 * Offline tests: upstream servers are tried fastest first, timeouts adapt
 * to measured response times, and one deadline bounds the whole attempt.
 */
public class TestUpstreamRanking {

	private static int deadPort() throws Exception {
		try(DatagramSocket s = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
			return s.getLocalPort();
		}
	}

	private static Section q(String n) {
		return new Section(n, DNS.A, DNS.IN);
	}

	/** A zone with the given upstream ports on 127.0.0.1, in this order. */
	private static RemoteServer zone(int ... ports) {
		RemoteServer rs = new RemoteServer();
		rs.setName("rank.test");
		for(int i=0; i< ports.length; i++ ) {
			rs.addAddress("ns"+i+".rank.test","127.0.0.1");
		}
		List<ServerA> list = new ArrayList<ServerA>();
		for(Iterator<ServerA> it = rs.iterator(); it.hasNext(); ) {
			list.add(it.next());
		}
		// iterator() order may rotate; match servers to ports by name
		for(ServerA s : list) {
			int idx = Integer.parseInt(s.getName().substring(2, s.getName().indexOf('.')));
			s.setPort(ports[idx]);
		}
		return rs;
	}

	private static ServerA named(RemoteServer rs, String name) {
		for(Iterator<ServerA> it = rs.iterator(); it.hasNext(); ) {
			ServerA s = it.next();
			if( s.getName().equals(name) ) {
				return s;
			}
		}
		return null;
	}

	@Test
	public void responseTimeIsMeasured() throws Exception {
		try(TestServerA.FakeUpstream up = new TestServerA.FakeUpstream()) {
			ServerA s = new ServerA("fast","127.0.0.1");
			s.setPort(up.port());
			assertEquals(0, s.getSrtt());
			assertEquals(ServerA.QUERY_TIMEOUT, s.timeoutFor(10_000), "unknown server: full timeout");
			for(int i=0; i< 5; i++ ) {
				assertNotNull(s.query(q("www.rank.test")));
			}
			assertTrue(s.getSrtt() > 0 && s.getSrtt() < 500, "srtt="+s.getSrtt());
			assertTrue(s.timeoutFor(10_000) < ServerA.QUERY_TIMEOUT, "known fast server: shorter timeout "+s.timeoutFor(10_000));
			assertTrue(s.timeoutFor(10_000) >= ServerA.MIN_QUERY_TIMEOUT);
			assertEquals(50, s.timeoutFor(50), "never past the remaining time");
		}
	}

	@Test
	public void deadServerMovesBehindLiveOne() throws Exception {
		int savedTimeout = ServerA.QUERY_TIMEOUT;
		ServerA.QUERY_TIMEOUT = 400;
		try(TestServerA.FakeUpstream up = new TestServerA.FakeUpstream()) {
			RemoteServer rs = zone(deadPort(), up.port());
			ServerA dead = named(rs, "ns0.rank.test");
			ServerA live = named(rs, "ns1.rank.test");
			// first round: both untried, whichever order; make sure each is measured once
			dead.query(q("probe.rank.test"));
			live.query(q("probe.rank.test"));
			int deadSent = dead.getMsgSent();
			for(int i=0; i< 5; i++ ) {
				assertNotNull(rs.resolve(q("www"+i+".rank.test"), System.currentTimeMillis()+5000));
			}
			assertEquals(deadSent, dead.getMsgSent(), "the dead server is no longer tried first");
			assertEquals(live.getName(), rs.iterator().next().getName());
		} finally {
			ServerA.QUERY_TIMEOUT = savedTimeout;
		}
	}

	@Test
	public void deadlineBoundsTheWholeAttempt() throws Exception {
		// 3 dead servers x 2 s timeout would be 6 s; the deadline is 600 ms
		RemoteServer rs = zone(deadPort(), deadPort(), deadPort());
		long start = System.currentTimeMillis();
		assertNull(rs.resolve(q("www.rank.test"), start+600));
		long took = System.currentTimeMillis()-start;
		assertTrue(took < 1500, "took "+took+" ms");
	}

	@Test
	public void resolverUsesOneDeadline() throws Exception {
		long saved = Resolver.getResolveTimeout();
		RemoteServer root = zone(deadPort(), deadPort(), deadPort());
		root.setName(".");
		Resolver.getCache().clear();
		Resolver.setRootServersForTests(java.util.Collections.singletonList(root));
		try {
			Resolver.setResolveTimeout(700);
			long start = System.currentTimeMillis();
			assertNull(Resolver.resolve(q("www.deadline.test")));
			long took = System.currentTimeMillis()-start;
			assertTrue(took < 1700, "took "+took+" ms");
		} finally {
			Resolver.setResolveTimeout(saved);
			Resolver.setRootServersForTests(java.util.Collections.<RemoteServer>emptyList());
			Resolver.reset();
		}
	}
}
