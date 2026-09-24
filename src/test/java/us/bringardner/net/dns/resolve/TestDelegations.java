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
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.A;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.Ns;

/**
 * Offline tests for the resolver's table of learned delegations
 * (Resolver.addServer / getDelegation).
 */
public class TestDelegations {

	/** A referral like an upstream returns: NS records for zone plus glue A records. */
	private static Message referral(String zone, String ... ips) {
		Message m = new Message();
		m.setQuestion("www."+zone, DNS.A, DNS.IN);
		m.setMessageTypeResponse();
		for(int i=0; i< ips.length; i++ ) {
			String host = "ns"+i+"."+zone;
			Ns ns = new Ns(zone);
			ns.setNs(host);
			ns.setTTL(3600);
			m.addAuthority(ns);
			A a = new A(host);
			a.setAddress(ips[i]);
			a.setTTL(3600);
			m.addAdditional(a);
		}
		return m;
	}

	private static RemoteServer fromReferral(String zone, String ... ips) {
		return new RemoteServer(referral(zone, ips));
	}

	private static void reset() {
		Resolver.reset();
		Resolver.setMaxDelegations(10000);
		Resolver.setDelegationMaxAge(60*60*1000L);
	}

	@Test
	public void repeatedReferralsDoNotGrow() {
		// The old code appended a new RemoteServer for every referral seen
		reset();
		RemoteServer first = Resolver.addServer(fromReferral("sub.test","10.0.5.1","10.0.5.2"));
		for(int i=0; i< 1000; i++ ) {
			RemoteServer got = Resolver.addServer(fromReferral("sub.test","10.0.5.1","10.0.5.2"));
			assertSame(first, got, "the known server for the zone is reused");
		}
		assertEquals(1, Resolver.delegationCount());
		assertEquals(2, first.getAddressCount());
	}

	@Test
	public void newAddressesAreMerged() {
		reset();
		RemoteServer first = Resolver.addServer(fromReferral("sub.test","10.0.5.1","10.0.5.2"));
		Resolver.addServer(fromReferral("sub.test","10.0.5.2","10.0.5.3"));
		assertEquals(3, first.getAddressCount());
		assertSame(first, Resolver.getDelegation("sub.test"));
	}

	@Test
	public void addressesPerZoneAreCapped() {
		reset();
		RemoteServer first = Resolver.addServer(fromReferral("big.test","10.0.6.1"));
		for(int i=2; i< 40; i++ ) {
			Resolver.addServer(fromReferral("big.test","10.0.6."+i));
		}
		assertEquals(RemoteServer.MAX_ADDRESSES, first.getAddressCount());
	}

	@Test
	public void deactivationSurvivesNewReferrals() {
		// With a new RemoteServer per referral a dead server was retried
		// immediately. Now the known ServerA (and its state) is kept.
		reset();
		RemoteServer first = Resolver.addServer(fromReferral("dead.test","10.0.7.1"));
		Iterator<ServerA> it = first.iterator();
		ServerA s = it.next();
		s.setActive(false);
		assertTrue(!first.isActive());
		RemoteServer again = Resolver.addServer(fromReferral("dead.test","10.0.7.1"));
		assertSame(first, again);
		assertTrue(!again.isActive(), "still inactive after the same referral arrives again");
	}

	@Test
	public void zoneNamesAreCaseInsensitive() {
		reset();
		RemoteServer first = Resolver.addServer(fromReferral("Mixed.TEST","10.0.8.1"));
		assertSame(first, Resolver.getDelegation("mixed.test"));
		assertSame(first, Resolver.addServer(fromReferral("MIXED.test","10.0.8.1")));
		assertEquals(1, Resolver.delegationCount());
	}

	@Test
	public void lruBound() {
		reset();
		Resolver.setMaxDelegations(3);
		for(int i=0; i< 5; i++ ) {
			Resolver.addServer(fromReferral("z"+i+".test","10.0.9."+(i+1)));
		}
		assertEquals(3, Resolver.delegationCount());
		assertNull(Resolver.getDelegation("z0.test"));
		assertNull(Resolver.getDelegation("z1.test"));
		assertNotNull(Resolver.getDelegation("z4.test"));
		Resolver.setMaxDelegations(10000);
	}

	@Test
	public void staleDelegationIsReplaced() throws Exception {
		reset();
		Resolver.setDelegationMaxAge(50);
		RemoteServer first = Resolver.addServer(fromReferral("old.test","10.0.10.1"));
		Thread.sleep(80);
		assertNull(Resolver.getDelegation("old.test"), "expired");
		RemoteServer fresh = Resolver.addServer(fromReferral("old.test","10.0.10.2"));
		assertNotSame(first, fresh);
		assertEquals(1, fresh.getAddressCount());
		Resolver.setDelegationMaxAge(60*60*1000L);
	}

	@Test
	public void referralWithoutNsIsIgnored() {
		reset();
		Message m = new Message();
		m.setQuestion("www.none.test", DNS.A, DNS.IN);
		RemoteServer rs = new RemoteServer(m);
		assertSame(rs, Resolver.addServer(rs));
		assertEquals(0, Resolver.delegationCount());
	}

	@Test
	public void concurrentReferrals() throws Exception {
		reset();
		AtomicReference<String> failure = new AtomicReference<String>();
		List<Thread> list = new ArrayList<Thread>();
		for(int t=0; t< 8; t++ ) {
			final int tn = t;
			Thread th = new Thread(() -> {
				try {
					for(int i=0; i< 2000; i++ ) {
						String zone = "c"+(i % 20)+".test";
						RemoteServer rs = Resolver.addServer(fromReferral(zone,"10.1."+(i % 20)+"."+(1+tn % 3)));
						if( rs.getAddressCount() > RemoteServer.MAX_ADDRESSES ) {
							failure.compareAndSet(null,"too many addresses");
						}
						Resolver.getDelegation(zone);
					}
				} catch(Throwable ex) {
					failure.compareAndSet(null, ex.toString());
				}
			});
			list.add(th);
			th.start();
		}
		for(Thread th : list) {
			th.join(60_000);
		}
		assertNull(failure.get(), failure.get());
		assertEquals(20, Resolver.delegationCount());
		for(int i=0; i< 20; i++ ) {
			assertEquals(3, Resolver.getDelegation("c"+i+".test").getAddressCount());
		}
	}
}
