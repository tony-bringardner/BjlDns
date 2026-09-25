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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.A;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.Name;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.resolve.QueryData;
import us.bringardner.net.dns.resolve.RemoteServer;
import us.bringardner.net.dns.resolve.ServerA;

/**
 * Offline tests for state shared between query and admin threads:
 * dynamic records, common domains and RemoteServer rotation.
 */
public class TestThreadSafeState {

	private static File dir;
	private static DnsServer server;
	private static String savedDynamicFile;

	@BeforeAll
	public static void setup() throws IOException {
		System.setProperty("JDns.useDataBase","false");
		dir = Files.createTempDirectory("dyn").toFile();
		//  Without this the dynamic file went to the working directory (the server
		//  has no JDns.dnsDir here), leaving a dynamic.txt in the project.
		savedDynamicFile = System.getProperty(DnsServer.PROP_DYNAMIC);
		System.setProperty(DnsServer.PROP_DYNAMIC, new File(dir,"dynamic.txt").getAbsolutePath());
		File zone = new File(dir,"dyn.test.txt");
		try(FileWriter w = new FileWriter(zone)) {
			w.write("@\tIN\tSOA\tns1.dyn.test. postmaster.dyn.test. (\n"
					+"\t\t\t1 ; serial\n\t\t\t3600 ; refresh\n\t\t\t1800 ; retry\n"
					+"\t\t\t1209600 ; expire\n\t\t\t3600 ) ; minimum\n\n"
					+"\t\tNS\tns1\n"
					+"ns1\tIN\tA\t10.0.0.53\n");
		}
		server = new DnsServer();
		server.addZone(new Zone(zone));
		server.setRecursionAvailable(false);
	}

	@AfterAll
	public static void cleanup() {
		if( savedDynamicFile == null ) {
			System.clearProperty(DnsServer.PROP_DYNAMIC);
		} else {
			System.setProperty(DnsServer.PROP_DYNAMIC, savedDynamicFile);
		}
		for(File f : dir.listFiles()) {
			f.delete();
		}
		dir.delete();
	}

	private static List<String> addresses(String name) {
		Message q = new Message();
		q.setQuestion(name, DNS.A, DNS.IN);
		List<Message> ret = server.query(new QueryData(InetAddress.getLoopbackAddress(), 5353, q));
		List<String> list = new ArrayList<String>();
		for(RR rr : ret.get(0).getAnswer()) {
			if( rr instanceof A ) {
				list.add(((A)rr).getAddressString());
			}
		}
		return list;
	}

	@Test
	public void dynamicNamesAreCaseInsensitive() throws Exception {
		// Stored with the case given, but the query path looks up lower case,
		// so mixed-case dynamic names were never answered.
		assertNotNull(server.addDynamic("Host1.Dyn.Test","10.0.1.1"));
		assertEquals("[10.0.1.1]", addresses("host1.dyn.test").toString());
		assertEquals("[10.0.1.1]", addresses("HOST1.dyn.TEST").toString());
		assertNotNull(server.getDynamic("HOST1.DYN.TEST"));
		server.removeDynamic("host1.DYN.test");
		assertNull(server.getDynamic("host1.dyn.test"));
	}

	@Test
	public void updateReplacesRecordInsteadOfMutating() throws Exception {
		server.addOrUpdateDynamic("host2.dyn.test","10.0.2.1");
		A before = server.getDynamic("host2.dyn.test").get(0);
		server.addOrUpdateDynamic("host2.dyn.test","10.0.2.2");
		A after = server.getDynamic("host2.dyn.test").get(0);
		assertEquals("10.0.2.1", before.getAddressString(), "published record must not change under a reader");
		assertEquals("10.0.2.2", after.getAddressString());
		assertEquals(before.getTTL(), after.getTTL());
		assertEquals("[10.0.2.2]", addresses("host2.dyn.test").toString());
	}

	@Test
	public void unknownDomainNotAdded() throws Exception {
		server.addOrUpdateDynamic("host.elsewhere.test","10.0.9.9");
		assertNull(server.getDynamic("host.elsewhere.test"));
	}

	@Test
	public void commonDomainsAreCaseInsensitive() {
		server.addDomain("Example.ORG");
		assertTrue(server.isCommon(new Name("www.example.org")));
		server.removeDomain("EXAMPLE.org");
		assertTrue(!server.isCommon(new Name("www.example.org")));
	}

	@Test
	public void concurrentUpdatesAndQueries() throws Exception {
		final String[] ips = {"10.0.3.1","10.0.3.2"};
		final int names = 20;
		for(int i=0; i< names; i++ ) {
			server.addOrUpdateDynamic("h"+i+".dyn.test", ips[0]);
		}
		AtomicBoolean done = new AtomicBoolean();
		AtomicReference<String> failure = new AtomicReference<String>();

		Thread writer = new Thread(() -> {
			try {
				for(int n=0; n< 3000 && failure.get() == null; n++ ) {
					String name = "h"+(n % names)+".dyn.test";
					server.addOrUpdateDynamic(name, ips[n % 2]);
					server.addDomain("d"+(n % 50)+".example");
					if( n % 7 == 0 ) {
						server.removeDomain("d"+((n+25) % 50)+".example");
					}
					// iterate the snapshot like the admin 'list' command does
					server.getDynamic().size();
				}
			} catch(Throwable ex) {
				failure.compareAndSet(null,"writer: "+ex);
			} finally {
				done.set(true);
			}
		});

		List<Thread> readers = new ArrayList<Thread>();
		for(int t=0; t< 4; t++ ) {
			final int tn = t;
			Thread r = new Thread(() -> {
				int i = tn;
				try {
					while( !done.get() && failure.get() == null ) {
						String name = "h"+(i++ % names)+".dyn.test";
						List<String> got = addresses(name);
						if( got.size() != 1 || !(got.get(0).equals(ips[0]) || got.get(0).equals(ips[1])) ) {
							failure.compareAndSet(null, name+" -> "+got);
						}
						server.isCommon(new Name("www.d"+(i % 50)+".example"));
					}
				} catch(Throwable ex) {
					failure.compareAndSet(null,"reader: "+ex);
				}
			});
			readers.add(r);
		}
		for(Thread r : readers) {
			r.start();
		}
		writer.start();
		writer.join(60_000);
		for(Thread r : readers) {
			r.join(10_000);
		}
		assertNull(failure.get(), failure.get());
	}

	@Test
	public void remoteServerRotationIsThreadSafe() throws Exception {
		RemoteServer rs = new RemoteServer("example.test");
		rs.addAddress("a","10.0.4.1");
		rs.addAddress("b","10.0.4.2");
		rs.addAddress("c","10.0.4.3");
		AtomicReference<String> failure = new AtomicReference<String>();
		Set<String> firsts = java.util.Collections.synchronizedSet(new HashSet<String>());
		List<Thread> list = new ArrayList<Thread>();
		for(int t=0; t< 8; t++ ) {
			Thread th = new Thread(() -> {
				try {
					for(int i=0; i< 20000; i++ ) {
						Iterator<ServerA> it = rs.iterator();
						int n = 0;
						while( it.hasNext() ) {
							ServerA s = it.next();
							if( n++ == 0 ) {
								firsts.add(s.toString());
							}
						}
						if( n != 3 ) {
							failure.compareAndSet(null,"iterated "+n+" servers");
						}
					}
				} catch(Throwable ex) {
					failure.compareAndSet(null, ex.toString());
				}
			});
			list.add(th);
			th.start();
		}
		for(Thread th : list) {
			th.join(30_000);
		}
		assertNull(failure.get(), failure.get());
		assertEquals(3, firsts.size(), "starting server rotates over all addresses");
	}
}
