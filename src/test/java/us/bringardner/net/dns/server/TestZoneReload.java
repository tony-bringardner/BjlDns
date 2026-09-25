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
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.A;
import us.bringardner.net.dns.DNS;

/**
 * Offline tests for atomic zone loading / reloading in DnsServer.
 */
public class TestZoneReload {

	private static String zoneText(String zone, String wwwIp) {
		return "@\tIN\tSOA\tns1."+zone+". postmaster."+zone+". (\n"
				+"\t\t\t1 ; serial\n\t\t\t3600 ; refresh\n\t\t\t1800 ; retry\n"
				+"\t\t\t1209600 ; expire\n\t\t\t3600 ) ; minimum\n\n"
				+"\t\tNS\tns1\n"
				+"ns1\tIN\tA\t10.0.0.53\n"
				+"www\tIN\tA\t"+wwwIp+"\n";
	}

	private static void write(File f, String text) throws IOException {
		try(FileWriter w = new FileWriter(f)) {
			w.write(text);
		}
	}

	/** Make a file look modified (timestamps can have 1s resolution). */
	private static void touch(File f, long bumpMs) {
		f.setLastModified(f.lastModified()+bumpMs);
	}

	private static String www(DnsServer s, String zone) {
		A a = (A)s.getZone(zone).getMatchingRR("www."+zone, DNS.A);
		return a.getAddressString();
	}

	/** A server whose zone dir holds a.test (default) and b.test */
	private static class Fixture implements AutoCloseable {
		final File dir;
		final File a;
		final File b;
		final DnsServer server = new DnsServer();
		//  Restored in close(): left behind, they pointed later tests (TestDns)
		//  at a deleted zone directory.
		final String savedZoneDir = System.getProperty(DnsServer.PROP_ZONE_DIR);
		final String savedDefaultZone = System.getProperty(DnsServer.PROP_DEFAULT_ZONE);

		Fixture() throws IOException {
			dir = Files.createTempDirectory("zones").toFile();
			a = new File(dir,"a.test.txt");
			b = new File(dir,"b.test.txt");
			write(a, zoneText("a.test","10.0.0.1"));
			write(b, zoneText("b.test","10.0.0.2"));
			System.setProperty(DnsServer.PROP_ZONE_DIR, dir.getAbsolutePath());
			System.setProperty(DnsServer.PROP_DEFAULT_ZONE, "a.test");
			server.loadZones();
		}

		@Override
		public void close() {
			restore(DnsServer.PROP_ZONE_DIR, savedZoneDir);
			restore(DnsServer.PROP_DEFAULT_ZONE, savedDefaultZone);
			for(File f : dir.listFiles()) {
				f.delete();
			}
			dir.delete();
		}

		private void restore(String key, String value) {
			if( value == null ) {
				System.clearProperty(key);
			} else {
				System.setProperty(key, value);
			}
		}
	}

	@Test
	public void initialLoad() throws Exception {
		try(Fixture fx = new Fixture()) {
			assertEquals(2, fx.server.getZones().size());
			assertEquals("a.test", fx.server.getDefaultZone().getName());
			assertEquals("10.0.0.2", www(fx.server,"b.test"));
			assertTrue(!fx.server.shouldReloadZones(), "nothing changed");
		}
	}

	@Test
	public void changedFileIsReloadedUnchangedFileReused() throws Exception {
		try(Fixture fx = new Fixture()) {
			Zone aBefore = fx.server.getZone("a.test");
			Zone bBefore = fx.server.getZone("b.test");
			write(fx.b, zoneText("b.test","10.0.0.22"));
			touch(fx.b, 2000);
			assertTrue(fx.server.shouldReloadZones());
			fx.server.loadZones();
			assertEquals("10.0.0.22", www(fx.server,"b.test"));
			assertNotSame(bBefore, fx.server.getZone("b.test"));
			assertSame(aBefore, fx.server.getZone("a.test"), "unchanged file is not re-parsed");
			assertTrue(!fx.server.shouldReloadZones());
		}
	}

	@Test
	public void addedAndRemovedFiles() throws Exception {
		try(Fixture fx = new Fixture()) {
			File c = new File(fx.dir,"c.test.txt");
			write(c, zoneText("c.test","10.0.0.3"));
			assertTrue(fx.server.shouldReloadZones());
			fx.server.loadZones();
			assertEquals("10.0.0.3", www(fx.server,"c.test"));

			assertTrue(fx.b.delete());
			assertTrue(fx.server.shouldReloadZones());
			fx.server.loadZones();
			assertNull(fx.server.getZone("b.test"));
			assertEquals(2, fx.server.getZones().size());
		}
	}

	@Test
	public void badNewFileDoesNotCauseReloadLoop() throws Exception {
		// The old check compared the file count to zones.size(), so one bad
		// file made shouldReloadZones() true forever (reload every minute).
		try(Fixture fx = new Fixture()) {
			File bad = new File(fx.dir,"bad.test.txt");
			write(bad, zoneText("bad.test","not.an.ip.address"));
			fx.server.loadZones();
			assertNull(fx.server.getZone("bad.test"));
			assertEquals(2, fx.server.getZones().size());
			assertTrue(!fx.server.shouldReloadZones(), "no reload until something changes");

			write(bad, zoneText("bad.test","10.0.0.9"));
			touch(bad, 2000);
			assertTrue(fx.server.shouldReloadZones());
			fx.server.loadZones();
			assertEquals("10.0.0.9", www(fx.server,"bad.test"));
		}
	}

	@Test
	public void brokenEditKeepsPreviousVersion() throws Exception {
		try(Fixture fx = new Fixture()) {
			write(fx.b, zoneText("b.test","999.1.1.1"));
			touch(fx.b, 2000);
			fx.server.loadZones();
			assertEquals("10.0.0.2", www(fx.server,"b.test"), "previous good version still served");
			assertTrue(!fx.server.shouldReloadZones());
		}
	}

	@Test
	public void missingDefaultKeepsServingOldZones() throws Exception {
		try(Fixture fx = new Fixture()) {
			assertTrue(fx.a.delete());
			assertThrows(IOException.class, () -> fx.server.loadZones());
			assertNotNull(fx.server.getDefaultZone(), "old set still published");
			assertEquals("10.0.0.1", www(fx.server,"a.test"));
			assertEquals("10.0.0.2", www(fx.server,"b.test"));
			assertTrue(!fx.server.shouldReloadZones(), "no retry until the directory changes");
		}
	}

	@Test
	public void zonesNeverMissingDuringReload() throws Exception {
		// The old loadZones() assigned an empty map first and filled it
		// afterwards, so concurrent queries could find no zone at all.
		try(Fixture fx = new Fixture()) {
			AtomicBoolean done = new AtomicBoolean();
			AtomicInteger misses = new AtomicInteger();
			AtomicInteger lookups = new AtomicInteger();
			Thread reader = new Thread(() -> {
				while( !done.get() ) {
					if( fx.server.getZone("a.test") == null || fx.server.getZone("b.test") == null
							|| fx.server.getDefaultZone() == null ) {
						misses.incrementAndGet();
					}
					lookups.incrementAndGet();
				}
			});
			reader.start();
			for(int i=0; i< 200; i++ ) {
				touch(fx.a, 1000);
				touch(fx.b, 1000);
				fx.server.loadZones();
			}
			done.set(true);
			reader.join();
			assertTrue(lookups.get() > 0);
			assertEquals(0, misses.get(), "lookups that found no zone during a reload");
		}
	}

	@Test
	public void addZoneStillWorks() throws Exception {
		try(Fixture fx = new Fixture()) {
			File extra = new File(fx.dir,"x.test.txt.later");
			write(extra, zoneText("x.test","10.0.0.8"));
			Zone x = new Zone(extra);
			fx.server.addZone(x);
			assertSame(x, fx.server.getZone("x.test.txt"));
			assertEquals("a.test", fx.server.getDefaultZone().getName());
		}
	}
}
