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
import static org.junit.jupiter.api.Assertions.assertSame;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.Name;

/**
 * Offline tests: the indexed zone lookup returns exactly what the original
 * linear scan returns (same entry object) for exact names, wildcards,
 * misses and mixed case; and it is faster on a large zone.
 */
public class TestZoneIndex {

	private static File dir;
	private static Zone big;
	private static Zone fixture;

	@BeforeAll
	public static void setup() throws IOException {
		dir = Files.createTempDirectory("zidx").toFile();
		File f = new File(dir,"big.test.txt");
		StringBuilder z = new StringBuilder();
		z.append("@\tIN\tSOA\tns1.big.test. postmaster.big.test. (\n"
				+"\t\t\t1 ; serial\n\t\t\t3600 ; refresh\n\t\t\t1800 ; retry\n"
				+"\t\t\t1209600 ; expire\n\t\t\t300 ) ; minimum\n\n"
				+"\t\tNS\tns1\n"
				+"ns1\tIN\tA\t10.0.0.53\n"
				+"*.wild\tIN\tA\t10.0.0.1\n"
				+"*.*\tIN\tA\t10.0.0.2\n"
				+"exact.wild\tIN\tA\t10.0.0.3\n");
		for(int i=0; i< 5000; i++ ) {
			z.append("h"+i+"\tIN\tA\t10.1."+(i/250)+"."+(1+i%250)+"\n");
		}
		try(FileWriter w = new FileWriter(f)) {
			w.write(z.toString());
		}
		big = new Zone(f);
		fixture = new Zone(new File("src/test/java/resources/TestFiles/zones/foo.com.txt"));
	}

	@AfterAll
	public static void cleanup() {
		for(File f : dir.listFiles()) {
			f.delete();
		}
		dir.delete();
	}

	private static void assertSameAsScan(Zone z, String name) {
		Name n = new Name(name);
		assertSame(z.linearMatchingRRs(n), z.getMatchingRRs(n), name);
	}

	@Test
	public void sameResultsAsTheScan() {
		String [] names = {
				"big.test", "ns1.big.test", "NS1.Big.Test", "h0.big.test", "h4999.big.test", "H2500.BIG.test",
				"anything.wild.big.test", "exact.wild.big.test", "EXACT.wild.big.test",
				"a.b.big.test", "x.y.z.big.test", "nope.big.test", "h5000.big.test", "big.testx"
		};
		for(String n : names) {
			assertSameAsScan(big, n);
		}
		assertNotNull(big.getMatchingRRs(new Name("h4999.big.test")));
		assertNull(big.getMatchingRRs(new Name("nope.big.test")));
	}

	@Test
	public void sameResultsOnTheFixtureZone() {
		// foo.com has several wildcard layers (*.*., *.*.*., dev.*.*., dns2.*.*.)
		String [] names = {
				"foo.com", "www.foo.com", "ns1.foo.com", "mail.foo.com", "_dmarc.foo.com",
				"xxx.com", "www.xxx.com", "dev.xxx.com", "dns2.xxx.com", "a.b.c.d", "nothing.here.at.all.x"
		};
		for(String n : names) {
			assertSameAsScan(fixture, n);
		}
	}

	@Test
	public void wildcardQueryNameUsesTheScan() {
		assertSameAsScan(big, "*.wild.big.test");
		assertSameAsScan(big, "*.big.test");
	}

	@Test
	public void fasterOnALargeZone() {
		List<Name> queries = new ArrayList<Name>();
		for(int i=0; i< 2000; i++ ) {
			queries.add(new Name("h"+(4999-i)+".big.test"));
		}
		long t0 = System.nanoTime();
		for(Name n : queries) {
			big.linearMatchingRRs(n);
		}
		long scan = System.nanoTime()-t0;
		t0 = System.nanoTime();
		for(Name n : queries) {
			big.getMatchingRRs(n);
		}
		long indexed = System.nanoTime()-t0;
		System.out.println("5000-name zone, 2000 lookups: scan "+(scan/1_000_000)+" ms, indexed "+(indexed/1_000_000)+" ms");
		assertEquals(true, indexed < scan, "indexed lookup should beat the scan");
	}
}
