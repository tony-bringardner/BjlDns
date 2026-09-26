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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.A;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Mx;
import us.bringardner.net.dns.Ns;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.Soa;
import us.bringardner.net.dns.Txt;
import us.bringardner.net.dns.Utility;

/**
 * $ORIGIN, $TTL and $INCLUDE, and the zone file syntax around them (rec #38).
 */
public class TestZoneDirectives {

	private File dir;

	private static final String SOA =
			"@\tIN\tSOA\tns1 postmaster (\n"
			+"\t\t\t1 ; serial\n\t\t\t1h ; refresh\n\t\t\t30m ; retry\n"
			+"\t\t\t2w ; expire\n\t\t\t300 ) ; minimum\n"
			+"\t\tNS\tns1\n"
			+"ns1\tIN\tA\t10.0.0.53\n";

	@BeforeEach
	public void setup() throws IOException {
		dir = Files.createTempDirectory("directives").toFile();
	}

	@AfterEach
	public void cleanup() {
		delete(dir);
	}

	private static void delete(File f) {
		File [] list = f.listFiles();
		if( list != null ) {
			for(File c : list) {
				delete(c);
			}
		}
		f.delete();
	}

	private File write(String name, String text) throws IOException {
		File f = new File(dir, name);
		f.getParentFile().mkdirs();
		try(FileWriter w = new FileWriter(f)) {
			w.write(text);
		}
		return f;
	}

	private Zone zone(String text) throws IOException {
		return new Zone(write("d.test.txt", text));
	}

	private static String a(Zone z, String name) {
		RR rr = z.getMatchingRR(name, DNS.A);
		return rr == null ? null : ((A)rr).getAddressString();
	}

	private static int ttl(Zone z, String name, int type) {
		return z.getMatchingRR(name, type).getTTL();
	}

	// ------------------------------------------------------------ $ORIGIN

	@Test
	public void originChangesRelativeNames() throws Exception {
		Zone z = zone(SOA
				+"www\tIN\tA\t10.0.0.1\n"
				+"$ORIGIN sub.d.test.\n"
				+"www\tIN\tA\t10.0.0.2\n"
				+"@\tIN\tMX\t10 mail\n"
				+"mail\tIN\tA\t10.0.0.25\n"
				+"$ORIGIN deeper\n"		//  relative: deeper.sub.d.test
				+"x\tIN\tA\t10.0.0.3\n");
		assertEquals("d.test", z.getName());
		assertEquals("10.0.0.1", a(z,"www.d.test"));
		assertEquals("10.0.0.2", a(z,"www.sub.d.test"));
		assertEquals("10.0.0.25", a(z,"mail.sub.d.test"));
		assertEquals("mail.sub.d.test", ((Mx)z.getMatchingRR("sub.d.test", DNS.MX)).getExchange(), "@ is the new origin");
		assertEquals("10.0.0.3", a(z,"x.deeper.sub.d.test"));
	}

	@Test
	public void originBeforeTheSoaNamesTheZone() throws Exception {
		Zone z = new Zone(write("whatever.txt", "$ORIGIN real.test.\n"+SOA+"www\tIN\tA\t10.0.0.1\n"));
		assertEquals("real.test", z.getName());
		assertEquals("10.0.0.1", a(z,"www.real.test"));
		Soa soa = z.getSoa();
		assertEquals("ns1.real.test", soa.getMname(), "relative SOA names use the origin");
		assertEquals("postmaster.real.test", soa.getRname());
	}

	@Test
	public void ownerOfBlankLinesIsKeptAcrossOrigin() throws Exception {
		Zone z = zone(SOA
				+"www\tIN\tA\t10.0.0.1\n"
				+"$ORIGIN other.test.\n"
				+"\tIN\tTXT\t\"still www.d.test\"\n");
		assertNotNull(z.getMatchingRR("www.d.test", DNS.TXT));
		assertNull(z.getMatchingRR("www.other.test", DNS.TXT));
	}

	// ------------------------------------------------------------ $TTL

	@Test
	public void ttlDefaults() throws Exception {
		Zone z = zone("$TTL 1h\n"+SOA
				+"www\tIN\tA\t10.0.0.1\n"
				+"short\t60\tIN\tA\t10.0.0.2\n"		//  explicit, lower than the SOA: kept
				+"$TTL 2d\n"
				+"later\tIN\tA\t10.0.0.3\n");
		assertEquals(3600, z.getSoa().getTTL(), "SOA without a TTL gets $TTL");
		assertEquals(3600, ttl(z,"www.d.test",DNS.A));
		assertEquals(60, ttl(z,"short.d.test",DNS.A), "an explicit TTL is used as is");
		assertEquals(2*86400, ttl(z,"later.d.test",DNS.A), "$TTL applies from where it is");
	}

	@Test
	public void withoutTtlDirectiveRecordsGetTheSoaTtl() throws Exception {
		Zone z = zone("@\t7200\tIN\tSOA\tns1 postmaster ( 1 3600 1800 1209600 300 )\n"
				+"\t\tNS\tns1\n"
				+"www\tIN\tA\t10.0.0.1\n");
		assertEquals(7200, z.getSoa().getTTL());
		assertEquals(7200, ttl(z,"www.d.test",DNS.A));
	}

	@Test
	public void ttlUnits() {
		assertEquals(90*60, Utility.toSeconds("1h30m"));
		assertEquals(8*86400, Utility.toSeconds("1w1d"));
		assertEquals(3600, Utility.toSeconds("1H"));
		assertEquals(300, Utility.toSeconds("300"));
		assertEquals(0, Utility.toSeconds("abc"));
	}

	// ------------------------------------------------------------ $INCLUDE

	@Test
	public void includeRelativeToTheIncludingFile() throws Exception {
		write("inc/hosts.inc", "www\tIN\tA\t10.0.0.1\nmail\tIN\tA\t10.0.0.25\n");
		Zone z = zone(SOA+"$INCLUDE inc/hosts.inc\nafter\tIN\tA\t10.0.0.9\n");
		assertEquals("10.0.0.1", a(z,"www.d.test"));
		assertEquals("10.0.0.25", a(z,"mail.d.test"));
		assertEquals("10.0.0.9", a(z,"after.d.test"));
		assertEquals(1, z.getIncludedFiles().size());
	}

	@Test
	public void includeWithOriginRestoresTheOrigin() throws Exception {
		write("lab.inc", "www\tIN\tA\t10.1.0.1\n@\tIN\tA\t10.1.0.0\n");
		Zone z = zone(SOA+"$INCLUDE lab.inc lab\nwww\tIN\tA\t10.0.0.1\n");
		assertEquals("10.1.0.1", a(z,"www.lab.d.test"));
		assertEquals("10.1.0.0", a(z,"lab.d.test"));
		assertEquals("10.0.0.1", a(z,"www.d.test"), "origin restored after the include");
	}

	@Test
	public void nestedIncludes() throws Exception {
		write("one.inc", "one\tIN\tA\t10.0.0.1\n$INCLUDE two.inc\n");
		write("two.inc", "two\tIN\tA\t10.0.0.2\n");
		Zone z = zone(SOA+"$INCLUDE one.inc\n");
		assertEquals("10.0.0.1", a(z,"one.d.test"));
		assertEquals("10.0.0.2", a(z,"two.d.test"));
		assertEquals(2, z.getIncludedFiles().size());
	}

	@Test
	public void includeLoopIsAnError() throws Exception {
		write("a.inc", "$INCLUDE b.inc\n");
		write("b.inc", "$INCLUDE a.inc\n");
		IOException ex = assertThrows(IOException.class, () -> zone(SOA+"$INCLUDE a.inc\n"));
		assertTrue(messages(ex).contains("loop"), messages(ex));
	}

	@Test
	public void missingIncludeNamesFileAndLine() throws Exception {
		IOException ex = assertThrows(IOException.class, () -> zone(SOA+"\n\n$INCLUDE nope.inc\n"));
		String m = messages(ex);
		assertTrue(m.contains("d.test.txt at line 11"), m);
		assertTrue(m.contains("nope.inc"), m);
	}

	@Test
	public void errorInIncludedFileNamesThatFile() throws Exception {
		write("bad.inc", "ok\tIN\tA\t10.0.0.1\nbroken\tIN\tA\t999.0.0.1\n");
		IOException ex = assertThrows(IOException.class, () -> zone(SOA+"$INCLUDE bad.inc\n"));
		assertTrue(messages(ex).contains("bad.inc at line 2"), messages(ex));
	}

	private static String messages(Throwable t) {
		StringBuilder b = new StringBuilder();
		for(; t != null; t = t.getCause()) {
			b.append(t.getMessage()).append(" | ");
		}
		return b.toString();
	}

	// ------------------------------------------------------------ syntax

	@Test
	public void oneLineSoaAndParenthesesAnywhere() throws Exception {
		//  Text after '(' on the same line used to be dropped
		Zone z = zone("@ IN SOA ns1.d.test. postmaster.d.test. ( 2024010101 3600 1800 1209600 300 )\n"
				+"  IN NS ns1\n"
				+"ns1 IN A 10.0.0.53\n"
				+"txt IN TXT ( \"one\" )\n");
		Soa soa = z.getSoa();
		assertEquals(2024010101, soa.getSerial());
		assertEquals(300, soa.getMinimum());
		assertEquals("ns1.d.test", ((Ns)z.getMatchingRR("d.test", DNS.NS)).getNs());
		assertEquals("one", ((Txt)z.getMatchingRR("txt.d.test", DNS.TXT)).getText());
	}

	@Test
	public void semicolonInsideQuotesIsNotAComment() throws Exception {
		Zone z = zone(SOA+"_dmarc\tIN\tTXT\t\"v=DMARC1; p=reject\" ; a real comment\n");
		assertEquals("v=DMARC1; p=reject", ((Txt)z.getMatchingRR("_dmarc.d.test", DNS.TXT)).getText());
	}

	@Test
	public void classBeforeTtl() throws Exception {
		Zone z = zone(SOA+"www\tIN\t600\tA\t10.0.0.1\n");
		assertEquals("10.0.0.1", a(z,"www.d.test"));
		assertEquals(600, ttl(z,"www.d.test",DNS.A));
	}

	@Test
	public void unknownDirectiveIsAnError() throws Exception {
		IOException ex = assertThrows(IOException.class, () -> zone(SOA+"$GENERATE 1-10 host$ A 10.0.0.$\n"));
		assertTrue(messages(ex).contains("Unsupported directive $GENERATE"), messages(ex));
	}

	// ------------------------------------------------------------ reload

	@Test
	public void editingAnIncludedFileReloadsTheZone() throws Exception {
		File zones = new File(dir,"zones");
		zones.mkdirs();
		File inc = write("zones/hosts.inc", "www\tIN\tA\t10.0.0.1\n");
		write("zones/d.test.txt", SOA+"$INCLUDE hosts.inc\n");
		String savedDir = System.getProperty(DnsServer.PROP_ZONE_DIR);
		String savedDefault = System.getProperty(DnsServer.PROP_DEFAULT_ZONE);
		System.setProperty(DnsServer.PROP_ZONE_DIR, zones.getAbsolutePath());
		System.setProperty(DnsServer.PROP_DEFAULT_ZONE, "d.test");
		try {
			DnsServer server = new DnsServer();
			server.loadZones();
			assertEquals("10.0.0.1", a(server.getZone("d.test"),"www.d.test"));
			assertTrue(!server.shouldReloadZones(), "nothing changed");

			try(FileWriter w = new FileWriter(inc)) {
				w.write("www\tIN\tA\t10.0.0.2\n");
			}
			inc.setLastModified(inc.lastModified()+2000);
			assertTrue(server.shouldReloadZones(), "the included file changed");
			server.loadZones();
			assertEquals("10.0.0.2", a(server.getZone("d.test"),"www.d.test"));
			assertTrue(!server.shouldReloadZones());
		} finally {
			restore(DnsServer.PROP_ZONE_DIR, savedDir);
			restore(DnsServer.PROP_DEFAULT_ZONE, savedDefault);
		}
	}

	private static void restore(String key, String value) {
		if( value == null ) {
			System.clearProperty(key);
		} else {
			System.setProperty(key, value);
		}
	}
}
