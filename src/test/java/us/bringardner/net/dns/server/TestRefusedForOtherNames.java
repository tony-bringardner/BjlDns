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
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.ByteBuffer;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.resolve.QueryData;
import us.bringardner.net.dns.resolve.ResolverThread;

/**
 * Offline tests: a query for a name we are not authoritative for, that we
 * won't resolve (recursion off or not requested), gets REFUSED (RFC 8906)
 * instead of NXDOMAIN or an empty NOERROR.
 */
public class TestRefusedForOtherNames {

	private static File dir;
	private static DnsServer server;
	private static String savedZoneDir;
	private static String savedMaster;

	@BeforeAll
	public static void setup() throws IOException {
		dir = Files.createTempDirectory("refused").toFile();
		try(FileWriter w = new FileWriter(new File(dir,"own.test.txt"))) {
			w.write("@\tIN\tSOA\tns1.own.test. postmaster.own.test. (\n"
					+"\t\t\t1 ; serial\n\t\t\t3600 ; refresh\n\t\t\t1800 ; retry\n"
					+"\t\t\t1209600 ; expire\n\t\t\t300 ) ; minimum\n\n"
					+"\t\tNS\tns1\n"
					+"ns1\tIN\tA\t10.0.0.53\n"
					+"www\tIN\tA\t10.0.0.80\n");
		}
		savedZoneDir = System.getProperty(DnsServer.PROP_ZONE_DIR);
		savedMaster = System.getProperty(DnsServer.PROP_DEFAULT_ZONE);
		System.setProperty(DnsServer.PROP_ZONE_DIR, dir.getAbsolutePath());
		System.setProperty(DnsServer.PROP_DEFAULT_ZONE, "own.test");
		server = new DnsServer();
		server.loadZones();
	}

	@AfterAll
	public static void cleanup() {
		restore(DnsServer.PROP_ZONE_DIR, savedZoneDir);
		restore(DnsServer.PROP_DEFAULT_ZONE, savedMaster);
		for(File f : dir.listFiles()) {
			f.delete();
		}
		dir.delete();
	}

	private static void restore(String k, String v) {
		if( v == null ) {
			System.clearProperty(k);
		} else {
			System.setProperty(k, v);
		}
	}

	private static Message ask(String name, boolean rd) {
		Message q = new Message();
		q.setQuestion(name, DNS.A, DNS.IN);
		q.setID(0x5151);
		q.getHeader().setRD(rd);
		List<Message> r = server.query(new QueryData(InetAddress.getLoopbackAddress(), 5353, q));
		Message m = r.get(0);
		return m == null ? null : new Message(new ByteBuffer(m.toByteArray()));
	}

	private static void assertRefused(Message m, String name) {
		assertNotNull(m);
		assertEquals(DNS.REFUSED, m.getResponseCode(), name);
		assertEquals(0x5151, m.getID());
		assertEquals(name, m.getFirstQuestion().getName());
		assertEquals(0, m.getAnswerCount());
		assertTrue(!m.getHeader().getAA(), "not authoritative");
	}

	@Test
	public void recursionOffOtherNameIsRefused() {
		// Used to be NXDOMAIN: claiming google.com does not exist
		server.setRecursionAvailable(false);
		assertRefused(ask("www.google.com", true), "www.google.com");
		assertRefused(ask("own.testx", true), "own.testx");
	}

	@Test
	public void recursionNotRequestedOtherNameIsRefused() {
		// Used to be an empty NOERROR
		server.setRecursionAvailable(true);
		assertRefused(ask("www.google.com", false), "www.google.com");
	}

	@Test
	public void recursionRequestedStillQueued() {
		ResolverThread.clearBacklog();
		try {
			server.setRecursionAvailable(true);
			assertNull(ask("www.google.com", true), "handed to a resolver thread as before");
		} finally {
			ResolverThread.clearBacklog();
		}
	}

	@Test
	public void ownNamesUnchanged() {
		server.setRecursionAvailable(false);
		Message ok = ask("www.own.test", true);
		assertEquals(DNS.NOERROR, ok.getResponseCode());
		assertEquals(1, ok.getAnswerCount());
		Message missing = ask("nope.own.test", true);
		assertEquals(DNS.NAME_ERROR, missing.getResponseCode(), "authoritative NXDOMAIN for our own zone");
		assertTrue(missing.getHeader().getAA());
	}

	@Test
	public void removedCommonDomainIsRefused() {
		// The TestDns scenario: served from the default zone while it is a
		// common domain, REFUSED once it is removed
		server.setRecursionAvailable(false);
		server.addDomain("flunky.bo");
		Message served = ask("flunky.bo", true);
		assertTrue(served.getResponseCode() != DNS.REFUSED, "answered for while it is ours");
		assertTrue(served.getHeader().getAA());
		server.removeDomain("flunky.bo");
		assertRefused(ask("flunky.bo", true), "flunky.bo");
	}
}
