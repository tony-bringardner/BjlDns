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
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.A;
import us.bringardner.net.dns.ByteBuffer;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.Ns;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.resolve.QueryData;

/**
 * Offline: names at or below a delegation inside our zone (NS records below
 * the apex) get a referral, RFC 1034 4.3.2 step 3b.
 */
public class TestReferrals {

	private static File dir;
	private static DnsServer server;
	private static String savedZoneDir;
	private static String savedMaster;

	@BeforeAll
	public static void setup() throws IOException {
		dir = Files.createTempDirectory("referrals").toFile();
		try(FileWriter w = new FileWriter(new File(dir,"ref.test.txt"))) {
			w.write("@\tIN\tSOA\tns1.ref.test. postmaster.ref.test. (\n"
					+"\t\t\t1 ; serial\n\t\t\t3600 ; refresh\n\t\t\t1800 ; retry\n"
					+"\t\t\t1209600 ; expire\n\t\t\t300 ) ; minimum\n\n"
					+"\t\tNS\tns1\n"
					+"ns1\tIN\tA\t10.0.0.53\n"
					+"www\tIN\tA\t10.0.0.80\n"
					+"alias\tIN\tCNAME\thost.sub.ref.test.\n"
					+"sub\tIN\tNS\tns1.sub.ref.test.\n"
					+"\t\tNS\tns.elsewhere.example.\n"
					+"ns1.sub\tIN\tA\t10.0.1.53\n");
		}
		savedZoneDir = System.getProperty(DnsServer.PROP_ZONE_DIR);
		savedMaster = System.getProperty(DnsServer.PROP_DEFAULT_ZONE);
		System.setProperty(DnsServer.PROP_ZONE_DIR, dir.getAbsolutePath());
		System.setProperty(DnsServer.PROP_DEFAULT_ZONE, "ref.test");
		server = new DnsServer();
		server.loadZones();
		server.setRecursionAvailable(false);
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

	private static Message ask(String name, int type) {
		Message q = new Message();
		q.setQuestion(name, type, DNS.IN);
		q.setID(0x7070);
		q.getHeader().setRD(false);
		List<Message> r = server.query(new QueryData(InetAddress.getLoopbackAddress(), 5353, q));
		Message m = r.get(0);
		assertNotNull(m);
		return new Message(new ByteBuffer(m.toByteArray()));
	}

	private static List<String> nsNames(List<RR> list) {
		List<String> ret = new ArrayList<String>();
		for(RR rr : list) {
			if( rr.getType() == DNS.NS ) {
				ret.add(((Ns)rr).getNs().toLowerCase());
			}
		}
		return ret;
	}

	private static void assertReferral(Message m, String what) {
		assertEquals(DNS.NOERROR, m.getResponseCode(), what);
		assertTrue(!m.getHeader().getAA(), what+": not authoritative");
		assertEquals(0, m.getAnswerCount(), what);
		List<String> ns = nsNames(m.getAuthority());
		assertEquals(2, ns.size(), what+" "+ns);
		assertTrue(ns.contains("ns1.sub.ref.test"), what+" "+ns);
		assertTrue(ns.contains("ns.elsewhere.example"), what+" "+ns);
		for(RR rr : m.getAuthority()) {
			assertEquals("sub.ref.test", rr.getName().toLowerCase(), what+": the delegation's NS");
		}
		boolean glue = false;
		for(RR rr : m.getAdditional()) {
			if( rr.getType() == DNS.A && ((A)rr).getAddressString().equals("10.0.1.53") ) {
				glue = true;
			}
		}
		assertTrue(glue, what+": glue for the in-zone server");
	}

	@Test
	public void nameBelowCutIsReferred() {
		// Used to be an authoritative NXDOMAIN
		assertReferral(ask("host.sub.ref.test", DNS.A), "host.sub");
		assertReferral(ask("a.b.c.sub.ref.test", DNS.MX), "deep name");
	}

	@Test
	public void cutItselfIsReferred() {
		// A query used to get an authoritative empty answer
		assertReferral(ask("sub.ref.test", DNS.A), "sub A");
		assertReferral(ask("SUB.ref.test", DNS.NS), "sub NS");
	}

	@Test
	public void glueIsNotAnsweredAuthoritatively() {
		assertReferral(ask("ns1.sub.ref.test", DNS.A), "glue name");
	}

	@Test
	public void authoritativeDataUnchanged() {
		Message m = ask("www.ref.test", DNS.A);
		assertTrue(m.getHeader().getAA());
		assertEquals(1, m.getAnswerCount());

		m = ask("nothing.ref.test", DNS.A);
		assertTrue(m.getHeader().getAA());
		assertEquals(DNS.NAME_ERROR, m.getResponseCode());

		m = ask("ref.test", DNS.NS);
		assertTrue(m.getHeader().getAA());
		assertEquals(1, m.getAnswerCount());
	}

	@Test
	public void cnameIntoDelegation() {
		Message m = ask("alias.ref.test", DNS.A);
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertEquals(1, m.getAnswerCount(), "the CNAME");
		assertEquals(DNS.CNAME, m.getAnswer().get(0).getType());
		assertTrue(m.getHeader().getAA(), "the CNAME is our data");
		assertEquals(2, nsNames(m.getAuthority()).size(), "plus the referral");
	}

	@Test
	public void findDelegation() {
		Zone z = server.getZone(new us.bringardner.net.dns.Section("www.ref.test", DNS.A, DNS.IN));
		assertNotNull(z);
		assertNull(z.findDelegation("ref.test"), "apex is not a cut");
		assertNull(z.findDelegation("www.ref.test"));
		assertNull(z.findDelegation("www.other.test"));
		assertEquals(2, z.findDelegation("x.Sub.ref.test.").size());
	}

	@Test
	public void canBeTurnedOff() {
		server.setZoneCutReferrals(false);
		try {
			Message m = ask("host.sub.ref.test", DNS.A);
			assertEquals(DNS.NAME_ERROR, m.getResponseCode(), "old behaviour");
		} finally {
			server.setZoneCutReferrals(true);
		}
	}
}
