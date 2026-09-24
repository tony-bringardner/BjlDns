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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Files;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.ByteBuffer;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.Soa;
import us.bringardner.net.dns.resolve.QueryData;

/**
 * Offline tests for authoritative answers: NXDOMAIN vs NODATA vs positive
 * (RFC 1034 4.3.2, RFC 2308, RFC 6604, RFC 8020).
 */
public class TestAuthoritativeAnswers {

	private static File dir;
	private static DnsServer server;

	@BeforeAll
	public static void setup() throws IOException {
		dir = Files.createTempDirectory("auth").toFile();
		File zone = new File(dir,"auth.test.txt");
		try(FileWriter w = new FileWriter(zone)) {
			w.write("@\tIN\tSOA\tns1.auth.test. postmaster.auth.test. (\n"
					+"\t\t\t1 ; serial\n\t\t\t3600 ; refresh\n\t\t\t1800 ; retry\n"
					+"\t\t\t1209600 ; expire\n\t\t\t300 ) ; minimum\n\n"
					+"\t\tNS\tns1\n"
					+"\t\tNS\tns2\n"
					+"\t\tMX\t10 mail\n"
					+"ns1\tIN\tA\t10.0.0.53\n"
					+"ns2\tIN\tA\t10.0.0.54\n"
					+"mail\tIN\tA\t10.0.0.25\n"
					+"www\tIN\tA\t10.0.0.80\n"
					+"a.b\tIN\tA\t10.0.0.11\n"
					+"dangling\tIN\tCNAME\tmissing.auth.test.\n"
					+"*.wild\tIN\tA\t10.0.0.99\n");
		}
		server = new DnsServer();
		server.addZone(new Zone(zone));
		server.setRecursionAvailable(false);
	}

	@AfterAll
	public static void cleanup() {
		for(File f : dir.listFiles()) {
			f.delete();
		}
		dir.delete();
	}

	/** Ask and return the response as a client would see it (through the wire format). */
	private static Message ask(String name, int type) {
		Message q = new Message();
		q.setQuestion(name, type, DNS.IN);
		Message r = server.query(new QueryData(InetAddress.getLoopbackAddress(), 5353, q)).get(0);
		return new Message(new ByteBuffer(r.toByteArray()));
	}

	private static int count(java.util.List<RR> list, int type) {
		int ret = 0;
		for(RR rr : list) {
			if( rr.getType() == type ) {
				ret++;
			}
		}
		return ret;
	}

	private static void assertNegativeSoa(Message m) {
		assertEquals(1, count(m.getAuthority(),DNS.SOA), "SOA in authority: "+m.getAuthority());
		assertEquals(0, count(m.getAuthority(),DNS.NS), "no NS in a negative answer");
		Soa soa = (Soa)m.getAuthority().get(0);
		assertEquals(Math.min(soa.getMinimum(), 300), soa.getTTL(), "SOA TTL = min(TTL, MINIMUM)");
	}

	@Test
	public void missingNameIsNxdomain() {
		Message m = ask("nope.auth.test", DNS.A);
		assertEquals(DNS.NAME_ERROR, m.getResponseCode());
		assertTrue(m.getHeader().getAA(), "authoritative");
		assertEquals(0, m.getAnswerCount());
		assertNegativeSoa(m);
	}

	@Test
	public void missingTypeIsNodata() {
		Message m = ask("www.auth.test", DNS.MX);
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertEquals(0, m.getAnswerCount());
		assertNegativeSoa(m);
	}

	@Test
	public void apexNodataHasSoaNotNs() {
		// Used to return the zone's NS records in authority with no SOA,
		// which other resolvers read as a referral.
		Message m = ask("auth.test", DNS.AAAA);
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertEquals(0, m.getAnswerCount());
		assertNegativeSoa(m);
	}

	@Test
	public void emptyNonTerminalIsNodata() {
		// b.auth.test has no records but a.b.auth.test does, so it exists
		Message m = ask("b.auth.test", DNS.A);
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertEquals(0, m.getAnswerCount());
		assertNegativeSoa(m);
	}

	@Test
	public void positiveAnswersUnchanged() {
		Message m = ask("www.auth.test", DNS.A);
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertEquals(1, count(m.getAnswer(),DNS.A));

		Message mx = ask("auth.test", DNS.MX);
		assertEquals(DNS.NOERROR, mx.getResponseCode());
		assertEquals(1, count(mx.getAnswer(),DNS.MX));

		Message ns = ask("auth.test", DNS.NS);
		assertEquals(2, count(ns.getAnswer(),DNS.NS));
	}

	@Test
	public void wildcardStillMatches() {
		Message m = ask("anything.wild.auth.test", DNS.A);
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertEquals(1, count(m.getAnswer(),DNS.A));
	}

	@Test
	public void cnameToMissingNameIsNxdomainWithChain() {
		// RFC 6604: RCODE describes the last name in the chain
		Message m = ask("dangling.auth.test", DNS.A);
		assertEquals(DNS.NAME_ERROR, m.getResponseCode());
		assertEquals(1, count(m.getAnswer(),DNS.CNAME));
		assertEquals(1, count(m.getAuthority(),DNS.SOA));
	}

	@Test
	public void soaQueryUnchanged() {
		Message m = ask("auth.test", DNS.SOA);
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertEquals(1, count(m.getAnswer(),DNS.SOA));
	}
}
