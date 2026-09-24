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
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Files;
import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.A;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.resolve.QueryData;

/**
 * Offline tests: the authoritative server must not recurse forever on CNAME
 * loops in its own zone data (it used to throw StackOverflowError).
 */
public class TestCnameLoopsServer {

	private static File dir;
	private static DnsServer server;

	@BeforeAll
	public static void setup() throws IOException {
		dir = Files.createTempDirectory("cnameloop").toFile();
		File zone = new File(dir,"loop.test.txt");
		StringBuilder z = new StringBuilder();
		z.append("@\tIN\tSOA\tns1.loop.test. postmaster.loop.test. (\n");
		z.append("\t\t\t1 ; serial\n\t\t\t3600 ; refresh\n\t\t\t1800 ; retry\n");
		z.append("\t\t\t1209600 ; expire\n\t\t\t3600 ) ; minimum\n\n");
		z.append("\t\tNS\tns1\n");
		z.append("ns1\tIN\tA\t10.0.0.53\n");
		z.append("a\tIN\tCNAME\tb.loop.test.\n");
		z.append("b\tIN\tCNAME\ta.loop.test.\n");
		z.append("self\tIN\tCNAME\tself.loop.test.\n");
		z.append("www\tIN\tCNAME\tweb.loop.test.\n");
		z.append("web\tIN\tA\t10.0.0.80\n");
		// c1 -> c2 -> ... -> c20 -> A
		for(int i=1; i< 20; i++ ) {
			z.append("c"+i+"\tIN\tCNAME\tc"+(i+1)+".loop.test.\n");
		}
		z.append("c20\tIN\tA\t10.0.0.20\n");
		try(FileWriter w = new FileWriter(zone)) {
			w.write(z.toString());
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

	private static Message ask(String name) {
		Message q = new Message();
		q.setQuestion(name, DNS.A, DNS.IN);
		QueryData qd = new QueryData(InetAddress.getLoopbackAddress(), 5353, q);
		List<Message> ret = server.query(qd);
		assertEquals(1, ret.size());
		return ret.get(0);
	}

	private static int count(Message m, int type) {
		int ret = 0;
		for(RR rr : m.getAnswer()) {
			if( rr.getType() == type ) {
				ret++;
			}
		}
		return ret;
	}

	@Test
	public void normalCnameStillFollowed() {
		Message m = ask("www.loop.test");
		assertEquals(1, count(m,DNS.CNAME));
		assertEquals(1, count(m,DNS.A));
		for(RR rr : m.getAnswer()) {
			if( rr instanceof A ) {
				assertEquals("10.0.0.80", ((A)rr).getAddressString());
			}
		}
	}

	@Test
	public void twoNameLoopTerminates() {
		Message m = assertTimeoutPreemptively(Duration.ofSeconds(5), () -> ask("a.loop.test"));
		assertEquals(0, count(m,DNS.A));
		assertTrue(count(m,DNS.CNAME) >= 1 && count(m,DNS.CNAME) <= 2, "chain so far: "+m.getAnswer());
	}

	@Test
	public void selfLoopTerminates() {
		Message m = assertTimeoutPreemptively(Duration.ofSeconds(5), () -> ask("self.loop.test"));
		assertEquals(1, count(m,DNS.CNAME));
	}

	@Test
	public void longChainIsCut() {
		Message m = assertTimeoutPreemptively(Duration.ofSeconds(5), () -> ask("c1.loop.test"));
		// original CNAME + MAX_CNAME_CHAIN followed CNAMEs, never the A at c20
		assertEquals(QueryData.MAX_CNAME_CHAIN+1, count(m,DNS.CNAME));
		assertEquals(0, count(m,DNS.A));
	}

	@Test
	public void chainWithinLimitResolves() {
		// c13 -> ... -> c20 is 7 CNAMEs, then the A record
		Message m = ask("c13.loop.test");
		assertEquals(7, count(m,DNS.CNAME));
		assertEquals(1, count(m,DNS.A));
	}
}
