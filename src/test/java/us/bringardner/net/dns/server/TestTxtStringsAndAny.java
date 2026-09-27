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
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.ByteBuffer;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.Soa;
import us.bringardner.net.dns.Txt;
import us.bringardner.net.dns.resolve.QueryData;

/**
 * TXT records keep all their character-strings (a zone file line kept only
 * the first), ANY at a zone apex includes the SOA (it was left out), and
 * only the apex answers an SOA query.
 */
public class TestTxtStringsAndAny {

	private static File dir;
	private static DnsServer server;

	@BeforeAll
	public static void setup() throws IOException {
		dir = Files.createTempDirectory("txtany").toFile();
		write(new File(dir,"txt.test.txt"), "$TTL 3600\n"
				+"@\tIN\tSOA\tns1.txt.test. hostmaster.txt.test. ( 7 3600 1800 1209600 300 )\n"
				+"\tIN\tNS\tns1\n"
				+"\tIN\tMX\t10 mail\n"
				+"\tIN\tTXT\t\"v=spf1 -all\"\n"
				+"ns1\tIN\tA\t10.0.0.53\n"
				+"mail\tIN\tA\t10.0.0.25\n"
				+"two\tIN\tTXT\t\"hello world\" \"second\"\n"
				+"esc\tIN\tTXT\t\"say \\\"hi\\\"\" \"back\\\\slash\" \"semi;colon\" \"tab\\009x\" \"caf\\195\\169\" \"\"\n"
				+"uni\tIN\tTXT\t\"café ☕\"\n"
				+"bare\tIN\tTXT\tv=spf1 -all ; unquoted words are strings too\n"
				+"paren\tIN\tTXT\t( \"one\"\n\t\t\"two\" )\n"
				+"spf\tIN\tSPF\t\"v=spf1\" \"-all\"\n"
				+"long\tIN\tTXT\t\""+repeat('x', 300)+"\"\n"
				+"www\tIN\tA\t10.0.0.80\n");
		write(new File(dir,"bare.test.txt"), "$TTL 3600\n"
				+"@\tIN\tSOA\tns1.bare.test. hostmaster.bare.test. ( 1 3600 1800 1209600 300 )\n");
		server = new DnsServer();
		server.addZone(new Zone(new File(dir,"txt.test.txt")));
		server.addZone(new Zone(new File(dir,"bare.test.txt")));
		server.setRecursionAvailable(false);
	}

	private static void write(File f, String text) throws IOException {
		try(Writer w = new OutputStreamWriter(new FileOutputStream(f), StandardCharsets.UTF_8)) {
			w.write(text);
		}
	}

	private static String repeat(char c, int n) {
		char [] a = new char[n];
		Arrays.fill(a, c);
		return new String(a);
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

	private static List<String> strings(String name) {
		Message m = ask(name, DNS.TXT);
		assertEquals(DNS.NOERROR, m.getResponseCode(), name);
		assertEquals(1, m.getAnswerCount(), name+" "+m.getAnswer());
		return ((Txt)m.getAnswer().get(0)).getStrings();
	}

	@Test
	public void everyStringIsKept() {
		assertEquals("[hello world, second]", strings("two.txt.test").toString());
		assertEquals("[v=spf1, -all]", strings("bare.txt.test").toString(), "unquoted words are separate strings (as BIND)");
		assertEquals("[one, two]", strings("paren.txt.test").toString());
		assertEquals("[v=spf1 -all]", strings("txt.test").toString());
		Message m = ask("spf.txt.test", DNS.SPF);
		assertEquals("[v=spf1, -all]", ((Txt)m.getAnswer().get(0)).getStrings().toString());
	}

	@Test
	public void escapesAndUtf8() {
		assertEquals(Arrays.asList("say \"hi\"", "back\\slash", "semi;colon", "tab\tx", "café", ""), strings("esc.txt.test"));
		assertEquals(Arrays.asList("café ☕"), strings("uni.txt.test"), "UTF-8 text is not encoded twice");
		//  On the wire: \195\169 is two bytes
		Message m = ask("esc.txt.test", DNS.TXT);
		byte [] rdata = m.getAnswer().get(0).getRdata();
		byte [] expect = {8,'s','a','y',' ','"','h','i','"', 10,'b','a','c','k','\\','s','l','a','s','h',
				10,'s','e','m','i',';','c','o','l','o','n', 5,'t','a','b',9,'x', 5,'c','a','f',(byte)0xc3,(byte)0xa9, 0};
		assertEquals(Arrays.toString(expect), Arrays.toString(rdata));
	}

	@Test
	public void longStringsAreSplitAt255Bytes() {
		List<String> s = strings("long.txt.test");
		assertEquals(2, s.size());
		assertEquals(255, s.get(0).length());
		assertEquals(repeat('x', 300), String.join("", s));
		//  UTF-8: never split inside a character
		Txt t = new Txt("x.test");
		t.setText(repeat('é', 200));
		assertEquals(Arrays.asList(repeat('é', 127), repeat('é', 73)), t.getStrings());
		assertEquals(repeat('é', 200), t.getText());
	}

	@Test
	public void zoneFileTextRoundTrips() {
		//  The journal and AXFR write records with Zone.recordLine; the reader must get them back
		Message m = ask("esc.txt.test", DNS.TXT);
		RR rr = m.getAnswer().get(0);
		String line = Zone.rdataText(rr);
		assertEquals("\"say \\\"hi\\\"\" \"back\\\\slash\" \"semi;colon\" \"tab\\009x\" \"café\" \"\"", line);
		List<String> fields = new ArrayList<String>();
		fields.add("esc");
		fields.add("3600");
		fields.add("TXT");
		//  (as the zone reader splits a line: one field per string, quotes removed, escapes kept)
		for(String f : new String[] {"say \\\"hi\\\"", "back\\\\slash", "semi;colon", "tab\\009x", "cafÃ©", ""}) {
			fields.add(f);
		}
		assertEquals(((Txt)rr).getStrings(), Zone.characterStrings(fields, 3));
	}

	@Test
	public void anyAtTheApexIncludesTheSoa() {
		Message m = ask("txt.test", DNS.QTYPE_ALL);
		assertEquals(DNS.NOERROR, m.getResponseCode());
		List<Integer> types = new ArrayList<Integer>();
		for(RR rr : m.getAnswer()) {
			types.add(rr.getType());
		}
		assertTrue(types.contains(DNS.SOA), "SOA in "+m.getAnswer());
		assertTrue(types.contains(DNS.NS) && types.contains(DNS.MX) && types.contains(DNS.TXT), m.getAnswer().toString());
		assertEquals(1, types.stream().filter(t -> t == DNS.SOA).count());
		Soa soa = null;
		for(RR rr : m.getAnswer()) {
			if( rr instanceof Soa ) {
				soa = (Soa) rr;
			}
		}
		assertEquals(7, soa.getSerial());
		assertEquals("txt.test", soa.getName());
	}

	@Test
	public void anyElsewhereHasNoSoa() {
		Message m = ask("www.txt.test", DNS.QTYPE_ALL);
		assertEquals(1, m.getAnswerCount(), m.getAnswer().toString());
		assertEquals(DNS.A, m.getAnswer().get(0).getType());
	}

	@Test
	public void soaOnlyAtTheApex() {
		//  An SOA query for a name below the apex gets NODATA (or NXDOMAIN) with
		//  the zone's SOA in the authority section; it used to get an SOA named
		//  after itself, so nsupdate took www.txt.test for a zone
		Message m = ask("www.txt.test", DNS.SOA);
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertEquals(0, m.getAnswerCount());
		assertEquals("txt.test", m.getAuthority().get(0).getName());
		assertEquals(DNS.SOA, m.getAuthority().get(0).getType());
		m = ask("nope.txt.test", DNS.SOA);
		assertEquals(DNS.NAME_ERROR, m.getResponseCode());
		assertEquals("txt.test", m.getAuthority().get(0).getName());
		m = ask("txt.test", DNS.SOA);
		assertEquals("txt.test", m.getAnswer().get(0).getName());
	}

	@Test
	public void apexWithOnlyAnSoa() {
		//  The apex exists: ANY gets the SOA (it was NXDOMAIN) and other types NODATA
		Message m = ask("bare.test", DNS.QTYPE_ALL);
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertEquals(1, m.getAnswerCount());
		assertEquals(DNS.SOA, m.getAnswer().get(0).getType());
		m = ask("bare.test", DNS.SOA);
		assertEquals(DNS.SOA, m.getAnswer().get(0).getType());
	}
}
