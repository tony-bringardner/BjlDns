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
 *
 */
package us.bringardner.net.dns.resolve;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Files;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;
import java.util.function.UnaryOperator;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.A;
import us.bringardner.net.dns.ByteBuffer;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Ds;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.Section;
import us.bringardner.net.dns.dnssec.Algorithm;
import us.bringardner.net.dns.dnssec.DnssecKey;
import us.bringardner.net.dns.dnssec.Nsec3Params;
import us.bringardner.net.dns.server.DnsServer;
import us.bringardner.net.dns.server.Zone;

/**
 * The validator against a small signed hierarchy served in process: test.
 * (the trust anchor) delegates to a signed zone, an NSEC3 zone, an unsigned
 * zone and a zone whose DS points at the wrong key.
 */
public class TestValidator {

	private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();

	private File dir;
	private DnsServer server;
	private DnssecKey anchorKey;
	private final AtomicLong now = new AtomicLong(System.currentTimeMillis()/1000);
	private final AtomicInteger fetches = new AtomicInteger();
	//  Changes answers on their way to the validator (an attacker)
	private volatile UnaryOperator<Message> tamper = UnaryOperator.identity();

	private static void zone(File dir, String name, String text) throws IOException {
		try(FileWriter w = new FileWriter(new File(dir, name+".txt"))) {
			w.write("$TTL 3600\n@ IN SOA ns1."+name+". h ( 1 3600 900 1209600 300 )\n NS ns1."+name+".\n"+text);
		}
	}

	private static DnssecKey key(File dir, String zone) throws Exception {
		DnssecKey k = DnssecKey.generate(zone, Algorithm.of(Algorithm.ECDSAP256SHA256), true, 0);
		k.save(dir);
		return k;
	}

	/** A server for the hierarchy (keys and zone files in dir). @return the trust anchor key of test. */
	static DnssecKey hierarchy(File dir, DnsServer server) throws Exception {
		DnssecKey anchor = key(dir, "test");
		DnssecKey sec = key(dir, "sec.test");
		DnssecKey n3 = key(dir, "n3.test");
		key(dir, "bogus.test");
		DnssecKey notUsed = DnssecKey.generate("bogus.test", Algorithm.of(13), true, 0);
		zone(dir, "test", "ns1 A 10.0.0.1\n"
				+"sec NS ns1.sec\nsec DS "+sec.toDs(Ds.SHA256, 3600).getRdataAsString()+"\n"
				+"n3 NS ns1.n3\nn3 DS "+n3.toDs(Ds.SHA256, 3600).getRdataAsString()+"\n"
				+"bogus NS ns1.bogus\nbogus DS "+notUsed.toDs(Ds.SHA256, 3600).getRdataAsString()+"\n"
				+"insecure NS ns1.insecure\n");
		zone(dir, "sec.test", "ns1 A 10.0.0.2\nwww A 10.0.0.80\nwww AAAA 2001:db8::80\n*.wild A 10.0.0.99\na.b.c A 10.0.0.1\n"
				+"alias CNAME www\nout CNAME www.insecure.test.\nsub NS ns.sub\nns.sub A 10.0.0.9\n");
		zone(dir, "n3.test", "ns1 A 10.0.0.3\nwww A 10.0.1.80\n*.wild TXT \"w\"\nx.y A 10.0.1.1\n");
		zone(dir, "insecure.test", "ns1 A 10.0.0.4\nwww A 10.0.2.80\n");
		zone(dir, "bogus.test", "ns1 A 10.0.0.5\nwww A 10.0.3.80\n");
		server.setRecursionAvailable(false);
		server.setDnssecKeyDir(dir);
		server.setDnssecNsec3("n3.test", Nsec3Params.DEFAULT);
		for(String z : new String[] {"test", "sec.test", "n3.test", "insecure.test", "bogus.test"}) {
			server.addZone(new Zone(new File(dir, z+".txt")));
		}
		return anchor;
	}

	@BeforeEach
	public void setup() throws Exception {
		dir = Files.createTempDirectory("validator").toFile();
		server = new DnsServer();
		anchorKey = hierarchy(dir, server);
	}

	@AfterEach
	public void cleanup() {
		for(File f : dir.listFiles()) {
			f.delete();
		}
		dir.delete();
	}

	/** Ask the server with DO, as the resolver does. */
	private Message ask(Section q) {
		fetches.incrementAndGet();
		Message m = new Message();
		m.setQuestion(q.getName(), q.getType(), DNS.IN);
		m.addAdditional(us.bringardner.net.dns.Edns.newOpt(0, true));
		List<Message> r = server.query(new us.bringardner.net.dns.resolve.QueryData(LOOPBACK, 5353, new Message(new ByteBuffer(m.toByteArray()))));
		Message back = new Message(new ByteBuffer(r.get(0).toByteArray()));
		return tamper.apply(back);
	}

	private Validator validator() {
		Function<Section, Message> f = this::ask;
		return new Validator(f, now::get, Validator.parseAnchors(anchorKey.toDs(Ds.SHA256, 0).getName()+". IN DS "
				+anchorKey.toDs(Ds.SHA256, 0).getRdataAsString()), 1000);
	}

	private Validator.Result check(Validator v, String name, int type) {
		Section q = new Section(name, type, DNS.IN);
		Message m = ask(q);
		return v.validate(m, q);
	}

	private void expect(Validator v, Validator.Status s, String name, int type) {
		Validator.Result r = check(v, name, type);
		assertEquals(s, r.status, name+" "+DNS.TYPENAMES[type]+": "+r);
	}

	@Test
	public void secureAnswers() {
		Validator v = validator();
		expect(v, Validator.Status.SECURE, "www.sec.test", DNS.A);
		expect(v, Validator.Status.SECURE, "WWW.Sec.Test", DNS.AAAA);
		expect(v, Validator.Status.SECURE, "sec.test", DNS.DNSKEY);
		expect(v, Validator.Status.SECURE, "sec.test", DNS.DS);
		expect(v, Validator.Status.SECURE, "test", DNS.SOA);
		expect(v, Validator.Status.SECURE, "alias.sec.test", DNS.A);
		expect(v, Validator.Status.SECURE, "x.y.wild.sec.test", DNS.A);
		expect(v, Validator.Status.SECURE, "www.n3.test", DNS.A);
		expect(v, Validator.Status.SECURE, "q.wild.n3.test", DNS.TXT);
	}

	@Test
	public void secureDenials() {
		Validator v = validator();
		expect(v, Validator.Status.SECURE, "nope.sec.test", DNS.A);
		expect(v, Validator.Status.SECURE, "a.b.nope.sec.test", DNS.A);
		expect(v, Validator.Status.SECURE, "www.sec.test", DNS.MX);
		expect(v, Validator.Status.SECURE, "b.c.sec.test", DNS.A);
		expect(v, Validator.Status.SECURE, "x.wild.sec.test", DNS.MX);
		expect(v, Validator.Status.SECURE, "nope.n3.test", DNS.A);
		expect(v, Validator.Status.SECURE, "www.n3.test", DNS.MX);
		expect(v, Validator.Status.SECURE, "y.n3.test", DNS.A);
		expect(v, Validator.Status.SECURE, "z.wild.n3.test", DNS.A);
		expect(v, Validator.Status.SECURE, "nope.test", DNS.A);
	}

	@Test
	public void insecureDelegations() {
		Validator v = validator();
		expect(v, Validator.Status.INSECURE, "www.insecure.test", DNS.A);
		expect(v, Validator.Status.INSECURE, "nope.insecure.test", DNS.A);
		expect(v, Validator.Status.INSECURE, "host.sub.sec.test", DNS.A);
		//  A secure CNAME into an unsigned zone: insecure as a whole
		expect(v, Validator.Status.INSECURE, "out.sec.test", DNS.A);
		//  No trust anchor above it
		assertEquals(Validator.Status.INSECURE, v.validate(new Message(), new Section("www.example.org", DNS.A, DNS.IN)).status);
	}

	@Test
	public void bogusAnswers() {
		Validator v = validator();
		Validator.Result r = check(v, "www.bogus.test", DNS.A);
		assertEquals(Validator.Status.BOGUS, r.status, r.toString());
		assertTrue(r.why.contains("not signed by a key its DS points to"), r.why);
		//  A changed address
		tamper = m -> {
			for(RR rr : m.getAnswer()) {
				if( rr instanceof A ) {
					((A)rr).setAddress("192.0.2.66");
				}
			}
			return m;
		};
		expect(v, Validator.Status.BOGUS, "www.sec.test", DNS.A);
		//  Signatures removed
		tamper = m -> {
			m.getAnswer().removeIf(rr -> rr.getType() == DNS.RRSIG);
			return m;
		};
		expect(v, Validator.Status.BOGUS, "www.sec.test", DNS.A);
		//  A made up NXDOMAIN without its proof
		tamper = m -> {
			if( m.getFirstQuestion().getName().equalsIgnoreCase("www.sec.test") ) {
				m.getAnswer().clear();
				m.setResponseCode(DNS.NAME_ERROR);
			}
			return m;
		};
		expect(v, Validator.Status.BOGUS, "www.sec.test", DNS.A);
		//  The proof of an unsigned delegation removed: can't be trusted either
		tamper = m -> {
			m.getAuthority().removeIf(rr -> rr.getType() == DNS.NSEC || rr.getType() == DNS.RRSIG);
			return m;
		};
		validatorFresh(Validator.Status.BOGUS, "www.insecure.test", DNS.A);
	}

	private void validatorFresh(Validator.Status s, String name, int type) {
		expect(validator(), s, name, type);
	}

	@Test
	public void expiredSignaturesAreBogus() {
		Validator v = validator();
		expect(v, Validator.Status.SECURE, "www.sec.test", DNS.A);
		now.addAndGet(30L*24*3600);
		v.clear();
		expect(v, Validator.Status.BOGUS, "www.sec.test", DNS.A);
		now.set(System.currentTimeMillis()/1000 - 2*3600);
		expect(validator(), Validator.Status.BOGUS, "www.sec.test", DNS.A);
	}

	@Test
	public void keysAreCached() {
		Validator v = validator();
		expect(v, Validator.Status.SECURE, "www.sec.test", DNS.A);
		int after = fetches.get();
		for(int i=0; i < 10; i++ ) {
			expect(v, Validator.Status.SECURE, "www.sec.test", DNS.A);
		}
		assertEquals(after+10, fetches.get(), "only the answers themselves are fetched again");
		//  They expire with the TTLs
		now.addAndGet(2*3600);
		expect(v, Validator.Status.SECURE, "www.sec.test", DNS.A);
		assertTrue(fetches.get() > after+11);
	}

	@Test
	public void trustAnchorFormats() {
		List<Ds> root = Validator.rootAnchors();
		assertEquals(2, root.size());
		assertEquals(20326, root.get(0).getKeyTag());
		assertEquals(38696, root.get(1).getKeyTag());
		assertEquals("", root.get(0).getName());
		//  A DNSKEY anchor (as in BIND's root.key) becomes its DS
		String key = "test. 3600 IN DNSKEY "+anchorKey.getDnskey().getRdataAsString()+" ; comment";
		List<Ds> a = Validator.parseAnchors("; anchors\n"+key+"\n");
		assertEquals(1, a.size());
		assertEquals(anchorKey.getKeyTag(), a.get(0).getKeyTag());
		assertEquals(anchorKey.toDs(Ds.SHA256, 0).getDigestHex(), a.get(0).getDigestHex());
	}

	@Test
	public void builtInRootAnchorsMatchTheRootKeys() {
		//  The root zone's KSK-2017 and KSK-2024 as published (IANA, BIND's root.key)
		String keys = ". IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU= ; keytag 20326\n"
				+". IN DNSKEY 257 3 8 AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc= ; keytag 38696\n";
		List<Ds> fromKeys = Validator.parseAnchors(keys);
		List<Ds> builtIn = Validator.rootAnchors();
		assertEquals(2, fromKeys.size());
		for(int i=0; i < 2; i++ ) {
			assertEquals(builtIn.get(i).getRdataAsString(), fromKeys.get(i).getRdataAsString());
		}
	}

	@Test
	public void unsupportedAlgorithmIsInsecure() throws Exception {
		//  A DS with an algorithm we don't know (RFC 4035 5.2)
		File f = new File(dir, "test.txt");
		String text = new String(Files.readAllBytes(f.toPath()), "UTF-8")
				.replaceAll("sec DS (\\d+) 13 ", "sec DS $1 253 ");
		Files.write(f.toPath(), text.getBytes("UTF-8"));
		server.addZone(new Zone(f));
		expect(validator(), Validator.Status.INSECURE, "www.sec.test", DNS.A);
	}

	@Test
	public void helpers() {
		assertEquals("b.c", Validator.lastLabels("a.b.c", 2));
		assertEquals("", Validator.lastLabels("a.b.c", 0));
		assertEquals("x.sec.test", Validator.nextCloser("a.b.x.sec.test", "sec.test"));
		assertEquals("sec.test", Validator.parent("www.sec.test"));
		assertEquals("", Validator.parent("test"));
	}
}
