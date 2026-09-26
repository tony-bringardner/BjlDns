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
package us.bringardner.net.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.A;
import us.bringardner.net.dns.ByteBuffer;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Dnskey;
import us.bringardner.net.dns.Edns;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.Nsec;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.Rrsig;
import us.bringardner.net.dns.dnssec.Algorithm;
import us.bringardner.net.dns.dnssec.Canonical;
import us.bringardner.net.dns.dnssec.DnssecKey;
import us.bringardner.net.dns.resolve.QueryData;

/**
 * Zones signed elsewhere: the fixtures were signed by BIND's
 * dnssec-signzone (NSEC, and NSEC3 with -3 -), valid until 2046, and are
 * served with their own signatures and chain.
 */
public class TestPresignedZone {

	private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();
	private static final File FIXTURES = new File("src/test/java/resources/TestFiles/presigned");

	private DnsServer server;
	private File dir;

	@BeforeEach
	public void setup() throws IOException {
		server = new DnsServer();
		server.setRecursionAvailable(false);
		dir = Files.createTempDirectory("presigned").toFile();
		server.setDnssecKeyDir(dir);
	}

	@AfterEach
	public void cleanup() {
		for(File f : dir.listFiles()) {
			f.delete();
		}
		dir.delete();
	}

	private Zone load(String variant) throws IOException {
		Zone z = new Zone(new File(FIXTURES, variant+"/signed.test.txt"));
		server.addZone(z);
		return server.getZone("signed.test");
	}

	private Message ask(String name, int type) {
		Message q = new Message();
		q.setQuestion(name, type, DNS.IN);
		RR opt = new RR("", DNS.OPT, 1232);
		opt.setTTL(0x8000);
		opt.setRdata(new byte[0]);
		q.addAdditional(opt);
		QueryData qd = new QueryData(LOOPBACK, 5353, new Message(new ByteBuffer(q.toByteArray())));
		Message r = server.query(qd).get(0);
		Edns.applyToResponse(r, qd.getEdns());
		return new Message(new ByteBuffer(r.toByteArray()));
	}

	private List<Dnskey> keys() {
		List<Dnskey> ret = new ArrayList<Dnskey>();
		for(RR rr : server.getZone("signed.test").exactRecords("signed.test")) {
			if( rr instanceof Dnskey ) {
				ret.add((Dnskey)rr);
			}
		}
		return ret;
	}

	/** Every RRSIG verifies; @return how many */
	private int verify(Message m, String what) {
		int n = 0;
		for(List<RR> section : java.util.Arrays.asList(m.getAnswer(), m.getAuthority())) {
			Map<String, List<RR>> sets = new LinkedHashMap<String, List<RR>>();
			for(RR rr : section) {
				if( !(rr instanceof Rrsig) ) {
					sets.computeIfAbsent(Canonical.key(rr.getName())+"|"+rr.getType(), k -> new ArrayList<RR>()).add(rr);
				}
			}
			for(RR rr : section) {
				if( rr instanceof Rrsig ) {
					Rrsig s = (Rrsig)rr;
					String owner = Canonical.key(s.getName());
					String signed = owner;
					if( s.getLabels() < Canonical.labelCount(owner) ) {
						String [] l = owner.split("\\.");
						StringBuilder b = new StringBuilder("*");
						for(int i=l.length-s.getLabels(); i < l.length; i++ ) {
							b.append('.').append(l[i]);
						}
						signed = b.toString();
					}
					List<RR> set = sets.get(owner+"|"+s.getTypeCovered());
					assertNotNull(set, what+": RRSIG without RRset");
					boolean ok = false;
					for(Dnskey k : keys()) {
						ok |= Canonical.verify(s, signed, set, k);
					}
					assertTrue(ok, what+": bad signature "+s);
					n++;
				}
			}
		}
		return n;
	}

	private static long count(List<RR> list, int type) {
		return list.stream().filter(r -> r.getType() == type).count();
	}

	private void checkAnswers(String what, int denial) {
		Message m = ask("www.signed.test", DNS.A);
		assertEquals(1, count(m.getAnswer(), DNS.A));
		verify(m, what+" www");
		assertEquals(1, count(m.getAnswer(), DNS.RRSIG));
		m = ask("nope.signed.test", DNS.A);
		assertEquals(DNS.NAME_ERROR, m.getResponseCode());
		assertTrue(count(m.getAuthority(), denial) >= 2, what+": proof "+m.getAuthority());
		verify(m, what+" NXDOMAIN");
		m = ask("www.signed.test", DNS.MX);
		assertEquals(0, m.getAnswerCount());
		assertEquals(1, count(m.getAuthority(), denial));
		verify(m, what+" NODATA");
		m = ask("b.c.signed.test", DNS.A);
		assertEquals(DNS.NOERROR, m.getResponseCode(), "empty non-terminal");
		verify(m, what+" ENT");
		m = ask("x.y.wild.signed.test", DNS.A);
		assertEquals("x.y.wild.signed.test", Canonical.key(m.getAnswer().get(0).getName()));
		assertTrue(count(m.getAuthority(), denial) >= 1, "no closer name");
		verify(m, what+" wildcard");
		m = ask("host.sub.signed.test", DNS.A);
		assertFalse(m.isAuthority(), "referral");
		assertEquals(1, count(m.getAuthority(), denial), "no DS");
		verify(m, what+" referral");
		m = ask("signed.test", DNS.DNSKEY);
		verify(m, what+" DNSKEY");
		assertEquals(1, count(m.getAnswer(), DNS.RRSIG));
		m = ask("MIXED.signed.test", DNS.TXT);
		verify(m, what+" mixed case");
		assertEquals(1, count(m.getAnswer(), DNS.RRSIG));
	}

	@Test
	public void bindSignedWithNsec() throws Exception {
		Zone z = load("nsec");
		assertTrue(z.getUnsigned().isPresigned());
		SignedZone sz = z.getSigned();
		assertTrue(sz.isPresigned() && !sz.isNsec3(), sz.mode);
		assertEquals(2046, 1970+(int)(sz.getExpires()/(365.2425*24*3600)));
		assertTrue(ZoneSigner.presigned(z.getUnsigned(), System.currentTimeMillis()/1000).warnings.isEmpty(),
				"every signature verifies");
		checkAnswers("NSEC", DNS.NSEC);
	}

	@Test
	public void bindSignedWithNsec3() throws Exception {
		Zone z = load("nsec3");
		SignedZone sz = z.getSigned();
		assertTrue(sz.isPresigned() && sz.isNsec3(), sz.mode);
		assertEquals("1 0 0 -", sz.getNsec3Params().toString());
		assertTrue(ZoneSigner.presigned(z.getUnsigned(), System.currentTimeMillis()/1000).warnings.isEmpty());
		checkAnswers("NSEC3", DNS.NSEC3);
		Message m = ask("signed.test", DNS.NSEC3PARAM);
		verify(m, "NSEC3PARAM");
		assertEquals(1, count(m.getAnswer(), DNS.RRSIG));
	}

	@Test
	public void ourKeysAreNotUsedAndNothingIsResigned() throws Exception {
		DnssecKey mine = DnssecKey.generate("signed.test", Algorithm.of(13), true, 0);
		mine.save(dir);
		Zone z = load("nsec");
		SignedZone sz = z.getSigned();
		assertTrue(sz.isPresigned());
		for(List<Rrsig> l : sz.allSigs().values()) {
			for(Rrsig s : l) {
				assertTrue(s.getKeyTag() != mine.getKeyTag());
			}
		}
		assertEquals(0, server.resignDue(sz.getExpires()+1), "never signed here");
		assertTrue(server.getZone("signed.test").getSigned() == sz);
	}

	@Test
	public void updatesAreRefused() throws Exception {
		load("nsec");
		server.setUpdateAllow("127.0.0.1");
		A a = new A("new.signed.test");
		a.setAddress("10.1.1.1");
		a.setTTL(300);
		Message u = new Message();
		u.setQuestion("signed.test", DNS.SOA, DNS.IN);
		u.getHeader().setOPCODE(DNS.UPDATE);
		u.getAuthority().add(a);
		Message r = server.query(new QueryData(LOOPBACK, 5353, new Message(new ByteBuffer(u.toByteArray())))).get(0);
		assertEquals(DNS.REFUSED, r.getResponseCode());
	}

	@Test
	public void expiryWarnings() throws Exception {
		SignedZone sz = load("nsec").getSigned();
		long exp = sz.getExpires();
		assertFalse(server.warnIfExpiring(sz, exp - 4*24*3600), "more than 3 days left");
		assertTrue(server.warnIfExpiring(sz, exp - 2*24*3600));
		assertFalse(server.warnIfExpiring(sz, exp - 2*24*3600 + 3600), "not again within 6 hours");
		assertTrue(server.warnIfExpiring(sz, exp + 3600), "expired");
	}

	@Test
	public void ourOwnSignedZoneTextLoadsBack() throws Exception {
		//  Sign with our signer, write the zone out as text, load it as a presigned zone
		File zf = new File(dir, "own.test.txt");
		try(FileWriter w = new FileWriter(zf)) {
			w.write("$TTL 300\n@ IN SOA ns1 h ( 1 3600 900 1209600 60 )\n NS ns1\nns1 A 10.0.0.1\nwww A 10.0.0.2\n*.w TXT \"x\"\n");
		}
		DnssecKey k = DnssecKey.generate("own.test", Algorithm.of(13), true, 0);
		ZoneSigner.Result signed = ZoneSigner.sign(new Zone(zf), new java.util.HashMap<String, List<? extends RR>>(), "",
				java.util.Collections.singletonList(k), System.currentTimeMillis()/1000, 86400);
		StringBuilder text = new StringBuilder(";  written by the test\n");
		Zone sz = signed.zone;
		text.append(Zone.recordLine(sz.getSoa())).append('\n');
		for(List<RR> list : sz.getRrs()) {
			for(RR rr : list) {
				text.append(Zone.recordLine(rr)).append('\n');
			}
		}
		for(List<Rrsig> list : sz.getSigned().allSigs().values()) {
			for(Rrsig s : list) {
				text.append(Zone.recordLine(s)).append('\n');
			}
		}
		File out = new File(dir, "presigned");
		out.mkdir();
		File pf = new File(out, "own.test.txt");
		Files.write(pf.toPath(), text.toString().getBytes("UTF-8"));
		try {
			Zone back = new Zone(pf);
			assertTrue(back.isPresigned());
			assertTrue(ZoneSigner.presigned(back, System.currentTimeMillis()/1000).warnings.isEmpty(), "all verify");
			assertEquals(sz.getSigned().rrsigCount, back.getPresignedSigs().size());
		} finally {
			pf.delete();
			out.delete();
		}
	}

	@Test
	public void incompleteDnssecDataIsRejected() throws Exception {
		File zf = new File(dir, "half.test.txt");
		try(FileWriter w = new FileWriter(zf)) {
			w.write("@ IN SOA ns1 h ( 1 3600 900 1209600 60 )\n NS ns1\nns1 A 10.0.0.1\n"
					+"@ DNSKEY 257 3 13 AAAA\n");
		}
		IOException ex = assertThrows(IOException.class, () -> new Zone(zf));
		assertTrue(ex.getMessage().contains("no RRSIG"), ex.getMessage());
	}

	@Test
	public void recordTextFormats() {
		assertEquals(1700000000L, PresignedRecords.time("1700000000"));
		assertEquals(1700000000L, PresignedRecords.time("20231114221320"));
		assertEquals(65534, PresignedRecords.typeCode("TYPE65534"));
		assertEquals(DNS.CAA, PresignedRecords.typeCode("caa"));
		assertEquals(DNS.NSEC3PARAM, PresignedRecords.typeCode("NSEC3PARAM"));
		assertThrows(IllegalArgumentException.class, () -> PresignedRecords.typeCode("NOPE"));
		Nsec n = (Nsec)PresignedRecords.parse(DNS.NSEC, "a.test", DNS.IN,
				java.util.Arrays.asList("B.test.", "A", "RRSIG", "NSEC", "TYPE65534"), x -> x.endsWith(".") ? x.substring(0, x.length()-1) : x+".test");
		assertEquals("B.test", n.getNext(), "case kept (RFC 6840 5.1)");
		assertTrue(n.hasType(65534));
	}
}
