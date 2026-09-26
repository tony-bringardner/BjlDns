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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
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
import us.bringardner.net.dns.Ds;
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
 * A signed zone served with DNSSEC (RFC 4033-4035): every answer to a DO
 * query is checked the way a validator would, signatures and NSEC proofs.
 * (BIND's delv, dnssec-verify and ldns-verify-zone agreed with these
 * answers; see the rec #44 notes.)
 */
public class TestDnssecServer {

	private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();

	private File dir;
	private File zoneFile;
	private DnsServer server;
	private DnssecKey ksk;
	private DnssecKey zsk;
	private String childDs;

	private static String zoneText(int serial, String ds) {
		return "$TTL 3600\n"
				+"@\tIN\tSOA\tns1 hostmaster ( "+serial+" 3600 900 1209600 300 )\n"
				+"\tNS\tns1\n"
				+"\tMX\t10 mail\n"
				+"ns1\tA\t127.0.0.1\n"
				+"mail\tA\t10.0.0.25\n"
				+"www\tA\t10.0.0.80\n"
				+"www\tAAAA\t2001:db8::80\n"
				+"alias\tCNAME\twww\n"
				+"*.wild\tA\t10.0.0.99\n"
				+"*.wild\tTXT\t\"wildcard\"\n"
				+"a.b.c\tA\t10.0.0.1\n"
				+"secure\tNS\tns.secure\n"
				+"secure\tDS\t"+ds+"\n"
				+"ns.secure\tA\t10.0.0.53\n"
				+"insecure\tNS\tns.insecure\n"
				+"ns.insecure\tA\t10.0.0.54\n";
	}

	@BeforeEach
	public void setup() throws Exception {
		dir = Files.createTempDirectory("dnssec").toFile();
		ksk = DnssecKey.generate("sec.test", Algorithm.of(Algorithm.ECDSAP256SHA256), true, 0);
		zsk = DnssecKey.generate("sec.test", Algorithm.of(Algorithm.ECDSAP256SHA256), false, 0);
		ksk.save(dir);
		zsk.save(dir);
		DnssecKey child = DnssecKey.generate("secure.sec.test", Algorithm.of(Algorithm.ECDSAP256SHA256), true, 0);
		childDs = child.toDs(Ds.SHA256, 3600).getRdataAsString();
		zoneFile = new File(dir, "sec.test.txt");
		write(zoneFile, zoneText(100, childDs));
		server = new DnsServer();
		server.setRecursionAvailable(false);
		server.setDnssecKeyDir(dir);
		server.addZone(new Zone(zoneFile));
	}

	@AfterEach
	public void cleanup() {
		for(File f : dir.listFiles()) {
			f.delete();
		}
		dir.delete();
	}

	private static void write(File f, String text) throws IOException {
		try(FileWriter w = new FileWriter(f)) {
			w.write(text);
		}
	}

	private Zone zone() {
		return server.getZone("sec.test");
	}

	/** Ask (in process, through the wire format both ways), with or without the DO bit. */
	private Message ask(String name, int type, boolean dnssecOk) {
		Message q = new Message();
		q.setQuestion(name, type, DNS.IN);
		RR opt = new RR("", DNS.OPT, 1232);
		opt.setTTL(dnssecOk ? 0x8000 : 0);
		opt.setRdata(new byte[0]);
		q.addAdditional(opt);
		Message in = new Message(new ByteBuffer(q.toByteArray()));
		QueryData qd = new QueryData(LOOPBACK, 5353, in);
		Message r = server.query(qd).get(0);
		Edns.applyToResponse(r, qd.getEdns());
		return new Message(new ByteBuffer(r.toByteArray()));
	}

	private Message ask(String name, int type) {
		return ask(name, type, true);
	}

	// ------------------------------------------------------------ a validator's checks

	private List<Dnskey> keys() {
		List<Dnskey> ret = new ArrayList<Dnskey>();
		ret.add(ksk.getDnskey());
		ret.add(zsk.getDnskey());
		return ret;
	}

	private static List<RR> of(List<RR> section, String owner, int type) {
		List<RR> ret = new ArrayList<RR>();
		for(RR rr : section) {
			if( rr.getType() == type && Canonical.key(rr.getName()).equals(Canonical.key(owner)) ) {
				ret.add(rr);
			}
		}
		return ret;
	}

	/**
	 * Every RRSIG in the section verifies over its RRset (with the wildcard
	 * owner when the labels field says so), and every RRset of the signed
	 * zone except delegation NS and glue has one.
	 *
	 * @return the owners that were wildcard expansions
	 */
	private List<String> verifySection(List<RR> section, String what) {
		long now = System.currentTimeMillis()/1000;
		Map<String, List<RR>> sets = new LinkedHashMap<String, List<RR>>();
		List<Rrsig> sigs = new ArrayList<Rrsig>();
		for(RR rr : section) {
			if( rr instanceof Rrsig ) {
				sigs.add((Rrsig)rr);
			} else if( rr.getType() != DNS.OPT ) {
				sets.computeIfAbsent(Canonical.key(rr.getName())+"|"+rr.getType(), k -> new ArrayList<RR>()).add(rr);
			}
		}
		List<String> wild = new ArrayList<String>();
		java.util.Set<String> signed = new java.util.HashSet<String>();
		for(Rrsig s : sigs) {
			String owner = Canonical.key(s.getName());
			List<RR> set = sets.get(owner+"|"+s.getTypeCovered());
			assertNotNull(set, what+": RRSIG without its RRset: "+s);
			String signedOwner = owner;
			String [] labels = owner.split("\\.");
			if( s.getLabels() < Canonical.labelCount(owner) ) {
				StringBuilder b = new StringBuilder("*");
				for(int i=labels.length-s.getLabels(); i < labels.length; i++ ) {
					b.append('.').append(labels[i]);
				}
				signedOwner = b.toString();
				wild.add(owner);
			}
			boolean ok = false;
			for(Dnskey k : keys()) {
				ok |= Canonical.verify(s, signedOwner, set, k);
			}
			assertTrue(ok, what+": signature does not verify: "+s);
			assertTrue(s.getInception() <= now && now < s.getExpiration(), what+": signature not valid now");
			assertEquals("sec.test", s.getSigner());
			assertTrue(s.getTTL() <= set.get(0).getTTL(), what+": RRSIG TTL above the RRset's");
			signed.add(owner+"|"+s.getTypeCovered());
		}
		for(String k : sets.keySet()) {
			String owner = k.substring(0, k.indexOf('|'));
			int type = Integer.parseInt(k.substring(k.indexOf('|')+1));
			//  The delegations secure and insecure: their NS and the glue below them are not signed
			boolean glueOrCut = (owner.equals("secure.sec.test") || owner.endsWith(".secure.sec.test")
					|| owner.equals("insecure.sec.test") || owner.endsWith(".insecure.sec.test")) && type != DNS.DS && type != DNS.NSEC;
			if( Canonical.isBelow(owner, "sec.test", true) && !glueOrCut ) {
				assertTrue(signed.contains(k), what+": unsigned RRset "+k);
			}
		}
		return wild;
	}

	private List<String> verify(Message m, String what) {
		List<String> wild = verifySection(m.getAnswer(), what);
		verifySection(m.getAuthority(), what);
		verifySection(m.getAdditional(), what);
		return wild;
	}

	private static List<Nsec> nsecs(Message m) {
		List<Nsec> ret = new ArrayList<Nsec>();
		for(RR rr : m.getAuthority()) {
			if( rr instanceof Nsec ) {
				ret.add((Nsec)rr);
			}
		}
		return ret;
	}

	/** Does this NSEC prove that name does not exist? */
	private static boolean covers(Nsec n, String name) {
		String owner = n.getName();
		String next = n.getNext();
		boolean last = Canonical.compareNames(next, owner) <= 0;
		return Canonical.compareNames(owner, name) < 0 && (last || Canonical.compareNames(name, next) < 0);
	}

	private static boolean anyCovers(Message m, String name) {
		for(Nsec n : nsecs(m)) {
			if( covers(n, name) ) {
				return true;
			}
		}
		return false;
	}

	private static Nsec nsecAt(Message m, String name) {
		for(Nsec n : nsecs(m)) {
			if( Canonical.key(n.getName()).equals(Canonical.key(name)) ) {
				return n;
			}
		}
		return null;
	}

	private static int count(List<RR> list, int type) {
		int n = 0;
		for(RR rr : list) {
			if( rr.getType() == type ) {
				n++;
			}
		}
		return n;
	}

	private static boolean optDo(Message m) {
		for(RR rr : m.getAdditional()) {
			if( rr.getType() == DNS.OPT ) {
				return (rr.getTTL() & 0x8000) != 0;
			}
		}
		return false;
	}

	// ------------------------------------------------------------ tests

	@Test
	public void signaturesOnlyWhenAskedFor() {
		Message plain = ask("www.sec.test", DNS.A, false);
		assertEquals(1, plain.getAnswerCount());
		assertEquals(0, count(plain.getAnswer(), DNS.RRSIG));
		assertFalse(optDo(plain));
		Message signed = ask("www.sec.test", DNS.A, true);
		assertEquals(1, count(signed.getAnswer(), DNS.A));
		assertEquals(1, count(signed.getAnswer(), DNS.RRSIG), "signed by the ZSK only");
		assertTrue(optDo(signed), "DO bit copied to the response");
		assertTrue(signed.isAuthority());
		verify(signed, "www A");
		assertEquals(zsk.getKeyTag(), ((Rrsig)of(signed.getAnswer(), "www.sec.test", DNS.RRSIG).get(0)).getKeyTag());
	}

	@Test
	public void positiveAnswersVerify() {
		for(Object [] q : new Object[][] {{"www.sec.test", DNS.AAAA}, {"sec.test", DNS.MX}, {"sec.test", DNS.NS},
				{"sec.test", DNS.SOA}, {"WWW.Sec.Test", DNS.A}, {"alias.sec.test", DNS.A}, {"a.b.c.sec.test", DNS.A},
				{"sec.test", DNS.QTYPE_ALL}}) {
			Message m = ask((String)q[0], (Integer)q[1]);
			assertEquals(DNS.NOERROR, m.getResponseCode(), q[0]+" "+q[1]);
			assertTrue(m.getAnswerCount() > 0, q[0]+" "+q[1]);
			assertTrue(verify(m, q[0]+" "+q[1]).isEmpty(), "no wildcard");
		}
		//  The CNAME and its target both signed
		Message m = ask("alias.sec.test", DNS.A);
		assertEquals(1, count(m.getAnswer(), DNS.CNAME));
		assertEquals(1, count(m.getAnswer(), DNS.A));
		assertEquals(2, count(m.getAnswer(), DNS.RRSIG));
	}

	@Test
	public void dnskeySetSignedByTheKsk() {
		Message m = ask("sec.test", DNS.DNSKEY);
		assertEquals(2, count(m.getAnswer(), DNS.DNSKEY));
		List<RR> sigs = of(m.getAnswer(), "sec.test", DNS.RRSIG);
		assertEquals(1, sigs.size());
		assertEquals(ksk.getKeyTag(), ((Rrsig)sigs.get(0)).getKeyTag());
		assertTrue(Canonical.verify((Rrsig)sigs.get(0), "sec.test", of(m.getAnswer(), "sec.test", DNS.DNSKEY), ksk.getDnskey()));
		verify(m, "DNSKEY");
	}

	@Test
	public void nxdomainIsProven() {
		for(String name : new String[] {"nope.sec.test", "x.nope.sec.test", "zzz.sec.test", "0.sec.test"}) {
			Message m = ask(name, DNS.A);
			assertEquals(DNS.NAME_ERROR, m.getResponseCode(), name);
			verify(m, name);
			assertTrue(anyCovers(m, name), name+": an NSEC covers the name");
			assertTrue(anyCovers(m, "*.sec.test") || anyCovers(m, "*."+name.substring(name.indexOf('.')+1)), name+": and the wildcard");
			assertEquals(1, count(m.getAuthority(), DNS.SOA));
		}
	}

	@Test
	public void nodataIsProven() {
		Message m = ask("www.sec.test", DNS.MX);
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertEquals(0, m.getAnswerCount());
		Nsec n = nsecAt(m, "www.sec.test");
		assertNotNull(n);
		assertTrue(n.hasType(DNS.A) && n.hasType(DNS.AAAA) && !n.hasType(DNS.MX), n.toString());
		verify(m, "www MX");
		//  An empty non-terminal (b.c has a.b.c below it) exists: NODATA, not NXDOMAIN
		for(String ent : new String[] {"b.c.sec.test", "c.sec.test", "wild.sec.test"}) {
			m = ask(ent, DNS.A);
			assertEquals(DNS.NOERROR, m.getResponseCode(), ent);
			assertTrue(anyCovers(m, ent), ent);
			verify(m, ent);
		}
		//  SOA at a name other than the apex: NODATA in a signed zone
		m = ask("www.sec.test", DNS.SOA);
		assertEquals(0, m.getAnswerCount());
		assertNotNull(nsecAt(m, "www.sec.test"));
		verify(m, "www SOA");
	}

	@Test
	public void wildcardAnswersAndProofs() {
		for(String name : new String[] {"x.wild.sec.test", "a.b.wild.sec.test"}) {
			Message m = ask(name, DNS.A);
			assertEquals(DNS.NOERROR, m.getResponseCode(), name);
			assertEquals(name, Canonical.key(m.getAnswer().get(0).getName()), "owner is the query name");
			assertEquals("[10.0.0.99]", String.valueOf(addresses(m)));
			assertEquals(1, count(m.getAnswer(), DNS.RRSIG));
			assertEquals("["+name+"]", verify(m, name).toString(), "signed as *.wild.sec.test");
			assertTrue(anyCovers(m, name), name+": no closer name");
			assertEquals(0, count(m.getAnswer(), DNS.NSEC), "the wildcard's NSEC is not copied");
		}
		//  NODATA from the wildcard
		Message m = ask("y.wild.sec.test", DNS.AAAA);
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertEquals(0, m.getAnswerCount());
		assertTrue(anyCovers(m, "y.wild.sec.test"));
		assertNotNull(nsecAt(m, "*.wild.sec.test"));
		verify(m, "wild NODATA");
		//  The wildcard name itself is an ordinary name
		m = ask("*.wild.sec.test", DNS.TXT);
		assertTrue(verify(m, "*.wild TXT").isEmpty());
	}

	private static List<String> addresses(Message m) {
		List<String> ret = new ArrayList<String>();
		for(RR rr : m.getAnswer()) {
			if( rr instanceof A ) {
				ret.add(((A)rr).getAddressString());
			}
		}
		return ret;
	}

	@Test
	public void referralsCarryTheDsOrItsAbsence() {
		Message m = ask("host.secure.sec.test", DNS.A);
		assertFalse(m.isAuthority(), "a referral");
		assertEquals(0, m.getAnswerCount());
		assertEquals(1, count(m.getAuthority(), DNS.NS));
		assertEquals(1, count(m.getAuthority(), DNS.DS));
		assertEquals(childDs, ((Ds)of(m.getAuthority(), "secure.sec.test", DNS.DS).get(0)).getRdataAsString());
		assertEquals(1, count(m.getAuthority(), DNS.RRSIG), "only the DS is signed");
		assertEquals(0, count(m.getAdditional(), DNS.RRSIG), "glue is not signed");
		verify(m, "secure referral");

		m = ask("host.insecure.sec.test", DNS.A);
		assertEquals(0, count(m.getAuthority(), DNS.DS));
		Nsec n = nsecAt(m, "insecure.sec.test");
		assertNotNull(n, "proof there is no DS");
		assertTrue(n.hasType(DNS.NS) && !n.hasType(DNS.DS) && !n.hasType(DNS.SOA), n.toString());
		verify(m, "insecure referral");
	}

	@Test
	public void dsIsAnsweredByTheParent() {
		Message m = ask("secure.sec.test", DNS.DS);
		assertTrue(m.isAuthority());
		assertEquals(1, count(m.getAnswer(), DNS.DS));
		verify(m, "DS");
		m = ask("insecure.sec.test", DNS.DS);
		assertTrue(m.isAuthority());
		assertEquals(0, m.getAnswerCount());
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertNotNull(nsecAt(m, "insecure.sec.test"));
		verify(m, "no DS");
	}

	@Test
	public void theNsecChainCoversTheZone() {
		SignedZone sz = zone().getSigned();
		assertNotNull(sz);
		//  Glue (below a delegation) is not in the chain; names below the apex are
		List<String> names = new ArrayList<String>();
		String n = "sec.test";
		do {
			names.add(n);
			n = Canonical.key(sz.nsecAt(n).getNext());
		} while( !n.equals("sec.test") && names.size() < 100 );
		assertEquals("[sec.test, alias.sec.test, a.b.c.sec.test, insecure.sec.test, mail.sec.test, ns1.sec.test, secure.sec.test, *.wild.sec.test, www.sec.test]",
				names.toString());
		assertTrue(sz.nsecAt("sec.test").hasType(DNS.DNSKEY));
		assertNull(sz.nsecAt("ns.secure.sec.test"));
		assertNull(sz.getSigs("ns.secure.sec.test", DNS.A), "glue is not signed");
		assertNull(sz.getSigs("secure.sec.test", DNS.NS), "delegation NS is not signed");
		assertNotNull(sz.getSigs("secure.sec.test", DNS.DS));
		//  The unsigned zone has neither DNSKEY nor NSEC
		for(List<RR> list : zone().getUnsigned().getRrs()) {
			for(RR rr : list) {
				assertTrue(rr.getType() != DNS.NSEC && rr.getType() != DNS.DNSKEY);
			}
		}
	}

	@Test
	public void zoneTransferHasTheDnssecRecords() {
		server.setAxfrAllow("127.0.0.1");
		Message q = new Message();
		q.setQuestion("sec.test", DNS.AXFR, DNS.IN);
		//  Port -1: over TCP
		List<Message> msgs = server.query(new QueryData(LOOPBACK, -1, new Message(new ByteBuffer(q.toByteArray()))));
		List<RR> all = new ArrayList<RR>();
		for(Message m : msgs) {
			all.addAll(new Message(new ByteBuffer(m.toByteArray())).getAnswer());
		}
		assertEquals(DNS.SOA, all.get(0).getType());
		assertEquals(DNS.SOA, all.get(all.size()-1).getType());
		assertEquals(2, count(all, DNS.DNSKEY));
		assertEquals(9, count(all, DNS.NSEC));
		assertEquals(zone().getSigned().rrsigCount, count(all, DNS.RRSIG));
		//  Everything in it verifies
		List<RR> body = new ArrayList<RR>(all.subList(0, all.size()-1));
		verifySection(body, "AXFR");
		//  In canonical order
		for(int i=2; i < body.size(); i++ ) {
			assertTrue(Canonical.compareNames(body.get(i-1).getName(), body.get(i).getName()) <= 0, "order at "+i);
		}
	}

	private int update(RR add) {
		Message m = new Message();
		m.setQuestion("sec.test", DNS.SOA, DNS.IN);
		m.setID(77);
		m.getHeader().setOPCODE(DNS.UPDATE);
		m.getAuthority().add(add);
		QueryData q = new QueryData(LOOPBACK, 5353, new Message(new ByteBuffer(m.toByteArray())));
		Message r = server.query(q).get(0);
		return new Message(new ByteBuffer(r.toByteArray())).getResponseCode();
	}

	@Test
	public void updatesAreSignedAndJournaled() throws Exception {
		server.setUpdateAllow("127.0.0.1");
		A a = new A("new.sec.test");
		a.setAddress("10.7.7.7");
		a.setTTL(300);
		assertEquals(DNS.NOERROR, update(a));
		assertEquals(101, zone().getSoa().getSerial());
		Message m = ask("new.sec.test", DNS.A);
		assertEquals("[10.7.7.7]", addresses(m).toString());
		verify(m, "updated name");
		assertNotNull(zone().getSigned().nsecAt("new.sec.test"), "in the NSEC chain");
		m = ask("sec.test", DNS.SOA);
		verify(m, "new SOA signed");
		//  The journal has the change, not the DNSSEC records
		String jnl = new String(Files.readAllBytes(new File(dir, "sec.test.txt.jnl").toPath()), StandardCharsets.UTF_8);
		assertTrue(jnl.contains("add new.sec.test. 300 IN A 10.7.7.7"), jnl);
		assertFalse(jnl.contains("NSEC") || jnl.contains("RRSIG"), jnl);
		//  DNSSEC records can't be changed by an update
		Nsec nsec = new Nsec("x.sec.test", DNS.IN);
		nsec.setNext("y.sec.test");
		nsec.setTypes(java.util.Collections.singletonList(DNS.A));
		assertEquals(DNS.REFUSED, update(nsec));
		//  A DS can
		Ds ds = new Ds("insecure.sec.test", DNS.IN);
		ds.setKeyTag(1);
		ds.setAlgorithm(13);
		ds.setDigestType(2);
		ds.setDigest(new byte[32]);
		ds.setTTL(3600);
		assertEquals(DNS.NOERROR, update(ds));
		m = ask("host.insecure.sec.test", DNS.A);
		assertEquals(1, count(m.getAuthority(), DNS.DS));
		verify(m, "new DS");
	}

	@Test
	public void dynamicEntriesAreSigned() {
		assertNotNull(server.addDynamic("dyn.sec.test", "10.8.8.8"));
		Message m = ask("dyn.sec.test", DNS.A);
		assertEquals("[10.8.8.8]", addresses(m).toString());
		verify(m, "dynamic");
		assertNotNull(zone().getSigned().nsecAt("dyn.sec.test"));
		//  Changing it signs again
		assertNotNull(server.addDynamic("dyn.sec.test", "10.8.8.9"));
		m = ask("dyn.sec.test", DNS.A);
		assertEquals("[10.8.8.9]", addresses(m).toString());
		verify(m, "dynamic changed");
		//  An entry replacing zone records
		server.addDynamic("www.sec.test", "10.8.8.10");
		m = ask("www.sec.test", DNS.A);
		assertEquals("[10.8.8.10]", addresses(m).toString());
		verify(m, "dynamic www");
		m = ask("www.sec.test", DNS.AAAA);
		assertEquals(0, m.getAnswerCount());
		assertFalse(nsecAt(m, "www.sec.test").hasType(DNS.AAAA));
		verify(m, "dynamic www AAAA");
	}

	@Test
	public void signaturesAreRenewedWithANewSerial() throws Exception {
		SignedZone before = zone().getSigned();
		long now = System.currentTimeMillis()/1000;
		assertEquals(0, server.resignDue(now), "nothing due yet");
		assertEquals(now+ZoneSigner.DEFAULT_VALIDITY, before.getExpires(), 5);
		long later = before.refreshAt;
		assertEquals(1, server.resignDue(later));
		SignedZone after = zone().getSigned();
		assertTrue(after != before);
		assertEquals(101, zone().getSoa().getSerial(), "secondaries see the change");
		String jnl = new String(Files.readAllBytes(new File(dir, "sec.test.txt.jnl").toPath()), StandardCharsets.UTF_8);
		assertTrue(jnl.contains("base 100\n") && jnl.contains("serial 101\n"), jnl);
		//  Survives a restart: the journal is replayed
		assertEquals(101, new Zone(zoneFile).getSoa().getSerial());
		verify(ask("www.sec.test", DNS.A), "after renewal");
	}

	@Test
	public void keysDecideWhatIsSigned() throws Exception {
		//  A published-only key (no .private) is in the DNSKEY set but signs nothing
		DnssecKey next = DnssecKey.generate("sec.test", Algorithm.of(Algorithm.ECDSAP256SHA256), false, 0);
		next.save(dir);
		assertTrue(new File(dir, next.baseName()+".private").delete());
		server.addZone(new Zone(zoneFile));
		Message m = ask("sec.test", DNS.DNSKEY);
		assertEquals(3, count(m.getAnswer(), DNS.DNSKEY));
		m = ask("www.sec.test", DNS.A);
		assertEquals(1, count(m.getAnswer(), DNS.RRSIG));
		assertEquals(zsk.getKeyTag(), ((Rrsig)of(m.getAnswer(), "www.sec.test", DNS.RRSIG).get(0)).getKeyTag());
		//  Without keys the zone is served unsigned
		for(File f : dir.listFiles()) {
			if( f.getName().startsWith("K") ) {
				assertTrue(f.delete());
			}
		}
		server.addZone(new Zone(zoneFile));
		assertNull(zone().getSigned());
		m = ask("www.sec.test", DNS.A);
		assertEquals(0, count(m.getAnswer(), DNS.RRSIG));
	}

	@Test
	public void combinedSigningKeySignsEverything() throws Exception {
		for(File f : dir.listFiles()) {
			if( f.getName().startsWith("K") ) {
				assertTrue(f.delete());
			}
		}
		ksk = DnssecKey.generate("sec.test", Algorithm.of(Algorithm.ECDSAP256SHA256), true, 0);
		zsk = ksk;
		ksk.save(dir);
		server.addZone(new Zone(zoneFile));
		Message m = ask("www.sec.test", DNS.A);
		assertEquals(ksk.getKeyTag(), ((Rrsig)of(m.getAnswer(), "www.sec.test", DNS.RRSIG).get(0)).getKeyTag());
		verify(m, "CSK");
		verify(ask("sec.test", DNS.DNSKEY), "CSK DNSKEY");
	}

	@Test
	public void zoneFilesTakeDsButNotHalfSignedData() throws Exception {
		File bad = new File(dir, "bad.test.txt");
		write(bad, "@\tIN\tSOA\tns1 hostmaster ( 1 3600 900 1209600 300 )\n\tNS\tns1\nns1\tA\t10.0.0.1\n"
				+"@\tDNSKEY\t257 3 13 AAAA\n");
		IOException ex = org.junit.jupiter.api.Assertions.assertThrows(IOException.class, () -> new Zone(bad));
		assertTrue(ex.getMessage().contains("no RRSIG"), ex.getMessage());
		//  A DS with its digest split in two
		File ok = new File(dir, "ok.test.txt");
		write(ok, "@\tIN\tSOA\tns1 hostmaster ( 1 3600 900 1209600 300 )\n\tNS\tns1\nns1\tA\t10.0.0.1\n"
				+"sub\tNS\tns1\nsub\tDS\t12345 13 2 ( 0123456789ABCDEF0123456789ABCDEF\n\t0123456789ABCDEF0123456789ABCDEF )\n");
		Zone z = new Zone(ok);
		RR ds = z.getMatchingRR("sub.ok.test", DNS.DS);
		assertEquals("12345 13 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", ds.getRdataAsString());
	}

	@Test
	public void unsignedZonesAreUnchanged() throws Exception {
		File plain = new File(dir, "plain.test.txt");
		write(plain, "@\tIN\tSOA\tns1 hostmaster ( 1 3600 900 1209600 300 )\n\tNS\tns1\nns1\tA\t10.0.0.1\n*\tA\t10.0.0.2\n");
		server.addZone(new Zone(plain));
		assertNull(server.getZone("plain.test").getSigned());
		Message m = ask("x.plain.test", DNS.A);
		assertEquals(1, m.getAnswerCount());
		assertEquals(0, count(m.getAnswer(), DNS.RRSIG));
		assertEquals(0, count(m.getAuthority(), DNS.NSEC));
		assertTrue(optDo(m));
	}
}
