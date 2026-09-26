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
import us.bringardner.net.dns.Base32Hex;
import us.bringardner.net.dns.ByteBuffer;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Dnskey;
import us.bringardner.net.dns.Ds;
import us.bringardner.net.dns.Edns;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.Nsec3;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.Rrsig;
import us.bringardner.net.dns.dnssec.Algorithm;
import us.bringardner.net.dns.dnssec.Canonical;
import us.bringardner.net.dns.dnssec.DnssecKey;
import us.bringardner.net.dns.dnssec.Nsec3Params;
import us.bringardner.net.dns.resolve.QueryData;

/**
 * A zone signed with NSEC3 (RFC 5155): the proofs a validator needs
 * (RFC 5155 7.2 / 8), checked by hashing the names the way it would.
 * (BIND's delv, dnssec-verify and ldns-verify-zone agreed with these
 * answers, and BIND's signer makes the same NSEC3 chain; see the rec #46 notes.)
 */
public class TestNsec3Server {

	private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();

	private File dir;
	private File zoneFile;
	private DnsServer server;
	private DnssecKey key;
	private Nsec3Params params = Nsec3Params.DEFAULT;

	@BeforeEach
	public void setup() throws Exception {
		dir = Files.createTempDirectory("nsec3").toFile();
		key = DnssecKey.generate("sec.test", Algorithm.of(Algorithm.ECDSAP256SHA256), true, 0);
		key.save(dir);
		DnssecKey child = DnssecKey.generate("secure.sec.test", Algorithm.of(Algorithm.ECDSAP256SHA256), true, 0);
		zoneFile = new File(dir, "sec.test.txt");
		try(FileWriter w = new FileWriter(zoneFile)) {
			w.write("$TTL 3600\n"
				+"@\tIN\tSOA\tns1 hostmaster ( 100 3600 900 1209600 300 )\n"
				+"\tNS\tns1\n"
				+"\tMX\t10 mail\n"
				+"ns1\tA\t127.0.0.1\n"
				+"mail\tA\t10.0.0.25\n"
				+"www\tA\t10.0.0.80\n"
				+"www\tAAAA\t2001:db8::80\n"
				+"*.wild\tA\t10.0.0.99\n"
				+"a.b.c\tA\t10.0.0.1\n"
				+"secure\tNS\tns.secure\n"
				+"secure\tDS\t"+child.toDs(Ds.SHA256, 3600).getRdataAsString()+"\n"
				+"ns.secure\tA\t10.0.0.53\n"
				+"insecure\tNS\tns.insecure\n"
				+"ns.insecure\tA\t10.0.0.54\n");
		}
		server = new DnsServer();
		server.setRecursionAvailable(false);
		server.setDnssecKeyDir(dir);
		server.setDnssecNsec3("*", params);
		server.addZone(new Zone(zoneFile));
	}

	@AfterEach
	public void cleanup() {
		for(File f : dir.listFiles()) {
			f.delete();
		}
		dir.delete();
	}

	private Zone zone() {
		return server.getZone("sec.test");
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

	// ------------------------------------------------------------ a validator's checks

	/** Every RRSIG verifies over its RRset; no NSEC anywhere. */
	private void verifySigs(List<RR> section, String what) {
		Map<String, List<RR>> sets = new LinkedHashMap<String, List<RR>>();
		for(RR rr : section) {
			assertTrue(rr.getType() != DNS.NSEC, what+": NSEC in an NSEC3 zone");
			if( !(rr instanceof Rrsig) && rr.getType() != DNS.OPT ) {
				sets.computeIfAbsent(Canonical.key(rr.getName())+"|"+rr.getType(), k -> new ArrayList<RR>()).add(rr);
			}
		}
		Dnskey k = key.getDnskey();
		for(RR rr : section) {
			if( rr instanceof Rrsig ) {
				Rrsig s = (Rrsig)rr;
				String owner = Canonical.key(s.getName());
				List<RR> set = sets.get(owner+"|"+s.getTypeCovered());
				assertNotNull(set, what+": RRSIG without RRset");
				String signed = owner;
				String [] l = owner.split("\\.");
				if( s.getLabels() < Canonical.labelCount(owner) ) {
					StringBuilder b = new StringBuilder("*");
					for(int i=l.length-s.getLabels(); i < l.length; i++ ) {
						b.append('.').append(l[i]);
					}
					signed = b.toString();
				}
				assertTrue(Canonical.verify(s, signed, set, k), what+": bad signature "+s);
			}
		}
		for(String rrset : sets.keySet()) {
			if( rrset.endsWith("|"+DNS.NSEC3) ) {
				boolean signed = false;
				for(RR rr : section) {
					signed |= rr instanceof Rrsig && ((Rrsig)rr).getTypeCovered() == DNS.NSEC3
							&& (Canonical.key(rr.getName())+"|"+DNS.NSEC3).equals(rrset);
				}
				assertTrue(signed, what+": unsigned "+rrset);
			}
		}
	}

	private void verify(Message m, String what) {
		verifySigs(m.getAnswer(), what);
		verifySigs(m.getAuthority(), what);
	}

	private List<Nsec3> nsec3s(Message m) {
		List<Nsec3> ret = new ArrayList<Nsec3>();
		for(RR rr : m.getAuthority()) {
			if( rr instanceof Nsec3 ) {
				Nsec3 n = (Nsec3)rr;
				assertEquals(params.getIterations(), n.getIterations());
				assertEquals(Nsec3.saltText(params.getSalt()), Nsec3.saltText(n.getSalt()));
				ret.add(n);
			}
		}
		return ret;
	}

	private String hash(String name) {
		return params.hashLabel(name);
	}

	private static String ownerHash(Nsec3 n) {
		String o = Canonical.key(n.getName());
		return o.substring(0, o.indexOf('.'));
	}

	/** The NSEC3 in the answer whose owner is the hash of name, or null. */
	private Nsec3 matching(Message m, String name) {
		for(Nsec3 n : nsec3s(m)) {
			if( ownerHash(n).equals(hash(name)) ) {
				return n;
			}
		}
		return null;
	}

	/** Does an NSEC3 in the answer cover (prove the absence of) the name's hash? */
	private boolean covered(Message m, String name) {
		String h = hash(name);
		for(Nsec3 n : nsec3s(m)) {
			String owner = ownerHash(n);
			String next = Base32Hex.encode(n.getNextHashed());
			boolean last = next.compareTo(owner) <= 0;
			boolean covers = last ? (h.compareTo(owner) > 0 || h.compareTo(next) < 0)
					: (h.compareTo(owner) > 0 && h.compareTo(next) < 0);
			if( covers ) {
				return true;
			}
		}
		return false;
	}

	// ------------------------------------------------------------ tests

	@Test
	public void signedWithNsec3NotNsec() {
		SignedZone sz = zone().getSigned();
		assertTrue(sz.isNsec3());
		//  Every name and empty non-terminal (b.c, c, wild) has an NSEC3; glue does not
		assertEquals(11, sz.allNsec3().size());
		for(String n : new String[] {"sec.test", "www.sec.test", "c.sec.test", "b.c.sec.test", "wild.sec.test", "*.wild.sec.test", "insecure.sec.test"}) {
			assertNotNull(sz.nsec3Matching(n), n);
		}
		assertNull(sz.nsec3Matching("ns.secure.sec.test"));
		assertTrue(sz.nsec3Matching("b.c.sec.test").getTypes().isEmpty(), "empty non-terminal");
		Nsec3 apex = sz.nsec3Matching("sec.test");
		assertTrue(apex.hasType(DNS.SOA) && apex.hasType(DNS.DNSKEY) && apex.hasType(DNS.NSEC3PARAM) && apex.hasType(DNS.RRSIG));
		assertFalse(apex.hasType(DNS.NSEC3));
		Message m = ask("sec.test", DNS.NSEC3PARAM);
		assertEquals(1, m.getAnswerCount() - 1, "NSEC3PARAM and its RRSIG");
		verify(m, "NSEC3PARAM");
		//  No NSEC records in the zone
		for(List<RR> list : zone().getRrs()) {
			for(RR rr : list) {
				assertTrue(rr.getType() != DNS.NSEC && rr.getType() != DNS.NSEC3);
			}
		}
	}

	@Test
	public void nxdomainHasTheClosestEncloserProof() {
		for(String[] c : new String[][] {{"nope.sec.test", "sec.test", "nope.sec.test"},
				{"x.y.nope.sec.test", "sec.test", "nope.sec.test"}, {"x.b.c.sec.test", "b.c.sec.test", "x.b.c.sec.test"}}) {
			Message m = ask(c[0], DNS.A);
			assertEquals(DNS.NAME_ERROR, m.getResponseCode(), c[0]);
			assertNotNull(matching(m, c[1]), c[0]+": closest encloser "+c[1]);
			assertTrue(covered(m, c[2]), c[0]+": next closer "+c[2]);
			assertTrue(covered(m, "*."+c[1]), c[0]+": wildcard");
			verify(m, c[0]);
		}
	}

	@Test
	public void nodataIsTheMatchingNsec3() {
		Message m = ask("www.sec.test", DNS.MX);
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertEquals(0, m.getAnswerCount());
		Nsec3 n = matching(m, "www.sec.test");
		assertTrue(n.hasType(DNS.A) && n.hasType(DNS.AAAA) && !n.hasType(DNS.MX));
		verify(m, "www MX");
		for(String ent : new String[] {"b.c.sec.test", "c.sec.test", "wild.sec.test"}) {
			m = ask(ent, DNS.A);
			assertEquals(DNS.NOERROR, m.getResponseCode(), ent);
			assertTrue(matching(m, ent).getTypes().isEmpty(), ent);
			verify(m, ent);
		}
	}

	@Test
	public void wildcards() {
		Message m = ask("a.b.wild.sec.test", DNS.A);
		assertEquals(1, m.getAnswerCount() - 1);
		assertTrue(covered(m, "b.wild.sec.test"), "next closer name");
		verify(m, "wildcard answer");
		m = ask("x.wild.sec.test", DNS.TXT);
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertNotNull(matching(m, "wild.sec.test"), "closest encloser");
		assertTrue(covered(m, "x.wild.sec.test"), "next closer");
		assertFalse(matching(m, "*.wild.sec.test").hasType(DNS.TXT), "the wildcard lacks the type");
		verify(m, "wildcard NODATA");
	}

	@Test
	public void delegations() {
		Message m = ask("host.insecure.sec.test", DNS.A);
		Nsec3 n = matching(m, "insecure.sec.test");
		assertNotNull(n, "RFC 5155 7.2.7");
		assertTrue(n.hasType(DNS.NS) && !n.hasType(DNS.DS) && !n.hasType(DNS.RRSIG), n.toString());
		verify(m, "insecure referral");
		m = ask("host.secure.sec.test", DNS.A);
		assertEquals(1, m.getAuthority().stream().filter(r -> r.getType() == DNS.DS).count());
		assertTrue(nsec3s(m).isEmpty());
		verify(m, "secure referral");
		m = ask("insecure.sec.test", DNS.DS);
		assertTrue(m.isAuthority());
		assertNotNull(matching(m, "insecure.sec.test"));
		verify(m, "no DS");
	}

	@Test
	public void nsec3OwnerNamesDoNotExist() {
		String owner = hash("www.sec.test")+".sec.test";
		Message m = ask(owner, DNS.A);
		assertEquals(DNS.NAME_ERROR, m.getResponseCode(), "RFC 5155 7.2.9");
		verify(m, "hashed name");
	}

	@Test
	public void zoneTransferAndUpdates() throws Exception {
		server.setAxfrAllow("127.0.0.1");
		Message q = new Message();
		q.setQuestion("sec.test", DNS.AXFR, DNS.IN);
		List<RR> all = new ArrayList<RR>();
		for(Message m : server.query(new QueryData(LOOPBACK, -1, new Message(new ByteBuffer(q.toByteArray()))))) {
			all.addAll(new Message(new ByteBuffer(m.toByteArray())).getAnswer());
		}
		assertEquals(11, all.stream().filter(r -> r.getType() == DNS.NSEC3).count());
		assertEquals(1, all.stream().filter(r -> r.getType() == DNS.NSEC3PARAM).count());
		assertEquals(0, all.stream().filter(r -> r.getType() == DNS.NSEC).count());
		verifySigs(all.subList(0, all.size()-1), "AXFR");

		//  An update adds a name and its new empty non-terminal
		server.setUpdateAllow("127.0.0.1");
		A a = new A("h.deep.sec.test");
		a.setAddress("10.7.7.7");
		a.setTTL(300);
		Message u = new Message();
		u.setQuestion("sec.test", DNS.SOA, DNS.IN);
		u.getHeader().setOPCODE(DNS.UPDATE);
		u.getAuthority().add(a);
		server.query(new QueryData(LOOPBACK, 5353, new Message(new ByteBuffer(u.toByteArray()))));
		assertEquals(101, zone().getSoa().getSerial());
		assertNotNull(zone().getSigned().nsec3Matching("deep.sec.test"));
		Message m = ask("deep.sec.test", DNS.A);
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertNotNull(matching(m, "deep.sec.test"));
		verify(m, "new empty non-terminal");
	}

	@Test
	public void parametersAndSwitchingBack() throws Exception {
		params = Nsec3Params.parse(5, "AB12");
		server.setDnssecNsec3("sec.test.", params);
		server.addZone(new Zone(zoneFile));
		assertEquals("1 0 5 AB12", zone().getSigned().getNsec3Params().toString());
		Message m = ask("nope.sec.test", DNS.A);
		assertNotNull(matching(m, "sec.test"));
		assertTrue(covered(m, "nope.sec.test"));
		verify(m, "salted");
		//  Other zones (none listed) and back to NSEC
		server.setDnssecNsec3("other.test", params);
		server.addZone(new Zone(zoneFile));
		assertFalse(zone().getSigned().isNsec3());
		assertTrue(zone().getSigned().nsecAt("sec.test") != null);
	}
}
