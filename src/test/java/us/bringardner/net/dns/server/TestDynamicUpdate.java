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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.A;
import us.bringardner.net.dns.ByteBuffer;
import us.bringardner.net.dns.Cname;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.Mx;
import us.bringardner.net.dns.Ns;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.Section;
import us.bringardner.net.dns.Soa;
import us.bringardner.net.dns.Tsig;
import us.bringardner.net.dns.resolve.QueryData;

/**
 * Dynamic UPDATE (RFC 2136) with a journal (rec #43).
 * Also checked against dnspython's dns.update (24 cases).
 */
public class TestDynamicUpdate {

	private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();
	private static final int ANY = ZoneUpdater.CLASS_ANY;
	private static final int NONE = ZoneUpdater.CLASS_NONE;
	private File dir;
	private File zoneFile;
	private DnsServer server;
	private String savedDir;
	private String savedDefault;

	private static String zoneText(int serial) {
		return "$TTL 300\n@\tIN\tSOA\tns1 postmaster ( "+serial+" 3600 1800 1209600 300 )\n"
				+"\t\tNS\tns1\n"
				+"\t\tNS\tns2\n"
				+"\t\tMX\t10 mail\n"
				+"ns1\tIN\tA\t10.0.0.53\n"
				+"ns2\tIN\tA\t10.0.0.54\n"
				+"mail\tIN\tA\t10.0.0.25\n"
				+"www\tIN\tA\t10.0.0.80\n"
				+"www\tIN\tA\t10.0.0.81\n"
				+"alias\tIN\tCNAME\twww\n";
	}

	@BeforeEach
	public void setup() throws Exception {
		dir = Files.createTempDirectory("update").toFile();
		zoneFile = new File(dir, "up.test.txt");
		write(zoneFile, zoneText(100));
		savedDir = System.getProperty(DnsServer.PROP_ZONE_DIR);
		savedDefault = System.getProperty(DnsServer.PROP_DEFAULT_ZONE);
		System.setProperty(DnsServer.PROP_ZONE_DIR, dir.getAbsolutePath());
		System.setProperty(DnsServer.PROP_DEFAULT_ZONE, "up.test");
		server = new DnsServer();
		server.loadZones();
		server.setRecursionAvailable(false);
		server.setUpdateAllow("127.0.0.1");
	}

	@AfterEach
	public void cleanup() {
		restore(DnsServer.PROP_ZONE_DIR, savedDir);
		restore(DnsServer.PROP_DEFAULT_ZONE, savedDefault);
		ZoneNotifier n = server.getNotifier();
		if( n != null ) {
			n.shutdown();
		}
		for(File f : dir.listFiles()) {
			f.delete();
		}
		dir.delete();
	}

	private static void restore(String key, String value) {
		if( value == null ) {
			System.clearProperty(key);
		} else {
			System.setProperty(key, value);
		}
	}

	private static void write(File f, String text) throws IOException {
		try(FileWriter w = new FileWriter(f)) {
			w.write(text);
		}
	}

	// ------------------------------------------------------------ building UPDATE messages

	/** An UPDATE message for up.test. */
	private static class Update {
		final Message m = new Message();

		Update() {
			this("up.test");
		}

		Update(String zone) {
			m.setQuestion(zone, DNS.SOA, DNS.IN);
			m.setID(4711);
			m.getHeader().setOPCODE(DNS.UPDATE);
		}

		private static RR empty(String name, int type, int cls) {
			RR rr = new RR(name, type, cls);
			rr.setRdata(new byte[0]);
			rr.setTTL(0);
			return rr;
		}

		Update nameInUse(String name) { m.getAnswer().add(empty(name, 255, ANY)); return this; }
		Update nameNotInUse(String name) { m.getAnswer().add(empty(name, 255, NONE)); return this; }
		Update rrsetExists(String name, int type) { m.getAnswer().add(empty(name, type, ANY)); return this; }
		Update rrsetAbsent(String name, int type) { m.getAnswer().add(empty(name, type, NONE)); return this; }
		Update rrsetIs(RR rr) { rr.setTTL(0); m.getAnswer().add(rr); return this; }

		Update add(RR rr) { m.getAuthority().add(rr); return this; }
		Update deleteRRset(String name, int type) { m.getAuthority().add(empty(name, type, ANY)); return this; }
		Update deleteName(String name) { m.getAuthority().add(empty(name, 255, ANY)); return this; }
		Update delete(RR rr) { rr.setDnsClass(NONE); rr.setTTL(0); m.getAuthority().add(rr); return this; }
	}

	private static A a(String name, String ip) {
		A a = new A(name);
		a.setAddress(ip);
		a.setTTL(300);
		return a;
	}

	private int send(Update u) {
		return send(u, LOOPBACK, null);
	}

	private int send(Update u, InetAddress from, String key) {
		QueryData q = new QueryData(from, 5353, new Message(new ByteBuffer(u.m.toByteArray())));
		q.setTsigKey(key);
		Message r = server.query(q).get(0);
		Message back = new Message(new ByteBuffer(r.toByteArray()));
		assertEquals(DNS.UPDATE, back.getHeader().getOPCODE());
		assertTrue(back.getHeader().getQR());
		assertEquals(4711, back.getID());
		assertEquals(u.m.getQuestion().size(), back.getQuestion().size(), "zone section echoed");
		return back.getResponseCode();
	}

	private Zone zone() {
		return server.getZone("up.test");
	}

	private List<String> data(String name, int type) {
		List<String> ret = new ArrayList<String>();
		for(RR rr : zone().exactRecords(name)) {
			if( rr.getType() == type ) {
				ret.add(Zone.rdataText(rr));
			}
		}
		Collections.sort(ret);
		return ret;
	}

	private int serial() {
		return zone().getSoa().getSerial();
	}

	private File journal() {
		return new File(dir, "up.test.txt.jnl");
	}

	// ------------------------------------------------------------ access

	@Test
	public void refusedUnlessAllowed() {
		server.setUpdateAllow(null);
		assertEquals(DNS.REFUSED, send(new Update().add(a("x.up.test","10.0.0.1"))));
		assertTrue(data("x.up.test", DNS.A).isEmpty());
		assertFalse(journal().exists());
	}

	@Test
	public void allowedByKey() {
		server.setUpdateAllow(null);
		server.setTsigKeys(Tsig.KeyRing.parse("upd:hmac-sha256:"+Base64.getEncoder().encodeToString(new byte[32])+" other:hmac-sha256:"+Base64.getEncoder().encodeToString(new byte[32])));
		server.setUpdateKeys("upd");
		assertEquals(DNS.REFUSED, send(new Update().add(a("x.up.test","10.0.0.1")), LOOPBACK, "other"));
		assertEquals(DNS.NOERROR, send(new Update().add(a("x.up.test","10.0.0.1")), LOOPBACK, "upd"));
		assertEquals("[10.0.0.1]", data("x.up.test", DNS.A).toString());
	}

	// ------------------------------------------------------------ changes

	@Test
	public void addAnswersBumpsSerialAndIsJournaled() throws Exception {
		assertEquals(DNS.NOERROR, send(new Update().add(a("new.up.test","10.1.1.1"))));
		assertEquals(101, serial());
		//  Answered like any other record
		Message q = new Message();
		q.setQuestion("new.up.test", DNS.A, DNS.IN);
		Message r = server.query(new QueryData(LOOPBACK, 5353, new Message(new ByteBuffer(q.toByteArray())))).get(0);
		assertEquals(1, r.getAnswerCount());
		//  The zone file is untouched; the journal has the change
		assertEquals(zoneText(100), new String(Files.readAllBytes(zoneFile.toPath()), StandardCharsets.UTF_8));
		String jnl = new String(Files.readAllBytes(journal().toPath()), StandardCharsets.UTF_8);
		assertTrue(jnl.contains("base 100\n"), jnl);
		assertTrue(jnl.contains("add new.up.test. 300 IN A 10.1.1.1\n"), jnl);
		assertTrue(jnl.contains("serial 101\n"), jnl);
		//  A restart (the zone read again) has it
		Zone again = new Zone(zoneFile);
		assertEquals(101, again.getSoa().getSerial());
		assertEquals(1, again.exactRecords("new.up.test").size());
	}

	@Test
	public void deletes() throws Exception {
		assertEquals(DNS.NOERROR, send(new Update().delete(a("www.up.test","10.0.0.81"))));
		assertEquals("[10.0.0.80]", data("www.up.test", DNS.A).toString());
		assertEquals(DNS.NOERROR, send(new Update().deleteRRset("mail.up.test", DNS.A)));
		assertTrue(zone().exactRecords("mail.up.test").isEmpty());
		assertEquals(DNS.NOERROR, send(new Update().deleteName("www.up.test")));
		assertTrue(zone().exactRecords("www.up.test").isEmpty());
		assertEquals(103, serial());
		Zone again = new Zone(zoneFile);
		assertTrue(again.exactRecords("www.up.test").isEmpty());
		assertTrue(again.exactRecords("mail.up.test").isEmpty());
		assertEquals(103, again.getSoa().getSerial());
	}

	@Test
	public void apexIsProtected() {
		send(new Update().deleteRRset("up.test", DNS.NS).deleteRRset("up.test", DNS.SOA));
		assertEquals(2, data("up.test", DNS.NS).size(), "the apex NS RRset can't be deleted");
		send(new Update().deleteName("up.test"));
		assertEquals(2, data("up.test", DNS.NS).size(), "delete name at the apex keeps NS (and SOA)");
		assertTrue(data("up.test", DNS.MX).isEmpty(), "... but other data goes");
		Ns ns1 = new Ns("up.test");
		ns1.setNs("ns1.up.test");
		Ns ns2 = new Ns("up.test");
		ns2.setNs("ns2.up.test");
		send(new Update().delete(ns1).delete(ns2));
		assertEquals(1, data("up.test", DNS.NS).size(), "never the last NS");
	}

	@Test
	public void cnameRules() {
		send(new Update().add(a("alias.up.test","10.0.0.9")));
		assertTrue(data("alias.up.test", DNS.A).isEmpty(), "no other data next to a CNAME");
		Cname c = new Cname("www.up.test");
		c.setCname("mail.up.test");
		c.setTTL(300);
		send(new Update().add(c));
		assertTrue(data("www.up.test", DNS.CNAME).isEmpty(), "no CNAME next to other data");
		Cname c2 = new Cname("alias.up.test");
		c2.setCname("mail.up.test");
		c2.setTTL(300);
		send(new Update().add(c2));
		assertEquals("[mail.up.test]", data("alias.up.test", DNS.CNAME).toString().replace(".]", "]"), "a CNAME replaces the CNAME");
	}

	@Test
	public void sameRecordAgainOnlyChangesTheTtl() {
		A a = a("www.up.test","10.0.0.80");
		a.setTTL(60);
		send(new Update().add(a));
		List<RR> www = zone().exactRecords("www.up.test");
		assertEquals(2, www.size());
		for(RR rr : www) {
			if( Zone.rdataText(rr).equals("10.0.0.80") ) {
				assertEquals(60, rr.getTTL());
			}
		}
	}

	@Test
	public void addingWhatIsThereIsNotAChange() {
		assertEquals(DNS.NOERROR, send(new Update().deleteName("nothing.up.test")));
		assertEquals(100, serial(), "no change, no new serial");
		assertFalse(journal().exists());
	}

	// ------------------------------------------------------------ prerequisites

	@Test
	public void prerequisites() {
		assertEquals(DNS.NOERROR, send(new Update().nameInUse("www.up.test")));
		assertEquals(DNS.NAME_ERROR, send(new Update().nameInUse("nope.up.test")));
		assertEquals(DNS.NOERROR, send(new Update().nameNotInUse("nope.up.test")));
		assertEquals(ZoneUpdater.YXDOMAIN, send(new Update().nameNotInUse("www.up.test")));
		assertEquals(DNS.NOERROR, send(new Update().rrsetExists("www.up.test", DNS.A)));
		assertEquals(ZoneUpdater.NXRRSET, send(new Update().rrsetExists("www.up.test", DNS.MX)));
		assertEquals(DNS.NOERROR, send(new Update().rrsetAbsent("www.up.test", DNS.MX)));
		assertEquals(ZoneUpdater.YXRRSET, send(new Update().rrsetAbsent("www.up.test", DNS.A)));
		//  Value dependent: exactly this RRset
		assertEquals(DNS.NOERROR, send(new Update().rrsetIs(a("www.up.test","10.0.0.80")).rrsetIs(a("www.up.test","10.0.0.81"))));
		assertEquals(ZoneUpdater.NXRRSET, send(new Update().rrsetIs(a("www.up.test","10.0.0.80"))), "only part of the RRset");
		assertEquals(100, serial());
	}

	@Test
	public void failedPrerequisiteChangesNothing() {
		assertEquals(ZoneUpdater.YXDOMAIN, send(new Update().nameNotInUse("www.up.test").add(a("x.up.test","10.0.0.1"))));
		assertTrue(data("x.up.test", DNS.A).isEmpty());
		assertFalse(journal().exists());
	}

	// ------------------------------------------------------------ errors

	@Test
	public void errors() {
		assertEquals(ZoneUpdater.NOTZONE, send(new Update().add(a("x.other.test","10.0.0.1"))));
		assertEquals(ZoneUpdater.NOTAUTH, send(new Update("other.test").add(a("x.other.test","10.0.0.1"))));
		A withTtl = a("www.up.test","10.0.0.80");
		Update u = new Update();
		u.m.getAnswer().add(withTtl);		//  prerequisite with a TTL
		assertEquals(DNS.FORMAT_ERROR, send(u));
		Update notSoa = new Update();
		notSoa.m.getQuestion().clear();
		notSoa.m.setQuestion("up.test", DNS.A, DNS.IN);
		assertEquals(DNS.FORMAT_ERROR, send(notSoa));
		//  A good add followed by an out-of-zone one: nothing is changed
		assertEquals(ZoneUpdater.NOTZONE, send(new Update().add(a("ok.up.test","10.0.0.1")).add(a("x.elsewhere","10.0.0.2"))));
		assertTrue(data("ok.up.test", DNS.A).isEmpty());
		assertEquals(100, serial());
	}

	// ------------------------------------------------------------ journal and reload

	@Test
	public void editedZoneFileWinsOverTheJournal() throws Exception {
		send(new Update().add(a("new.up.test","10.1.1.1")));
		assertTrue(journal().exists());
		//  Same serial: an edit is reloaded with the journal on top
		write(zoneFile, zoneText(100)+"extra\tIN\tA\t10.2.2.2\n");
		zoneFile.setLastModified(zoneFile.lastModified()+2000);
		assertTrue(server.shouldReloadZones());
		server.loadZones();
		assertEquals(1, zone().exactRecords("new.up.test").size());
		assertEquals(1, zone().exactRecords("extra.up.test").size());
		//  New serial: the file is taken as it is and the journal set aside
		write(zoneFile, zoneText(200));
		zoneFile.setLastModified(zoneFile.lastModified()+4000);
		server.loadZones();
		assertTrue(zone().exactRecords("new.up.test").isEmpty());
		assertEquals(200, serial());
		assertFalse(journal().exists());
		assertTrue(new File(dir, "up.test.txt.jnl.old").exists());
	}

	@Test
	public void unchangedReloadKeepsTheUpdatedZone() throws Exception {
		send(new Update().add(a("new.up.test","10.1.1.1")));
		assertFalse(server.shouldReloadZones(), "our own journal write is not a zone file change");
		server.loadZones();
		assertEquals(1, zone().exactRecords("new.up.test").size());
	}

	@Test
	public void notifyAfterUpdate() throws Exception {
		try(DatagramSocket sec = new DatagramSocket(0, LOOPBACK)) {
			sec.setSoTimeout(5000);
			server.setNotifyTargets("127.0.0.1:"+sec.getLocalPort(), 1, 200);
			send(new Update().add(a("new.up.test","10.1.1.1")));
			byte [] buf = new byte[4096];
			DatagramPacket p = new DatagramPacket(buf, buf.length);
			sec.receive(p);
			Message n = new Message(new ByteBuffer(java.util.Arrays.copyOf(buf, p.getLength())));
			assertEquals(DNS.NOTIFY, n.getHeader().getOPCODE());
			assertEquals(101, ((Soa)n.getAnswer().get(0)).getSerial());
		}
	}

	@Test
	public void otherTypes() {
		Mx mx = new Mx("up.test");
		mx.setPref((short)20);
		mx.setExchange("mx2.up.test");
		mx.setTTL(300);
		us.bringardner.net.dns.Txt txt = new us.bringardner.net.dns.Txt("t.up.test");
		txt.setText("v=spf1 -all; with spaces");
		txt.setTTL(300);
		us.bringardner.net.dns.AAAA aaaa = new us.bringardner.net.dns.AAAA("v6.up.test");
		aaaa.setAddress("2001:db8::7");
		aaaa.setTTL(300);
		assertEquals(DNS.NOERROR, send(new Update().add(mx).add(txt).add(aaaa)));
		assertEquals(2, data("up.test", DNS.MX).size());
		assertEquals("[\"v=spf1 -all; with spaces\"]", data("t.up.test", DNS.TXT).toString());
		assertEquals("[2001:db8::7]", data("v6.up.test", DNS.AAAA).toString());
		//  and read back from the journal
		try {
			Zone again = new Zone(zoneFile);
			assertEquals("v=spf1 -all; with spaces", ((us.bringardner.net.dns.Txt)again.exactRecords("t.up.test").get(0)).getText());
			assertNotNull(again.exactRecords("v6.up.test").get(0));
		} catch(IOException e) {
			throw new AssertionError(e);
		}
	}
}
