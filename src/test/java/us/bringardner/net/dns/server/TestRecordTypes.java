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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.AAAA;
import us.bringardner.net.dns.ByteBuffer;
import us.bringardner.net.dns.Caa;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.Soa;
import us.bringardner.net.dns.Srv;
import us.bringardner.net.dns.resolve.QueryData;

/**
 * AAAA, SRV and CAA in zone files and on the wire, SOA field order, and
 * NOTIMP / REFUSED for opcodes and zone transfers we don't support (rec #37).
 */
public class TestRecordTypes {

	private static File dir;
	private static DnsServer server;

	@BeforeAll
	public static void setup() throws IOException {
		dir = Files.createTempDirectory("types").toFile();
		File zone = new File(dir,"types.test.txt");
		try(FileWriter w = new FileWriter(zone)) {
			w.write("@\tIN\tSOA\tns1.types.test. postmaster.types.test. (\n"
					+"\t\t\t7 ; serial\n\t\t\t3600 ; refresh\n\t\t\t1800 ; retry\n"
					+"\t\t\t1209600 ; expire\n\t\t\t300 ) ; minimum\n\n"
					+"\t\tNS\tns1\n"
					+"\t\tCAA\t0 issue \"letsencrypt.org\"\n"
					+"\t\tCAA\t128 iodef \"mailto:security@types.test\"\n"
					+"ns1\tIN\tA\t10.0.0.53\n"
					+"www\tIN\tA\t10.0.0.80\n"
					+"www\tIN\tAAAA\t2001:db8::80\n"
					+"v6only\tIN\tAAAA\t2001:0DB8:0000:0000:0001:0000:0000:0001\n"
					+"mapped\tIN\tAAAA\t::ffff:192.0.2.1\n"
					+"_sip._tcp\tIN\tSRV\t10 60 5060 sip\n"
					+"_sip._tcp\tIN\tSRV\t20 0 5060 backup.example.org.\n"
					+"sip\tIN\tA\t10.0.0.5\n");
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

	/** Ask through the wire format, as a client would. */
	private static Message ask(String name, int type, int opcode) {
		Message q = new Message();
		q.setQuestion(name, type, DNS.IN);
		q.setID(4242);
		q.getHeader().setOPCODE(opcode);
		Message in = new Message(new ByteBuffer(q.toByteArray()));
		Message r = server.query(new QueryData(InetAddress.getLoopbackAddress(), 5353, in)).get(0);
		return new Message(new ByteBuffer(r.toByteArray()));
	}

	private static Message ask(String name, int type) {
		return ask(name, type, DNS.QUERY);
	}

	/** A response with one answer of the given type and rdata, as an upstream server would send it. */
	private static byte [] wireAnswer(int type, byte [] rdata) throws IOException {
		ByteArrayOutputStream b = new ByteArrayOutputStream();
		DataOutputStream d = new DataOutputStream(b);
		d.writeShort(7); d.writeShort(0x8180); d.writeShort(1); d.writeShort(1); d.writeShort(0); d.writeShort(0);
		d.write(new byte[] {1,'h',4,'t','e','s','t',0});
		d.writeShort(type); d.writeShort(1);
		d.writeShort(0xC00C); d.writeShort(type); d.writeShort(1); d.writeInt(300);
		d.writeShort(rdata.length); d.write(rdata);
		return b.toByteArray();
	}

	private static RR reserialized(byte [] wire) {
		Message m = new Message(new ByteBuffer(wire));
		Message again = new Message(new ByteBuffer(m.toByteArray()));
		return again.getAnswer().get(0);
	}

	// ------------------------------------------------------------ AAAA

	@Test
	public void aaaaFromZoneFile() throws Exception {
		Message m = ask("www.types.test", DNS.AAAA);
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertEquals(1, m.getAnswerCount(), m.toString());
		AAAA a = (AAAA)m.getAnswer().get(0);
		assertEquals("2001:db8::80", a.getAddressString());
		assertArrayEquals(InetAddress.getByName("2001:db8::80").getAddress(), a.getAddress());
		assertEquals("2001:db8::1:0:0:1", ((AAAA)ask("v6only.types.test", DNS.AAAA).getAnswer().get(0)).getAddressString());
		assertEquals("::ffff:192.0.2.1", ((AAAA)ask("mapped.types.test", DNS.AAAA).getAnswer().get(0)).getAddressString());
		//  The A record is still there and separate
		assertEquals(1, ask("www.types.test", DNS.A).getAnswerCount());
	}

	@Test
	public void aaaaPassedOnKeepsItsAddress() throws Exception {
		//  Used to go out as :: (16 zero bytes) when re-serialized, i.e. for
		//  every AAAA answer the resolver passed on
		byte [] addr = InetAddress.getByName("2607:f8b0:4004:c07::64").getAddress();
		AAAA a = (AAAA)reserialized(wireAnswer(DNS.AAAA, addr));
		assertArrayEquals(addr, a.getAddress());
		assertEquals("2607:f8b0:4004:c07::64", a.getAddressString());
	}

	@Test
	public void aaaaTextForms() {
		String [][] cases = {
				{"2001:db8::1", "2001:db8::1"},
				{"::1", "::1"},
				{"::", "::"},
				{"fe80::1:2", "fe80::1:2"},
				{"2001:DB8:0:0:0:0:0:1", "2001:db8::1"},
				{"2001:db8:0:1:0:0:0:1", "2001:db8:0:1::1"},	//  longest zero run
				{"2001:db8:0:1:1:1:1:1", "2001:db8:0:1:1:1:1:1"},	//  a single zero group is not '::'
		};
		for(String [] c : cases) {
			AAAA a = new AAAA("x.test");
			a.setAddress(c[0]);
			assertEquals(c[1], a.getAddressString(), c[0]);
		}
		for(String bad : new String[] {"example.com", "10.0.0.1", "2001:db8::1::2", "12345::", "", "localhost"}) {
			AAAA a = new AAAA("x.test");
			assertThrows(IllegalArgumentException.class, () -> a.setAddress(bad), bad);
		}
	}

	// ------------------------------------------------------------ SRV

	@Test
	public void srvFromZoneFile() throws Exception {
		Message m = ask("_sip._tcp.types.test", DNS.SRV);
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertEquals(2, m.getAnswerCount(), m.toString());
		Srv first = null;
		Srv second = null;
		for(RR rr : m.getAnswer()) {
			Srv s = (Srv)rr;
			if( s.getPriority() == 10 ) {
				first = s;
			} else {
				second = s;
			}
		}
		assertEquals(60, first.getWeight());
		assertEquals(5060, first.getPort());
		assertEquals("sip.types.test", first.getTarget(), "relative target completed with the zone");
		assertEquals("backup.example.org", second.getTarget());
	}

	@Test
	public void srvOnTheWire() throws Exception {
		ByteArrayOutputStream rd = new ByteArrayOutputStream();
		DataOutputStream d = new DataOutputStream(rd);
		d.writeShort(1); d.writeShort(2); d.writeShort(443);
		d.write(new byte[] {3,'w','w','w',1,'h',4,'t','e','s','t',0});
		Srv s = (Srv)reserialized(wireAnswer(DNS.SRV, rd.toByteArray()));
		assertEquals(1, s.getPriority());
		assertEquals(2, s.getWeight());
		assertEquals(443, s.getPort());
		assertEquals("www.h.test", s.getTarget());
		//  Not compressed (RFC 2782), even though h.test is already in the message
		assertEquals(6+12, s.getRdLength());
	}

	// ------------------------------------------------------------ CAA

	@Test
	public void caaFromZoneFile() throws Exception {
		Message m = ask("types.test", DNS.CAA);
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertEquals(2, m.getAnswerCount(), m.toString());
		boolean issue = false;
		boolean iodef = false;
		for(RR rr : m.getAnswer()) {
			Caa c = (Caa)rr;
			if( c.getTag().equals("issue") ) {
				issue = c.getValue().equals("letsencrypt.org") && c.getFlags() == 0;
			} else if( c.getTag().equals("iodef") ) {
				iodef = c.getValue().equals("mailto:security@types.test") && c.isCritical();
			}
		}
		assertTrue(issue && iodef, m.getAnswer().toString());
	}

	@Test
	public void caaOnTheWire() throws Exception {
		byte [] tag = "issuewild".getBytes(StandardCharsets.US_ASCII);
		byte [] val = ";".getBytes(StandardCharsets.US_ASCII);
		byte [] rdata = new byte[2+tag.length+val.length];
		rdata[0] = 0;
		rdata[1] = (byte)tag.length;
		System.arraycopy(tag, 0, rdata, 2, tag.length);
		System.arraycopy(val, 0, rdata, 2+tag.length, val.length);
		Caa c = (Caa)reserialized(wireAnswer(DNS.CAA, rdata));
		assertEquals("issuewild", c.getTag());
		assertEquals(";", c.getValue());
		assertEquals(rdata.length, c.getRdLength());
	}

	@Test
	public void zoneListingShowsTheNewTypes() {
		String text = server.getZone("types.test").toString(true);
		assertTrue(text.contains("AAAA\t2001:db8::80"), text);
		assertTrue(text.contains("SRV\t10 60 5060 sip.types.test."), text);
		assertTrue(text.contains("CAA\t0 issue \"letsencrypt.org\""), text);
	}

	// ------------------------------------------------------------ SOA

	@Test
	public void soaFieldsInTheRightOrder() throws Exception {
		//  From our zone file: MNAME is the name server, RNAME the mailbox
		Soa soa = (Soa)ask("types.test", DNS.SOA).getAnswer().get(0);
		assertEquals("ns1.types.test", soa.getMname());
		assertEquals("postmaster.types.test", soa.getRname());
		//  Passed on from upstream: the order is kept (it used to be swapped)
		ByteArrayOutputStream rd = new ByteArrayOutputStream();
		DataOutputStream d = new DataOutputStream(rd);
		d.write(new byte[] {2,'n','s',4,'t','e','s','t',0});
		d.write(new byte[] {2,'p','m',4,'t','e','s','t',0});
		d.writeInt(1); d.writeInt(3600); d.writeInt(1800); d.writeInt(1209600); d.writeInt(300);
		Soa up = (Soa)reserialized(wireAnswer(DNS.SOA, rd.toByteArray()));
		assertEquals("ns.test", up.getMname());
		assertEquals("pm.test", up.getRname());
	}

	// ------------------------------------------------------------ opcodes / transfers

	@Test
	public void unsupportedOpcodesGetNotImp() {
		for(int opcode : new int[] {1 /*IQUERY*/, 2 /*STATUS*/, 4 /*NOTIFY*/, 5 /*UPDATE*/}) {
			Message m = ask("www.types.test", DNS.A, opcode);
			assertEquals(DNS.NOT_IMPLEMENTED, m.getResponseCode(), "opcode "+opcode);
			assertEquals(0, m.getAnswerCount(), "opcode "+opcode);
			assertEquals(4242, m.getID());
			assertEquals(opcode, m.getHeader().getOPCODE());
			assertTrue(m.getHeader().getQR(), "a response");
			List<?> q = m.getQuestion();
			assertEquals(1, q.size(), "question (UPDATE: zone) section echoed");
		}
		assertEquals(DNS.NOERROR, ask("www.types.test", DNS.A).getResponseCode());
	}

	@Test
	public void zoneTransfersAreRefused() {
		for(int type : new int[] {DNS.AXFR, DNS.IXFR}) {
			Message m = ask("types.test", type);
			assertEquals(DNS.REFUSED, m.getResponseCode(), "type "+type);
			assertEquals(0, m.getAnswerCount());
		}
	}
}
