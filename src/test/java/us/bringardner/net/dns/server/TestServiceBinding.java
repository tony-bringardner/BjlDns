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
import java.nio.file.Files;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.ByteBuffer;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.DnsFormatException;
import us.bringardner.net.dns.Https;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.Svcb;
import us.bringardner.net.dns.resolve.QueryData;

/**
 * HTTPS and SVCB records (RFC 9460) in zone files and on the wire (rec #39).
 */
public class TestServiceBinding {

	private static File dir;
	private static DnsServer server;

	@BeforeAll
	public static void setup() throws IOException {
		dir = Files.createTempDirectory("svcb").toFile();
		File zone = new File(dir,"svc.test.txt");
		try(FileWriter w = new FileWriter(zone)) {
			w.write("$TTL 300\n"
					+"@\tIN\tSOA\tns1 postmaster ( 1 3600 1800 1209600 300 )\n"
					+"\t\tNS\tns1\n"
					+"\t\tHTTPS\t1 . alpn=h2,h3 ipv4hint=192.0.2.1,192.0.2.2 ipv6hint=2001:db8::1 port=8443\n"
					+"ns1\tIN\tA\t10.0.0.53\n"
					+"www\tIN\tHTTPS\t0 cdn.example.net.\n"
					+"_8443._foo\tIN\tSVCB\t2 svc mandatory=alpn alpn=foo no-default-alpn key65000=\"hi there\" ech=AQID\n");
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

	private static Message ask(String name, int type) {
		Message q = new Message();
		q.setQuestion(name, type, DNS.IN);
		Message in = new Message(new ByteBuffer(q.toByteArray()));
		Message r = server.query(new QueryData(InetAddress.getLoopbackAddress(), 5353, in)).get(0);
		return new Message(new ByteBuffer(r.toByteArray()));
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

	/** The rdata bytes a record has on the wire. */
	private static byte [] wireRdata(RR rr) {
		Message m = new Message();
		m.setQuestion("h.test", rr.getType(), DNS.IN);
		m.getAnswer().add(rr);
		Message back = new Message(new ByteBuffer(m.toByteArray()));
		RR r = back.getAnswer().get(0);
		return r.getRdata();
	}

	private static byte [] hex(String h) {
		h = h.replaceAll("[^0-9a-fA-F]", "");
		byte [] ret = new byte[h.length()/2];
		for(int i=0; i < ret.length; i++ ) {
			ret[i] = (byte)Integer.parseInt(h.substring(i*2, i*2+2), 16);
		}
		return ret;
	}

	private static Svcb svcb(String target, int priority, String ... params) {
		Svcb s = new Svcb("h.test");
		s.setPriority(priority);
		s.setTarget(target);
		s.setParams(Arrays.asList(params));
		return s;
	}

	// ------------------------------------------------------------ RFC 9460 Appendix D test vectors

	@Test
	public void rfcVectorAliasMode() {
		assertArrayEquals(hex("0000 03666f6f076578616d706c6503636f6d00"), wireRdata(svcb("foo.example.com", 0)));
	}

	@Test
	public void rfcVectorGenericKey() {
		Svcb s = svcb("foo.example.com", 1, "key667=hello");
		assertArrayEquals(hex("0001 03666f6f076578616d706c6503636f6d00 029b 0005 68656c6c6f"), wireRdata(s));
	}

	@Test
	public void rfcVectorIpv6Hints() {
		Svcb s = svcb("", 1, "ipv6hint=2001:db8::1,2001:db8::53:1");
		assertArrayEquals(hex("0001 00 0006 0020 20010db8000000000000000000000001 20010db8000000000000000000530001"), wireRdata(s));
	}

	@Test
	public void rfcVectorMandatoryAndAlpn() {
		//  Keys are written in order, whatever order the zone file used
		Svcb s = svcb("foo.example.org", 16, "alpn=h2,h3-19", "mandatory=ipv4hint,alpn", "ipv4hint=192.0.2.1");
		assertArrayEquals(hex("0010 03666f6f076578616d706c65036f726700 0000 0004 00010004 0001 0009 02683205 6833 2d3139 0004 0004 c0000201"), wireRdata(s));
		assertEquals("16 foo.example.org. mandatory=alpn,ipv4hint alpn=h2,h3-19 ipv4hint=192.0.2.1", s.getRdataAsString());
	}

	@Test
	public void rfcVectorEscapedAlpn() {
		//  alpn value "f\\oo,bar" and "h2" -> ids "f\oo,bar" and "h2"
		Svcb s = svcb("foo.example.org", 16, "alpn=f\\\\oo\\,bar,h2");
		assertArrayEquals(hex("0010 03666f6f076578616d706c65036f726700 0001 000c 08 665c6f6f2c626172 02 6832"), wireRdata(s));
		assertEquals(Arrays.asList("f\\oo,bar","h2"), s.getAlpn());
	}

	// ------------------------------------------------------------ zone file

	@Test
	public void httpsServiceModeFromZoneFile() throws Exception {
		Message m = ask("svc.test", DNS.HTTPS);
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertEquals(1, m.getAnswerCount(), m.toString());
		Https h = (Https)m.getAnswer().get(0);
		assertEquals(1, h.getPriority());
		assertEquals("", h.getTarget(), "'.' = the owner");
		assertEquals(Arrays.asList("h2","h3"), h.getAlpn());
		assertEquals(8443, h.getPort());
		assertEquals("192.0.2.1,192.0.2.2", h.valueString(Svcb.KEY_IPV4HINT));
		assertEquals("2001:db8::1", h.valueString(Svcb.KEY_IPV6HINT));
	}

	@Test
	public void httpsAliasModeFromZoneFile() throws Exception {
		Https h = (Https)ask("www.svc.test", DNS.HTTPS).getAnswer().get(0);
		assertTrue(h.isAliasMode());
		assertEquals("cdn.example.net", h.getTarget());
		assertTrue(h.getParams().isEmpty());
	}

	@Test
	public void svcbWithAllKindsOfParams() throws Exception {
		Svcb s = (Svcb)ask("_8443._foo.svc.test", DNS.SVCB).getAnswer().get(0);
		assertEquals(DNS.SVCB, s.getType());
		assertEquals("svc.svc.test", s.getTarget(), "relative target completed with the zone");
		assertEquals("alpn", s.valueString(Svcb.KEY_MANDATORY));
		assertEquals(Arrays.asList("foo"), s.getAlpn());
		assertEquals("", s.valueString(Svcb.KEY_NO_DEFAULT_ALPN));
		assertArrayEquals(new byte[] {1,2,3}, s.getParam(Svcb.KEY_ECH));
		assertEquals("hi there", new String(s.getParam(65000), "US-ASCII"));
		assertEquals("2 svc.svc.test. mandatory=alpn alpn=foo no-default-alpn ech=AQID key65000=\"hi\\032there\"", s.getRdataAsString());
	}

	@Test
	public void zoneListingShowsServiceBindings() {
		String text = server.getZone("svc.test").toString(true);
		assertTrue(text.contains("HTTPS\t1 . alpn=h2,h3 port=8443 ipv4hint=192.0.2.1,192.0.2.2 ipv6hint=2001:db8::1"), text);
		assertTrue(text.contains("HTTPS\t0 cdn.example.net."), text);
	}

	@Test
	public void invalidParamsAreRejected() {
		String [][] bad = {
				{"0","alpn=h2"},					//  AliasMode with params
				{"1","alpn=h2","alpn=h3"},			//  twice
				{"1","mandatory=port","alpn=h2"},	//  mandatory key missing
				{"1","mandatory=mandatory"},		//  lists itself
				{"1","no-default-alpn"},			//  without alpn
				{"1","port=70000"},
				{"1","port"},
				{"1","ipv4hint=1.2.3"},
				{"1","ipv6hint=10.0.0.1"},
				{"1","ech=@@@"},
				{"1","nosuchkey=1"},
				{"1","alpn=h2,,h3"},
		};
		for(String [] b : bad) {
			List<String> p = Arrays.asList(b).subList(1, b.length);
			assertThrows(IllegalArgumentException.class, () -> svcb("x.test", Integer.parseInt(b[0]), p.toArray(new String[0])), String.join(" ", b));
		}
	}

	@Test
	public void badZoneLineNamesTheLine() throws Exception {
		File f = new File(dir,"bad.test.txt");
		try(FileWriter w = new FileWriter(f)) {
			w.write("@\tIN\tSOA\tns1 postmaster ( 1 3600 1800 1209600 300 )\n\t\tNS\tns1\n@\tIN\tHTTPS\t0 . alpn=h2\n");
		}
		IOException ex = assertThrows(IOException.class, () -> new Zone(f));
		assertTrue(ex.getMessage().contains("line 3") && ex.getMessage().contains("AliasMode"), ex.getMessage());
		f.delete();
	}

	// ------------------------------------------------------------ wire

	@Test
	public void passedOnUnchanged() throws Exception {
		byte [] rdata = hex("0001 00 0001 0006 026832 026833 0003 0002 20fb");
		Message m = new Message(new ByteBuffer(wireAnswer(DNS.HTTPS, rdata)));
		Https h = (Https)m.getAnswer().get(0);
		assertEquals(Arrays.asList("h2","h3"), h.getAlpn());
		assertEquals(8443, h.getPort());
		Message again = new Message(new ByteBuffer(m.toByteArray()));
		assertArrayEquals(rdata, again.getAnswer().get(0).getRdata());
	}

	@Test
	public void malformedWireData() {
		//  Keys out of order, and a value longer than the record
		for(String h : new String[] {"0001 00 0003 0002 20fb 0001 0003 026832", "0001 00 0001 0009 026832"}) {
			assertThrows(DnsFormatException.class, () -> new Message(new ByteBuffer(wireAnswer(DNS.HTTPS, hex(h)))).getAnswer().get(0), h);
		}
	}
}
