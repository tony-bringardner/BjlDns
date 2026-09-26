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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.ByteBuffer;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.Soa;
import us.bringardner.net.dns.resolve.QueryData;

/**
 * Zone transfers (AXFR, RFC 5936) and NOTIFY (RFC 1996) (rec #41).
 */
public class TestZoneTransfer {

	private File dir;
	private DnsServer server;
	private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();
	private static final int TCP = -1;		//  QueryData port for a TCP request

	private static String zoneText(String zone, int serial, String extra) {
		return "$TTL 300\n@\tIN\tSOA\tns1 postmaster ( "+serial+" 3600 1800 1209600 300 )\n"
				+"\t\tNS\tns1\n"
				+"\t\tMX\t10 mail\n"
				+"ns1\tIN\tA\t10.0.0.53\n"
				+"mail\tIN\tA\t10.0.0.25\n"
				+"www\tIN\tA\t10.0.0.80\n"
				+"www\tIN\tAAAA\t2001:db8::80\n"
				+"*.wild\tIN\tA\t10.0.0.99\n"
				+"sub\tIN\tNS\tns.sub\n"
				+"ns.sub\tIN\tA\t10.0.1.53\n"
				+extra;
	}

	private File write(String name, String text) throws IOException {
		File f = new File(dir, name);
		f.getParentFile().mkdirs();
		try(FileWriter w = new FileWriter(f)) {
			w.write(text);
		}
		return f;
	}

	@BeforeEach
	public void setup() throws IOException {
		dir = Files.createTempDirectory("axfr").toFile();
		server = new DnsServer();
		server.addZone(new Zone(write("xfr.test.txt", zoneText("xfr.test", 7, ""))));
		server.setRecursionAvailable(false);
	}

	@AfterEach
	public void cleanup() {
		ZoneNotifier n = server.getNotifier();
		if( n != null ) {
			n.shutdown();
		}
		delete(dir);
	}

	private static void delete(File f) {
		File [] list = f.listFiles();
		if( list != null ) {
			for(File c : list) {
				delete(c);
			}
		}
		f.delete();
	}

	private List<Message> ask(String name, int type, int port) {
		Message q = new Message();
		q.setQuestion(name, type, DNS.IN);
		q.setID(321);
		Message in = new Message(new ByteBuffer(q.toByteArray()));
		List<Message> ret = new ArrayList<Message>();
		for(Message r : server.query(new QueryData(LOOPBACK, port, in))) {
			ret.add(new Message(new ByteBuffer(r.toByteArray())));
		}
		return ret;
	}

	private static List<RR> answers(List<Message> msgs) {
		List<RR> ret = new ArrayList<RR>();
		for(Message m : msgs) {
			ret.addAll(m.getAnswer());
		}
		return ret;
	}

	private static Set<String> keys(List<RR> rrs) {
		Set<String> ret = new HashSet<String>();
		for(RR rr : rrs) {
			ret.add(rr.getName().toLowerCase()+" "+DNS.TYPENAMES[rr.getType()]+" "+rr.getRdataAsString());
		}
		return ret;
	}

	// ------------------------------------------------------------ access

	@Test
	public void refusedByDefault() {
		List<Message> r = ask("xfr.test", DNS.AXFR, TCP);
		assertEquals(1, r.size());
		assertEquals(DNS.REFUSED, r.get(0).getResponseCode());
		assertEquals(0, r.get(0).getAnswerCount());
	}

	@Test
	public void refusedForOtherClientsNamesAndUdp() {
		server.setAxfrAllow("192.0.2.0/24");
		assertEquals(DNS.REFUSED, ask("xfr.test", DNS.AXFR, TCP).get(0).getResponseCode(), "client not allowed");
		server.setAxfrAllow("127.0.0.1");
		assertEquals(DNS.REFUSED, ask("www.xfr.test", DNS.AXFR, TCP).get(0).getResponseCode(), "not a zone name");
		assertEquals(DNS.REFUSED, ask("other.test", DNS.AXFR, TCP).get(0).getResponseCode(), "not our zone");
		assertEquals(DNS.REFUSED, ask("xfr.test", DNS.AXFR, 5353).get(0).getResponseCode(), "AXFR over UDP");
	}

	// ------------------------------------------------------------ AXFR

	@Test
	public void wholeZoneBetweenTwoSoas() {
		server.setAxfrAllow("127.0.0.0/8, ::1");
		List<Message> r = ask("xfr.test", DNS.AXFR, TCP);
		assertEquals(1, r.size(), "a small zone fits in one message");
		Message m = r.get(0);
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertTrue(m.getHeader().getAA());
		assertEquals(321, m.getID());
		assertEquals(1, m.getQuestion().size());
		List<RR> a = answers(r);
		assertEquals(DNS.SOA, a.get(0).getType(), "starts with the SOA");
		assertEquals(DNS.SOA, a.get(a.size()-1).getType(), "ends with the SOA");
		assertEquals(7, ((Soa)a.get(0)).getSerial());
		Set<String> k = keys(a.subList(1, a.size()-1));
		assertEquals(9, a.size()-2, k.toString());
		assertTrue(k.contains("www.xfr.test AAAA 2001:db8::80"), k.toString());
		assertTrue(k.contains("*.wild.xfr.test A 10.0.0.99"), "wildcards as they are: "+k);
		assertTrue(k.contains("sub.xfr.test NS ns.sub.xfr.test."), "delegations: "+k);
		assertTrue(k.contains("ns.sub.xfr.test A 10.0.1.53"), "glue: "+k);
	}

	@Test
	public void bigZoneIsSplitOverMessages() throws Exception {
		StringBuilder extra = new StringBuilder();
		char [] big = new char[900];
		java.util.Arrays.fill(big, 'x');
		for(int i=0; i < 3000; i++ ) {
			extra.append("h").append(i).append("\tIN\tA\t10.1.").append(i/250).append('.').append(i%250).append('\n');
		}
		for(int i=0; i < 200; i++ ) {
			extra.append("t").append(i).append("\tIN\tTXT\t\"").append(big).append("\"\n");
		}
		server.addZone(new Zone(write("big.test.txt", zoneText("big.test", 1, extra.toString()))));
		server.setAxfrAllow("127.0.0.1");
		Message q = new Message();
		q.setQuestion("big.test", DNS.AXFR, DNS.IN);
		List<Message> raw = server.query(new QueryData(LOOPBACK, TCP, new Message(new ByteBuffer(q.toByteArray()))));
		assertTrue(raw.size() > 5, "messages: "+raw.size());
		List<Message> parsed = new ArrayList<Message>();
		for(Message m : raw) {
			byte [] wire = m.toByteArray();
			assertTrue(wire.length <= DnsServer.AXFR_MESSAGE_SIZE, "message of "+wire.length+" bytes");
			Message back = new Message(new ByteBuffer(wire));
			assertTrue(back.getHeader().getAA());
			assertFalse(back.isTruncated());
			parsed.add(back);
		}
		assertEquals(1, parsed.get(0).getQuestion().size());
		List<RR> a = answers(parsed);
		assertEquals(9+3200+2, a.size());
		assertEquals(DNS.SOA, a.get(0).getType());
		assertEquals(DNS.SOA, a.get(a.size()-1).getType());
		assertEquals(3200+9, keys(a.subList(1, a.size()-1)).size(), "every record once");
	}

	@Test
	public void dynamicEntriesAreIncluded() {
		server.setAxfrAllow("127.0.0.1");
		server.addDynamic("www.xfr.test", "10.9.9.9");
		server.addDynamic("new.xfr.test", "10.9.9.10");
		Set<String> k = keys(answers(ask("xfr.test", DNS.AXFR, TCP)));
		assertTrue(k.contains("www.xfr.test A 10.9.9.9"), k.toString());
		assertFalse(k.contains("www.xfr.test A 10.0.0.80"), "the dynamic entry replaces the zone's records at its name, as in answers");
		assertTrue(k.contains("new.xfr.test A 10.9.9.10"), k.toString());
	}

	@Test
	public void ixfr() {
		server.setAxfrAllow("127.0.0.1");
		List<Message> udp = ask("xfr.test", DNS.IXFR, 5353);
		assertEquals(1, udp.size());
		assertEquals(1, udp.get(0).getAnswerCount(), "IXFR over UDP: just the SOA");
		assertEquals(DNS.SOA, udp.get(0).getAnswer().get(0).getType());
		List<RR> tcp = answers(ask("xfr.test", DNS.IXFR, TCP));
		assertEquals(11, tcp.size(), "IXFR over TCP: the whole zone (AXFR form)");
	}

	@Test
	public void overRealTcp() throws Exception {
		server.setAxfrAllow("127.0.0.1");
		int port;
		try(ServerSocket probe = new ServerSocket(0, 5, LOOPBACK)) {
			port = probe.getLocalPort();
		}
		DnsServer.setShutdown(false);
		TCPProsessor.initTCPProsessor(port, 5, LOOPBACK, 2000);
		Thread t = new Thread(new TCPProsessor(server,0),"TestAxfrTCP");
		t.setDaemon(true);
		t.start();
		try(Socket s = new Socket(LOOPBACK, port)) {
			s.setSoTimeout(5000);
			Message q = new Message();
			q.setQuestion("xfr.test", DNS.AXFR, DNS.IN);
			q.setID(77);
			byte [] b = q.toByteArray();
			DataOutputStream out = new DataOutputStream(s.getOutputStream());
			out.writeShort(b.length);
			out.write(b);
			out.flush();
			DataInputStream in = new DataInputStream(s.getInputStream());
			List<RR> all = new ArrayList<RR>();
			int soas = 0;
			while( soas < 2 ) {
				byte [] buf = new byte[in.readUnsignedShort()];
				in.readFully(buf);
				Message m = new Message(new ByteBuffer(buf));
				assertEquals(77, m.getID());
				for(RR rr : m.getAnswer()) {
					all.add(rr);
					if( rr.getType() == DNS.SOA ) {
						soas++;
					}
				}
			}
			assertEquals(11, all.size());
		} finally {
			TCPProsessor.getServerSocket().close();
			t.join(3000);
		}
	}

	// ------------------------------------------------------------ AddressMatcher

	@Test
	public void addressMatcher() throws Exception {
		AddressMatcher m = AddressMatcher.parse("192.0.2.10, 10.0.0.0/8 2001:db8::/32,::1");
		assertTrue(m.matches(InetAddress.getByName("192.0.2.10")));
		assertFalse(m.matches(InetAddress.getByName("192.0.2.11")));
		assertTrue(m.matches(InetAddress.getByName("10.200.3.4")));
		assertFalse(m.matches(InetAddress.getByName("11.0.0.1")));
		assertTrue(m.matches(InetAddress.getByName("2001:db8:ffff::1")));
		assertFalse(m.matches(InetAddress.getByName("2001:db9::1")));
		assertTrue(m.matches(InetAddress.getByName("::1")));
		assertFalse(AddressMatcher.parse("172.16.0.0/12").matches(InetAddress.getByName("172.32.0.1")));
		assertTrue(AddressMatcher.parse("172.16.0.0/12").matches(InetAddress.getByName("172.31.255.1")));
		assertFalse(AddressMatcher.parse(null).matches(LOOPBACK));
		for(String bad : new String[] {"secondary.example", "10.0.0.0/33", "10.0.0/8", "::1/200", "1.2.3.4/x"}) {
			assertThrows(IllegalArgumentException.class, () -> AddressMatcher.parse(bad), bad);
		}
	}

	// ------------------------------------------------------------ NOTIFY

	@Test
	public void notifyTargets() {
		List<InetSocketAddress> t = ZoneNotifier.parseTargets("192.0.2.2, 192.0.2.3:5353 [2001:db8::2]:5300 2001:db8::3");
		assertEquals(4, t.size());
		assertEquals(53, t.get(0).getPort());
		assertEquals(5353, t.get(1).getPort());
		assertEquals(5300, t.get(2).getPort());
		assertEquals(53, t.get(3).getPort());
		for(String bad : new String[] {"secondary.example", "192.0.2.2:0", "192.0.2.2:70000", "[2001:db8::2"}) {
			assertThrows(IllegalArgumentException.class, () -> ZoneNotifier.parseTargets(bad), bad);
		}
	}

	/** A secondary that records NOTIFY messages and (if answer) acknowledges them. */
	private static class FakeSecondary implements AutoCloseable {
		final DatagramSocket sock = new DatagramSocket(0, LOOPBACK);
		final List<Message> received = new java.util.concurrent.CopyOnWriteArrayList<Message>();
		final Thread thread;

		FakeSecondary(boolean answer) throws IOException {
			thread = new Thread(() -> {
				byte [] buf = new byte[4096];
				while( !sock.isClosed() ) {
					try {
						DatagramPacket p = new DatagramPacket(buf, buf.length);
						sock.receive(p);
						Message m = new Message(new ByteBuffer(java.util.Arrays.copyOf(buf, p.getLength())));
						received.add(m);
						if( answer ) {
							Message r = new Message();
							r.setID(m.getID());
							r.getHeader().setOPCODE(DNS.NOTIFY);
							r.setMessageTypeResponse();
							r.setQuestion(m.getQuestion().get(0));
							byte [] b = r.toByteArray();
							sock.send(new DatagramPacket(b, b.length, p.getSocketAddress()));
						}
					} catch(IOException ex) {
						//  closed
					}
				}
			}, "FakeSecondary");
			thread.setDaemon(true);
			thread.start();
		}

		String target() {
			return "127.0.0.1:"+sock.getLocalPort();
		}

		@Override
		public void close() {
			sock.close();
		}
	}

	@Test
	public void notifyOnLoadAndOnSerialChange() throws Exception {
		File zones = new File(dir,"zones");
		File zf = write("zones/n.test.txt", zoneText("n.test", 1, ""));
		String savedDir = System.getProperty(DnsServer.PROP_ZONE_DIR);
		String savedDefault = System.getProperty(DnsServer.PROP_DEFAULT_ZONE);
		System.setProperty(DnsServer.PROP_ZONE_DIR, zones.getAbsolutePath());
		System.setProperty(DnsServer.PROP_DEFAULT_ZONE, "n.test");
		try(FakeSecondary sec = new FakeSecondary(true)) {
			server.setNotifyTargets(sec.target(), 3, 1000);
			server.loadZones();
			ZoneNotifier n = server.getNotifier();
			assertTrue(n.awaitIdle(10_000));
			assertEquals(1, sec.received.size(), "NOTIFY when the zone is loaded");
			Message m = sec.received.get(0);
			assertEquals(DNS.NOTIFY, m.getHeader().getOPCODE());
			assertTrue(m.getHeader().getAA());
			assertTrue(m.isQuery());
			assertEquals("n.test", m.getQuestion().get(0).getName());
			assertEquals(DNS.SOA, m.getQuestion().get(0).getType());
			assertEquals(1, ((Soa)m.getAnswer().get(0)).getSerial());
			assertEquals(1, n.getAcknowledged());

			//  Reload without a serial change: no NOTIFY
			zf.setLastModified(zf.lastModified()+2000);
			server.loadZones();
			assertTrue(n.awaitIdle(10_000));
			assertEquals(1, sec.received.size());

			//  New serial: NOTIFY again
			try(FileWriter w = new FileWriter(zf)) {
				w.write(zoneText("n.test", 2, "extra\tIN\tA\t10.0.0.7\n"));
			}
			zf.setLastModified(zf.lastModified()+4000);
			server.loadZones();
			assertTrue(n.awaitIdle(10_000));
			assertEquals(2, sec.received.size());
			assertEquals(2, ((Soa)sec.received.get(1).getAnswer().get(0)).getSerial());
			assertEquals(2, n.getAcknowledged());
			assertEquals(0, n.getFailed());
		} finally {
			restore(DnsServer.PROP_ZONE_DIR, savedDir);
			restore(DnsServer.PROP_DEFAULT_ZONE, savedDefault);
		}
	}

	@Test
	public void unansweredNotifyIsRetried() throws Exception {
		try(FakeSecondary sec = new FakeSecondary(false)) {
			server.setNotifyTargets(sec.target(), 3, 100);
			ZoneNotifier n = server.getNotifier();
			n.notifyZone(server.getZone("xfr.test"));
			assertTrue(n.awaitIdle(10_000));
			assertEquals(3, sec.received.size(), "one message per attempt");
			assertEquals(3, n.getSent());
			assertEquals(1, n.getFailed());
			assertEquals(0, n.getAcknowledged());
		}
	}

	private static void restore(String key, String value) {
		if( value == null ) {
			System.clearProperty(key);
		} else {
			System.setProperty(key, value);
		}
	}
}
