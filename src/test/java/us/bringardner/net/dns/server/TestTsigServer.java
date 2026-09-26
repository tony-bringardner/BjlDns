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
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.ByteBuffer;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.Tsig;

/**
 * TSIG in the server: signed queries over UDP and TCP, TSIG errors,
 * zone transfers allowed by key, signed NOTIFY (rec #42).
 */
public class TestTsigServer {

	private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();
	private static final String SECRET = Base64.getEncoder().encodeToString("0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.US_ASCII));
	private static final Tsig.KeyRing KEYS = Tsig.KeyRing.parse("xfr:hmac-sha256:"+SECRET+" other:hmac-sha256:"+SECRET);
	private static File dir;
	private static DnsServer server;
	private static int port;
	private static Thread udp;
	private static Thread tcp;

	@BeforeAll
	public static void start() throws Exception {
		dir = Files.createTempDirectory("tsig").toFile();
		File zone = new File(dir,"tsig.test.txt");
		try(FileWriter w = new FileWriter(zone)) {
			w.write("$TTL 300\n@\tIN\tSOA\tns1 postmaster ( 3 3600 1800 1209600 300 )\n\t\tNS\tns1\n"
					+"ns1\tIN\tA\t10.0.0.53\nwww\tIN\tA\t10.0.0.80\n");
			for(int i=0; i < 2000; i++ ) {
				w.write("h"+i+"\tIN\tTXT\t\"some text to make the transfer need several messages "+i+"\"\n");
			}
		}
		server = new DnsServer();
		server.addZone(new Zone(zone));
		server.setRecursionAvailable(false);
		server.setTsigKeys(KEYS);
		server.setAxfrKeys("xfr");
		for(int i=0; ; i++ ) {
			try(DatagramSocket probe = new DatagramSocket(0, LOOPBACK)) {
				port = probe.getLocalPort();
			}
			try(ServerSocket s = new ServerSocket(port, 5, LOOPBACK)) {
				break;
			} catch(IOException ex) {
				if( i > 20 ) {
					throw ex;
				}
			}
		}
		DnsServer.setShutdown(false);
		UDPProsessor.initUDPProsessor(port, LOOPBACK, 200);
		TCPProsessor.initTCPProsessor(port, 5, LOOPBACK, 2000);
		udp = new Thread(new UDPProsessor(server,0),"TestTsigUDP");
		udp.setDaemon(true);
		udp.start();
		tcp = new Thread(new TCPProsessor(server,0),"TestTsigTCP");
		tcp.setDaemon(true);
		tcp.start();
	}

	@AfterAll
	public static void stop() throws Exception {
		UDPProsessor.getSock().close();
		TCPProsessor.getServerSocket().close();
		udp.join(3000);
		tcp.join(3000);
		for(File f : dir.listFiles()) {
			f.delete();
		}
		dir.delete();
	}

	private static byte [] query(String name, int type, int id) {
		Message m = new Message();
		m.setQuestion(name, type, DNS.IN);
		m.setID(id);
		return m.toByteArray();
	}

	private static byte [] udp(byte [] req) throws IOException {
		try(DatagramSocket s = new DatagramSocket(0, LOOPBACK)) {
			s.setSoTimeout(3000);
			s.send(new DatagramPacket(req, req.length, LOOPBACK, port));
			byte [] buf = new byte[65535];
			DatagramPacket p = new DatagramPacket(buf, buf.length);
			s.receive(p);
			return java.util.Arrays.copyOf(buf, p.getLength());
		}
	}

	/** Send one TCP request; read responses until stop says so. */
	private static List<byte[]> tcp(byte [] req, java.util.function.Predicate<List<byte[]>> done) throws IOException {
		List<byte[]> ret = new ArrayList<byte[]>();
		try(Socket s = new Socket(LOOPBACK, port)) {
			s.setSoTimeout(5000);
			DataOutputStream out = new DataOutputStream(s.getOutputStream());
			out.writeShort(req.length);
			out.write(req);
			out.flush();
			DataInputStream in = new DataInputStream(s.getInputStream());
			while( !done.test(ret) ) {
				byte [] b = new byte[in.readUnsignedShort()];
				in.readFully(b);
				ret.add(b);
			}
		}
		return ret;
	}

	@Test
	public void signedQueryOverUdpAndTcp() throws Exception {
		Tsig.Session c = Tsig.Session.client(KEYS.get("other"));
		byte [] resp = udp(c.signRequest(query("www.tsig.test", DNS.A, 1)));
		c.verifyResponse(resp);
		assertEquals(1, new Message(new ByteBuffer(resp)).getAnswerCount());

		Tsig.Session t = Tsig.Session.client(KEYS.get("other"));
		byte [] tr = tcp(t.signRequest(query("www.tsig.test", DNS.A, 2)), l -> l.size() == 1).get(0);
		t.verifyResponse(tr);
	}

	@Test
	public void unsignedQueryGetsUnsignedAnswer() throws Exception {
		byte [] resp = udp(query("www.tsig.test", DNS.A, 3));
		assertEquals(null, Tsig.find(resp));
		assertEquals(1, new Message(new ByteBuffer(resp)).getAnswerCount());
	}

	@Test
	public void badSignatureGetsNotAuth() throws Exception {
		Tsig.Session c = Tsig.Session.client(new Tsig.Key("xfr", "hmac-sha256", "wrong secret, wrong secret!!".getBytes(StandardCharsets.US_ASCII)));
		byte [] resp = udp(c.signRequest(query("www.tsig.test", DNS.A, 4)));
		Message m = new Message(new ByteBuffer(resp));
		assertEquals(Tsig.NOTAUTH, m.getResponseCode());
		assertEquals(0, m.getAnswerCount(), "the request was not answered");
		assertEquals(Tsig.BADSIG, Tsig.find(resp).error);
		Tsig.TsigException ex = assertThrows(Tsig.TsigException.class, () -> c.verifyResponse(resp));
		assertEquals(Tsig.BADSIG, ex.error);
	}

	@Test
	public void unknownKeyGetsNotAuth() throws Exception {
		Tsig.Session c = Tsig.Session.client(new Tsig.Key("nobody", "hmac-sha256", new byte[32]));
		byte [] resp = udp(c.signRequest(query("www.tsig.test", DNS.A, 5)));
		assertEquals(Tsig.NOTAUTH, new Message(new ByteBuffer(resp)).getResponseCode());
		assertEquals(Tsig.BADKEY, Tsig.find(resp).error);
	}

	private static boolean ended(List<byte[]> msgs) {
		int soas = 0;
		for(byte [] b : msgs) {
			Message m = new Message(new ByteBuffer(b));
			if( m.getResponseCode() != DNS.NOERROR ) {
				return true;
			}
			for(RR rr : m.getAnswer()) {
				if( rr.getType() == DNS.SOA ) {
					soas++;
				}
			}
		}
		return soas >= 2;
	}

	@Test
	public void transferAllowedByKey() throws Exception {
		//  127.0.0.1 is not in JDns.axfrAllow; the key is in JDns.axfrKeys
		Tsig.Session c = Tsig.Session.client(KEYS.get("xfr"));
		List<byte[]> msgs = tcp(c.signRequest(query("tsig.test", DNS.AXFR, 6)), TestTsigServer::ended);
		assertTrue(msgs.size() > 3, "messages: "+msgs.size());
		int records = 0;
		for(byte [] b : msgs) {
			c.verifyResponse(b);		//  each one, in order
			Message m = new Message(new ByteBuffer(b));
			assertEquals(DNS.NOERROR, m.getResponseCode());
			records += m.getAnswerCount();
		}
		assertEquals(2003+2, records);
	}

	@Test
	public void transferRefusedWithoutAnAllowedKey() throws Exception {
		List<byte[]> unsigned = tcp(query("tsig.test", DNS.AXFR, 7), l -> l.size() == 1);
		assertEquals(DNS.REFUSED, new Message(new ByteBuffer(unsigned.get(0))).getResponseCode());

		Tsig.Session c = Tsig.Session.client(KEYS.get("other"));
		byte [] r = tcp(c.signRequest(query("tsig.test", DNS.AXFR, 8)), l -> l.size() == 1).get(0);
		assertEquals(DNS.REFUSED, new Message(new ByteBuffer(r)).getResponseCode());
		c.verifyResponse(r);		//  the refusal itself is signed
	}

	@Test
	public void serverFudgeSetting() {
		DnsServer s = new DnsServer();
		assertEquals(Tsig.DEFAULT_FUDGE, s.getTsigFudge());
		s.setTsigFudge(60);
		assertEquals(60, s.getTsigFudge());
		assertThrows(IllegalArgumentException.class, () -> s.setTsigFudge(0));
		assertThrows(IllegalArgumentException.class, () -> s.setTsigFudge(70000));
	}

	@Test
	public void unknownAxfrKeyIsAConfigurationError() {
		assertThrows(IllegalArgumentException.class, () -> new DnsServer().setAxfrKeys("xfr"), "no keys set");
	}

	/** A secondary that checks the NOTIFY's TSIG and answers (signed if sign). */
	private static List<Integer> secondary(DatagramSocket sock, boolean sign, int expect) throws Exception {
		List<Integer> errors = new ArrayList<Integer>();
		byte [] buf = new byte[4096];
		for(int i=0; i < expect; i++ ) {
			DatagramPacket p = new DatagramPacket(buf, buf.length);
			sock.receive(p);
			byte [] wire = java.util.Arrays.copyOf(buf, p.getLength());
			Tsig.Session s = Tsig.Session.verifyRequest(KEYS, wire);
			errors.add(s == null ? -1 : s.getError());
			Message m = new Message(new ByteBuffer(wire));
			Message r = new Message();
			r.setID(m.getID());
			r.getHeader().setOPCODE(DNS.NOTIFY);
			r.setMessageTypeResponse();
			r.setQuestion(m.getQuestion().get(0));
			byte [] out = r.toByteArray();
			if( sign && s != null ) {
				out = s.signResponse(out);
			}
			sock.send(new DatagramPacket(out, out.length, p.getSocketAddress()));
		}
		return errors;
	}

	@Test
	public void signedNotify() throws Exception {
		try(DatagramSocket sec = new DatagramSocket(0, LOOPBACK)) {
			sec.setSoTimeout(5000);
			DnsServer s = new DnsServer();
			s.setTsigKeys(KEYS);
			s.setNotifyKey("xfr");
			s.setNotifyTargets("127.0.0.1:"+sec.getLocalPort(), 2, 500);
			ZoneNotifier n = s.getNotifier();
			n.notifyZone(server.getZone("tsig.test"));
			List<Integer> errors = secondary(sec, true, 1);
			assertEquals(Tsig.NOERROR, (int)errors.get(0), "the NOTIFY is signed with the key");
			assertTrue(n.awaitIdle(10_000));
			assertEquals(1, n.getAcknowledged());
			n.shutdown();
		}
	}

	@Test
	public void unsignedAnswerToSignedNotifyIsNotAnAcknowledgement() throws Exception {
		try(DatagramSocket sec = new DatagramSocket(0, LOOPBACK)) {
			sec.setSoTimeout(5000);
			DnsServer s = new DnsServer();
			s.setTsigKeys(KEYS);
			s.setNotifyKey("xfr");
			s.setNotifyTargets("127.0.0.1:"+sec.getLocalPort(), 2, 300);
			ZoneNotifier n = s.getNotifier();
			n.notifyZone(server.getZone("tsig.test"));
			secondary(sec, false, 2);
			assertTrue(n.awaitIdle(10_000));
			assertEquals(0, n.getAcknowledged());
			assertEquals(1, n.getFailed());
			n.shutdown();
		}
	}
}
