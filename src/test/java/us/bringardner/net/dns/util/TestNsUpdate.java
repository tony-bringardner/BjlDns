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
package us.bringardner.net.dns.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.StringReader;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.ByteBuffer;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.Tsig;
import us.bringardner.net.dns.server.DnsServer;
import us.bringardner.net.dns.server.TCPProsessor;
import us.bringardner.net.dns.server.UDPProsessor;
import us.bringardner.net.dns.server.Zone;

/**
 * NsUpdate against a DnsServer on the loopback. The expected output and
 * resulting zone in TestFiles/nsupdate/expected.txt were recorded from the
 * ISC nsupdate 9.18 against the same zone, so these tests check that
 * NsUpdate prints (and changes) exactly what nsupdate does.
 */
public class TestNsUpdate {

	private static final File FIXTURES = new File("src/test/java/resources/TestFiles/nsupdate");
	private static final String BIND_VERSION = "9.18.39-0ubuntu0.24.04.7-Ubuntu";

	private static DnsServer server;
	private static int port;
	private static File dir;
	private static DatagramSocket sink;
	private static int closed;

	@BeforeAll
	public static void startServer() throws Exception {
		dir = Files.createTempDirectory("nsupdate").toFile();
		String secret = null;
		for(String line : Files.readAllLines(new File(FIXTURES, "upd.conf").toPath())) {
			if( line.contains("secret") ) {
				secret = line.replaceAll(".*\"(.*)\".*", "$1");
			}
		}
		server = new DnsServer();
		server.setRecursionAvailable(false);
		server.setAxfrAllow("127.0.0.0/8");
		server.setTsigKeys(Tsig.KeyRing.parse("upd.key:hmac-sha256:"+secret));
		server.setUpdateKeys("upd.key");
		server.setUpdateAllow("127.0.0.0/8");
		freshZone();
		for(int i=0; ; i++ ) {
			try(DatagramSocket probe = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
				port = probe.getLocalPort();
			}
			try(ServerSocket tcp = new ServerSocket(port, 5, InetAddress.getLoopbackAddress())) {
				break;
			} catch(java.io.IOException ex) {
				if( i > 20 ) {
					throw ex;
				}
			}
		}
		DnsServer.setShutdown(false);
		UDPProsessor.initUDPProsessor(port, InetAddress.getLoopbackAddress(), 200);
		TCPProsessor.initTCPProsessor(port, 5, InetAddress.getLoopbackAddress(), 200);
		Thread u = new Thread(new UDPProsessor(server, 0), "TestNsUpdateUDP");
		u.setDaemon(true);
		u.start();
		Thread t = new Thread(new TCPProsessor(server, 0), "TestNsUpdateTCP");
		t.setDaemon(true);
		t.start();
		//  A UDP port that never answers, and a closed one
		sink = new DatagramSocket(0, InetAddress.getLoopbackAddress());
		try(ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
			closed = s.getLocalPort();
		}
	}

	/** A new copy of the zone (each case starts from the file). */
	private static void freshZone() throws Exception {
		File d = Files.createTempDirectory(dir.toPath(), "z").toFile();
		File z = new File(d, "upd.test.txt");
		Files.copy(new File(FIXTURES, "upd.test.txt").toPath(), z.toPath(), StandardCopyOption.REPLACE_EXISTING);
		server.addZone(new Zone(z));
	}

	@AfterAll
	public static void stopServer() throws Exception {
		NsUpdate.setOut(System.out);
		NsUpdate.setErr(System.err);
		NsUpdate.setInteractive(null);
		UDPProsessor.getSock().close();
		TCPProsessor.getServerSocket().close();
		sink.close();
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

	static class Result {
		int exit;
		String out;
		String err;
	}

	private static Result run(String stdin, String ... args) throws Exception {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		ByteArrayOutputStream err = new ByteArrayOutputStream();
		NsUpdate.setOut(new PrintStream(out, true, "UTF-8"));
		NsUpdate.setErr(new PrintStream(err, true, "UTF-8"));
		NsUpdate.setIn(new BufferedReader(new StringReader(stdin)));
		NsUpdate.setInteractive(false);
		Result r = new Result();
		try {
			r.exit = NsUpdate.run(args);
		} finally {
			NsUpdate.setOut(System.out);
			NsUpdate.setErr(System.err);
		}
		r.out = out.toString("UTF-8");
		r.err = err.toString("UTF-8");
		return r;
	}

	/** The zone as dig prints an AXFR. */
	private static String axfr() throws Exception {
		Message q = new Message();
		q.setQuestion("upd.test", 252, DNS.IN);
		q.setID(4242);
		byte [] data = q.toByteArray();
		StringBuilder sb = new StringBuilder();
		try(Socket s = new Socket(InetAddress.getLoopbackAddress(), port)) {
			s.setSoTimeout(5000);
			OutputStream os = s.getOutputStream();
			os.write(new byte[] {(byte)(data.length >> 8), (byte)data.length});
			os.write(data);
			os.flush();
			DataInputStream in = new DataInputStream(s.getInputStream());
			int soas = 0;
			while( soas < 2 ) {
				byte [] resp = new byte[in.readUnsignedShort()];
				in.readFully(resp);
				Message m = new Message(new ByteBuffer(resp));
				for(RR rr : m.getAnswer()) {
					sb.append(NsUpdate.recordLine(rr));
					if( rr.getType() == DNS.SOA ) {
						soas++;
					}
				}
			}
		}
		return sb.toString();
	}

	static class Case {
		String name;
		List<String> args = new ArrayList<String>();
		String stdin;
		int exit;
		StringBuilder out = new StringBuilder();
		StringBuilder err = new StringBuilder();
		StringBuilder zone;
	}

	private static String unescape(String s) {
		StringBuilder sb = new StringBuilder();
		for(int i=0; i < s.length(); i++ ) {
			char c = s.charAt(i);
			if( c == '\\' && i+1 < s.length() ) {
				char n = s.charAt(++i);
				sb.append(n == 'n' ? '\n' : n == 't' ? '\t' : n);
			} else {
				sb.append(c);
			}
		}
		return sb.toString();
	}

	private static List<Case> recorded() throws Exception {
		List<Case> ret = new ArrayList<Case>();
		Case c = null;
		StringBuilder into = null;
		for(String line : Files.readAllLines(new File(FIXTURES, "expected.txt").toPath(), StandardCharsets.UTF_8)) {
			if( line.startsWith("=== ") ) {
				c = new Case();
				c.name = line.substring(4);
				ret.add(c);
				into = null;
			} else if( c == null ) {
				continue;
			} else if( line.equals("--- stdout") ) {
				into = c.out;
			} else if( line.equals("--- stderr") ) {
				into = c.err;
			} else if( line.equals("--- zone") ) {
				c.zone = new StringBuilder();
				into = c.zone;
			} else if( into != null ) {
				if( line.equals("\\ no newline") ) {
					into.setLength(into.length()-1);
				} else {
					into.append(line).append('\n');
				}
			} else if( line.startsWith("args: ") ) {
				for(String a : line.substring(6).split("\t")) {
					if( !a.isEmpty() ) {
						c.args.add(a);
					}
				}
			} else if( line.startsWith("stdin: ") ) {
				c.stdin = unescape(line.substring(7));
			} else if( line.startsWith("exit: ") ) {
				c.exit = Integer.parseInt(line.substring(6));
			}
		}
		return ret;
	}

	private static File script;

	private static String subst(String s) throws Exception {
		if( script == null ) {
			//  script.txt with the port filled in
			script = new File(dir, "script.txt");
			Files.write(script.toPath(), new String(Files.readAllBytes(new File(FIXTURES, "script.txt").toPath()), StandardCharsets.UTF_8)
					.replace("${PORT}", String.valueOf(port)).getBytes(StandardCharsets.UTF_8));
		}
		return s.replace("${SCRIPT}", script.getPath()).replace("${PORT}", String.valueOf(port)).replace("${DIR}", FIXTURES.getPath())
				.replace("${SINK}", String.valueOf(sink.getLocalPort())).replace("${CLOSED}", String.valueOf(closed));
	}

	/**
	 * What varies between runs: message IDs, TSIG times and MACs, the version;
	 * and the time stamped lines of BIND's log (libdns messages, e.g. about
	 * the text of a record, that NsUpdate does not print).
	 */
	static String normalize(String s) {
		s = s.replaceAll("(?m)^\\d\\d-\\w\\w\\w-\\d{4} [\\d:.]+ .*\n", "");
		//  A UDP request to a closed port fails at once with "connection refused"
		//  only when the ICMP port unreachable comes back. Linux sends it; macOS
		//  rate-limits (and may drop) it, and then the request times out, for
		//  nsupdate too. Either is right, so they compare equal.
		s = s.replaceAll("(?m)^(; Communication with \\S+ failed: )(connection refused|timed out)$", "$1no answer");
		java.util.regex.Matcher m = java.util.regex.Pattern.compile("id: +\\d+").matcher(s);
		StringBuffer sb = new StringBuffer();
		while( m.find() ) {
			m.appendReplacement(sb, "id:"+"_".repeat(m.group().length()-3));
		}
		m.appendTail(sb);
		s = sb.toString();
		s = s.replaceAll("(TSIG\\thmac-[a-z0-9]+\\. )\\d+ (\\d+) (\\d+) \\S+ \\d+", "$1T $2 $3 MAC ID");
		s = s.replaceAll("(TSIG\\thmac-[a-z0-9]+\\. )\\d+ (\\d+) 0 \\d+", "$1T $2 0 ID");
		return s.replace(BIND_VERSION, NsUpdate.VERSION);
	}

	@Test
	public void sameAsTheIscNsupdate() throws Exception {
		List<Case> cases = recorded();
		assertTrue(cases.size() >= 60, "cases: "+cases.size());
		List<String> failures = new ArrayList<String>();
		for(Case c : cases) {
			freshZone();
			List<String> args = new ArrayList<String>();
			for(String a : c.args) {
				args.add(subst(a));
			}
			Result r = run(subst(c.stdin), args.toArray(new String[0]));
			String eo = normalize(subst(c.out.toString()));
			String ee = normalize(subst(c.err.toString()));
			String ao = normalize(r.out);
			String ae = normalize(r.err);
			StringBuilder why = new StringBuilder();
			if( c.exit != r.exit ) {
				why.append("exit ").append(c.exit).append(" != ").append(r.exit).append('\n');
			}
			if( !eo.equals(ao) ) {
				why.append("--- stdout expected\n").append(eo).append("--- got\n").append(ao);
			}
			if( !ee.equals(ae) ) {
				why.append("--- stderr expected\n").append(ee).append("--- got\n").append(ae);
			}
			if( c.zone != null ) {
				String z = axfr();
				if( !c.zone.toString().equals(z) ) {
					why.append("--- zone expected\n").append(c.zone).append("--- got\n").append(z);
				}
			}
			if( why.length() > 0 ) {
				failures.add(c.name+" "+c.args+"\n"+why);
			}
		}
		assertEquals("", String.join("\n", failures));
	}

	@Test
	public void strsepAsNsupdate() {
		String [] rest = {"  add  www 300\tA 1.2.3.4"};
		assertEquals("add", NsUpdate.strsep(rest, " \t\r\n"));
		assertEquals(" www 300\tA 1.2.3.4", rest[0]);
		assertEquals("www", NsUpdate.strsep(rest, " \t\r\n"));
		assertEquals("300", NsUpdate.strsep(rest, " \t\r\n"));
		assertEquals("A", NsUpdate.strsep(rest, " \t\r\n"));
		assertEquals("1.2.3.4", NsUpdate.strsep(rest, " \t\r\n"));
		assertNull(rest[0]);
		assertNull(NsUpdate.strsep(rest, " \t\r\n"));
	}

	@Test
	public void checkNames() {
		assertTrue(NsUpdate.isHostname("www.example.com.", false));
		assertTrue(NsUpdate.isHostname("*.example.com.", true));
		assertFalse(NsUpdate.isHostname("*.example.com.", false));
		assertFalse(NsUpdate.isHostname("bad_name.example.com.", false));
		assertFalse(NsUpdate.isHostname("-a.example.com.", false));
		assertFalse(NsUpdate.isHostname("a-.example.com.", false));
		assertTrue(NsUpdate.isHostname("a-b.example.com.", false));
		assertTrue(NsUpdate.isMailbox("first.last.example.com."));
		assertTrue(NsUpdate.isMailbox("hostmaster."));
		assertNull(NsUpdate.checkOwner("gc._msdcs.example.com.", DNS.A));
		assertNull(NsUpdate.checkOwner("x._spf.example.com.", DNS.A));
		assertEquals("_x.example.com.", NsUpdate.checkOwner("_x.example.com.", DNS.A));
		assertNull(NsUpdate.checkOwner("_x.example.com.", DNS.TXT));
	}

	@Test
	public void columnsAsBind() {
		assertEquals("www.upd.test.\t\t300\tIN\tA\t10.0.0.1\n", NsUpdate.columns("www.upd.test.", "300", "IN", "A", "10.0.0.1"));
		assertEquals("a-very-long-owner-name-for-columns.upd.test. 86400 IN MX 10 x.\n",
				NsUpdate.columns("a-very-long-owner-name-for-columns.upd.test.", "86400", "IN", "MX", "10 x."));
		assertEquals("t.\t\t\t300\tIN\tNSEC3PARAM 1 0 0 -\n", NsUpdate.columns("t.", "300", "IN", "NSEC3PARAM", "1 0 0 -"));
		assertEquals(";upd.test.\t\t\tIN\tSOA\n", NsUpdate.questionLine("upd.test.", DNS.IN, DNS.SOA));
	}
}
