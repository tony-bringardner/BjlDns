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
package us.bringardner.net.dns;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintStream;
import java.io.StringReader;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.server.DnsServer;
import us.bringardner.net.dns.server.TCPProsessor;
import us.bringardner.net.dns.server.UDPProsessor;
import us.bringardner.net.dns.server.Zone;
import us.bringardner.net.dns.util.NsLookup;
import us.bringardner.net.dns.util.NsLookupAccess;

/**
 * NsLookup against a DnsServer on the loopback, so it runs without the
 * internet. The expected output in TestFiles/nslookup/expected.txt was
 * recorded from the Linux nslookup (ISC BIND 9.18) against the same zones,
 * so these tests check that NsLookup prints exactly what nslookup prints.
 */
public class TestNsLookupOffline {

	private static final File FIXTURES = new File("src/test/java/resources/TestFiles/nslookup");

	private static int port;

	@BeforeAll
	public static void startServer() throws Exception {
		DnsServer server = new DnsServer();
		for(String f : new String[] {"nsl.test.txt", "1.10.in-addr.arpa.txt", "8.b.d.0.1.0.0.2.ip6.arpa.txt"}) {
			server.addZone(new Zone(new File(FIXTURES, f)));
		}
		server.setRecursionAvailable(false);
		port = freePort();
		DnsServer.setShutdown(false);
		UDPProsessor.initUDPProsessor(port, InetAddress.getLoopbackAddress(), 200);
		TCPProsessor.initTCPProsessor(port, 5, InetAddress.getLoopbackAddress(), 200);
		Thread u = new Thread(new UDPProsessor(server,0),"TestNsLookupUDP");
		u.setDaemon(true);
		u.start();
		Thread t = new Thread(new TCPProsessor(server,0),"TestNsLookupTCP");
		t.setDaemon(true);
		t.start();
	}

	/** A port that is free for both UDP and TCP. */
	private static int freePort() throws Exception {
		for(int i=0; ; i++ ) {
			int p;
			try(DatagramSocket probe = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
				p = probe.getLocalPort();
			}
			try(ServerSocket tcp = new ServerSocket(p, 5, InetAddress.getLoopbackAddress())) {
				return p;
			} catch(java.io.IOException ex) {
				if( i > 20 ) {
					throw ex;
				}
			}
		}
	}

	@AfterAll
	public static void stopServer() throws Exception {
		NsLookup.setOut(System.out);
		NsLookup.setErr(System.err);
		NsLookup.setInteractive(null);
		UDPProsessor.getSock().close();
		TCPProsessor.getServerSocket().close();
	}

	static class Result {
		String out;
		String err;
		int exit;

		@Override
		public String toString() {
			return "exit "+exit+"\n"+out+(err.isEmpty() ? "" : "stderr: "+err);
		}
	}

	/** Run NsLookup (as with stdin piped: no prompt). */
	private static Result run(String stdin, String ... args) throws Exception {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		ByteArrayOutputStream err = new ByteArrayOutputStream();
		NsLookup.setOut(new PrintStream(out, true, "UTF-8"));
		NsLookup.setErr(new PrintStream(err, true, "UTF-8"));
		NsLookup.setIn(new BufferedReader(new StringReader(stdin == null ? "" : stdin)));
		NsLookup.setInteractive(false);
		Result r = new Result();
		String saved = System.getProperty(NsLookup.PROP_RESOLV_CONF);
		//  The recording machine's resolv.conf, not this one's (for its options)
		System.setProperty(NsLookup.PROP_RESOLV_CONF, new File(FIXTURES, "resolv.conf").getPath());
		try {
			r.exit = NsLookup.run(args);
		} finally {
			if( saved == null ) {
				System.clearProperty(NsLookup.PROP_RESOLV_CONF);
			} else {
				System.setProperty(NsLookup.PROP_RESOLV_CONF, saved);
			}
			NsLookup.setOut(System.out);
			NsLookup.setErr(System.err);
		}
		r.out = out.toString("UTF-8");
		r.err = err.toString("UTF-8");
		return r;
	}

	private static String [] args(String ... a) {
		List<String> ret = new ArrayList<String>();
		ret.add("-port="+port);
		ret.addAll(Arrays.asList(a));
		return ret.toArray(new String[0]);
	}

	static class Case {
		String name;
		String args;
		String stdin;
		int exit;
		StringBuilder out = new StringBuilder();
	}

	/** The cases recorded from the Linux nslookup. */
	private static List<Case> recorded() throws Exception {
		List<Case> ret = new ArrayList<Case>();
		List<String> lines = Files.readAllLines(new File(FIXTURES, "expected.txt").toPath(), StandardCharsets.UTF_8);
		Case c = null;
		boolean body = false;
		for(String line : lines) {
			if( line.startsWith("=== ") ) {
				c = new Case();
				c.name = line.substring(4);
				ret.add(c);
				body = false;
			} else if( c == null ) {
				continue;
			} else if( body ) {
				c.out.append(line).append('\n');
			} else if( line.startsWith("args: ") ) {
				c.args = line.substring(6);
			} else if( line.startsWith("stdin: ") ) {
				c.stdin = line.substring(7).replace("\\n", "\n");
			} else if( line.startsWith("exit: ") ) {
				c.exit = Integer.parseInt(line.substring(6));
			} else if( line.equals("---") ) {
				body = true;
			}
		}
		return ret;
	}

	@Test
	public void sameOutputAsLinuxNslookup() throws Exception {
		List<Case> cases = recorded();
		assertTrue(cases.size() >= 36, "cases: "+cases.size());
		List<String> failures = new ArrayList<String>();
		for(Case c : cases) {
			Result r = run(c.stdin, args(c.args.split(" ")));
			String expect = c.out.toString().replace("${PORT}", String.valueOf(port));
			if( !expect.equals(r.out) || r.exit != c.exit || !r.err.isEmpty() ) {
				failures.add(c.name+" ("+c.args+")\n--- expected (exit "+c.exit+")\n"+expect+"--- got\n"+r);
			}
		}
		assertEquals("", String.join("\n", failures));
	}

	@Test
	public void timeoutsAndRetries() throws Exception {
		//  A server that never answers
		try(DatagramSocket sink = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
			long start = System.currentTimeMillis();
			Result r = run(null, "-port="+sink.getLocalPort(), "-timeout=1", "-retry=2", "www.nsl.test", "127.0.0.1");
			String addr = "127.0.0.1#"+sink.getLocalPort();
			assertEquals(";; communications error to "+addr+": timed out\n"
					+";; communications error to "+addr+": timed out\n"
					+";; no servers could be reached\n\n", r.out);
			assertEquals(1, r.exit);
			long took = System.currentTimeMillis()-start;
			assertTrue(took >= 1900 && took < 6000, "two tries of 1 second: "+took);
		}
	}

	@Test
	public void refusedTcpConnection() throws Exception {
		int closed;
		try(ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
			closed = s.getLocalPort();
		}
		Result r = run(null, "-port="+closed, "-vc", "-retry=2", "www.nsl.test", "127.0.0.1");
		String line = ";; Connection to 127.0.0.1#"+closed+"(127.0.0.1) for www.nsl.test failed: connection refused.\n"
				+";; no servers could be reached\n";
		assertEquals(line+line+"\n", r.out);
		assertEquals(1, r.exit);
	}

	@Test
	public void resolvConfGivesTheServersAndSearchList() throws Exception {
		File dir = Files.createTempDirectory("resolv").toFile();
		File conf = new File(dir, "resolv.conf");
		try(FileWriter w = new FileWriter(conf)) {
			//  The first server does not answer; the second is ours
			w.write("# test\nnameserver 127.0.0.2 ; unreachable\nnameserver 127.0.0.1\n"
					+"search nsl.test example.invalid\noptions ndots:1 timeout:1 attempts:1 rotate\n");
		}
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		NsLookup.setOut(new PrintStream(out, true, "UTF-8"));
		NsLookup.setInteractive(false);
		NsLookup.setIn(new BufferedReader(new StringReader("set all\n")));
		System.setProperty(NsLookup.PROP_RESOLV_CONF, conf.getPath());
		try {
			NsLookup.run(new String[] {"-port="+port});
			String all = out.toString("UTF-8");
			assertTrue(all.startsWith("Default server: 127.0.0.2\nAddress: 127.0.0.2#"+port+"\nDefault server: 127.0.0.1\n"), all);
			assertTrue(all.contains("  timeout = 1\t\tretry = 1\tport = "+port+"\tndots = 1\n"), all);
			assertTrue(all.contains("  srchlist = nsl.test/example.invalid\n"), all);

			out.reset();
			NsLookup.setIn(new BufferedReader(new StringReader("")));
			int exit = NsLookup.run(new String[] {"-port="+port, "www"});
			String text = out.toString("UTF-8");
			//  127.0.0.2 doesn't answer; 127.0.0.1 does, without recursion (it is authoritative only)
			assertTrue(text.contains(";; Got recursion not available from 127.0.0.1\n"), text);
			assertTrue(text.contains("Server:\t\t127.0.0.1\n"), text);
			assertTrue(text.contains("Name:\twww.nsl.test\nAddress: 10.1.0.80\n"), text);
			assertEquals(0, exit, text);
		} finally {
			System.clearProperty(NsLookup.PROP_RESOLV_CONF);
			NsLookup.setOut(System.out);
			conf.delete();
			dir.delete();
		}
	}

	@Test
	public void resolvConfWithoutNameServerMeansThisHost() throws Exception {
		File dir = Files.createTempDirectory("resolv").toFile();
		File conf = new File(dir, "resolv.conf");
		try(FileWriter w = new FileWriter(conf)) {
			w.write("domain nsl.test\n");
		}
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		NsLookup.setOut(new PrintStream(out, true, "UTF-8"));
		NsLookup.setInteractive(false);
		NsLookup.setIn(new BufferedReader(new StringReader("set all\n")));
		System.setProperty(NsLookup.PROP_RESOLV_CONF, conf.getPath());
		try {
			NsLookup.run(new String[] {"-port="+port});
			String all = out.toString("UTF-8");
			assertTrue(all.startsWith("Default server: 127.0.0.1\nAddress: 127.0.0.1#"+port+"\n\n"), all);
			assertTrue(all.contains("  srchlist = nsl.test\n"), all);
		} finally {
			System.clearProperty(NsLookup.PROP_RESOLV_CONF);
			NsLookup.setOut(System.out);
			conf.delete();
			dir.delete();
		}
	}

	@Test
	public void nameThenServerInInteractiveMode() throws Exception {
		//  "NAME SERVER" looks NAME up on SERVER (it used to look up both names)
		Result r = run("www.nsl.test 127.0.0.1\nwww.nsl.test bogus.invalid\n", "-port="+port, "-type=a", "-", "127.0.0.2");
		assertTrue(r.out.startsWith("Server:\t\t127.0.0.1\nAddress:\t127.0.0.1#"+port+"\n\nName:\twww.nsl.test\nAddress: 10.1.0.80\n"), r.toString());
		assertTrue(r.out.contains("nslookup: couldn't get address for 'bogus.invalid': not found\n"), r.toString());
	}

	@Test
	public void commandLineErrors() throws Exception {
		Result r = run(null, "-port="+port, "a", "b", "c");
		assertEquals(1, r.exit);
		assertTrue(r.err.startsWith("Usage:\n"), r.toString());

		r = run(null, "-port="+port, "www.nsl.test", "bogus.invalid");
		assertEquals(1, r.exit);
		assertEquals("nslookup: couldn't get address for 'bogus.invalid': not found\n", r.err);

		r = run(null, "-version");
		assertEquals(0, r.exit);
		assertTrue(r.err.startsWith("nslookup "), r.toString());
	}

	@Test
	public void helpAndPrompt() throws Exception {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		NsLookup.setOut(new PrintStream(out, true, "UTF-8"));
		NsLookup.setIn(new BufferedReader(new StringReader("help\nexit\n")));
		NsLookup.setInteractive(true);
		try {
			NsLookup.run(new String[] {"-port="+port, "-", "127.0.0.1"});
		} finally {
			NsLookup.setInteractive(null);
			NsLookup.setOut(System.out);
		}
		String text = out.toString("UTF-8");
		assertTrue(text.startsWith("> Commands:"), text);
		assertTrue(text.contains("set OPTION"), text);
		assertTrue(text.endsWith("> \n"), "the prompt, and the new line at exit: "+text);
	}

	@Test
	public void reverseNames() {
		assertEquals("80.0.1.10.in-addr.arpa", NsLookupAccess.reverseName("10.1.0.80"));
		assertEquals("b.a.9.8.7.6.5.4.3.2.1.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", NsLookupAccess.reverseName("2001:db8::123:4567:89ab"));
		assertEquals("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", NsLookupAccess.reverseName("::1"));
		assertEquals("4.3.2.1.0.0.0.0.f.f.f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa".length(), NsLookupAccess.reverseName("::ffff:1.2.3.4").length());
		//  Names that start with a digit are names (it used to look up their PTR)
		assertNull(NsLookupAccess.reverseName("3com.com"));
		assertNull(NsLookupAccess.reverseName("1.2.3"));
		assertNull(NsLookupAccess.reverseName("1.2.3.256"));
		assertNull(NsLookupAccess.reverseName("1.2.3.4.5"));
		assertNull(NsLookupAccess.reverseName("face"));
	}

	@Test
	public void searchOrder() throws Exception {
		NsLookupAccess.searchList("a.test", "b.test");
		NsLookupAccess.ndots(1);
		assertEquals("[www.a.test, www.b.test, www]", NsLookupAccess.searchNames("www").toString());
		assertEquals("[www.example.com]", NsLookupAccess.searchNames("www.example.com").toString(), "dots >= ndots: as is");
		assertEquals("[www]", NsLookupAccess.searchNames("www.").toString(), "absolute");
		NsLookupAccess.ndots(3);
		assertEquals("[www.x.a.test, www.x.b.test, www.x]", NsLookupAccess.searchNames("www.x").toString());
		NsLookupAccess.searchList();
		NsLookupAccess.ndots(1);
	}

	@Test
	public void presentationFormats() {
		assertEquals("\"say \\\"hi\\\"\" \"back\\\\slash\" \"\\009tab\"",
				NsLookupAccess.characterStrings(new byte[] {8,'s','a','y',' ','"','h','i','"', 10,'b','a','c','k','\\','s','l','a','s','h', 4,9,'t','a','b'}));
		assertEquals("\"\"", NsLookupAccess.characterStrings(new byte[] {0}));
		assertNull(NsLookupAccess.characterStrings(new byte[] {5,'a'}), "malformed");
		assertEquals("\\# 0", NsLookupAccess.generic(new byte[0]));
		assertEquals("\\# 3 0A00FF", NsLookupAccess.generic(new byte[] {10,0,(byte)255}));
		byte [] a = new byte[16];
		assertEquals("::", NsLookupAccess.ipv6Text(a));
		a[15] = 1;
		assertEquals("::1", NsLookupAccess.ipv6Text(a));
		a = new byte[] {0x20,0x01,0x0d,(byte)0xb8,0,0,0,0,0,1,0,0,0,0,0,1};
		assertEquals("2001:db8::1:0:0:1", NsLookupAccess.ipv6Text(a), "the first longest run of zeros");
		a = new byte[] {0x20,0x01,0x0d,(byte)0xb8,0,0,0,1,0,1,0,1,0,1,0,1};
		assertEquals("2001:db8:0:1:1:1:1:1", NsLookupAccess.ipv6Text(a), "a single zero group is not shortened");
		a = new byte[] {0,0,0,0,0,0,0,0,0,0,(byte)0xff,(byte)0xff,1,2,3,4};
		assertEquals("::ffff:1.2.3.4", NsLookupAccess.ipv6Text(a));
	}

	@Test
	public void hinfoFromTheWire() throws Exception {
		//  HINFO read from a response was always empty (field initializers
		//  ran after the constructor had parsed it)
		Hinfo h = new Hinfo("h.test", DNS.IN);
		h.setCpu("PC");
		h.setOs("Linux");
		Message m = new Message();
		m.setQuestion("h.test", DNS.HINFO, DNS.IN);
		m.addAnswer(h);
		Message back = new Message(new ByteBuffer(m.toByteArray()));
		RR rr = back.getAnswer().get(0);
		assertTrue(rr instanceof Hinfo, rr.getClass().toString());
		assertEquals("PC", ((Hinfo)rr).getCpu());
		assertEquals("Linux", ((Hinfo)rr).getOs());
		assertFalse(rr.getRdataAsString().trim().isEmpty());
	}
}
