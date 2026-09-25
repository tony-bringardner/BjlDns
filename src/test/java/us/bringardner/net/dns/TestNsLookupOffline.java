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
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.server.DnsServer;
import us.bringardner.net.dns.server.TCPProsessor;
import us.bringardner.net.dns.server.UDPProsessor;
import us.bringardner.net.dns.server.Zone;
import us.bringardner.net.dns.util.NsLookup;

/**
 * NsLookup against a DnsServer on the loopback, so it runs without the internet
 * (TestNsLookup needs the real root servers and is only run with -DliveTests=true).
 */
public class TestNsLookupOffline {

	private static File dir;
	private static int port;

	@BeforeAll
	public static void startServer() throws Exception {
		dir = Files.createTempDirectory("nslookup").toFile();
		File zone = new File(dir,"nslookup.test.txt");
		try(FileWriter w = new FileWriter(zone)) {
			w.write("@\tIN\tSOA\tns1.nslookup.test. postmaster.nslookup.test. (\n"
					+"\t\t\t1 ; serial\n\t\t\t3600 ; refresh\n\t\t\t1800 ; retry\n"
					+"\t\t\t1209600 ; expire\n\t\t\t300 ) ; minimum\n\n"
					+"\t\tNS\tns1\n"
					+"\t\tMX\t10 mail\n"
					+"ns1\tIN\tA\t10.0.0.53\n"
					+"mail\tIN\tA\t10.0.0.25\n"
					+"www\tIN\tA\t10.0.0.80\n"
					+"multi\tIN\tA\t10.0.0.1\n"
					+"multi\tIN\tA\t10.0.0.2\n"
					//  A delegation whose name server is this same server: the
					//  referral points back to where NsLookup already asked
					+"sub\tIN\tNS\tns.sub\n"
					+"ns.sub\tIN\tA\t127.0.0.1\n");
		}
		DnsServer server = new DnsServer();
		server.addZone(new Zone(zone));
		server.setRecursionAvailable(false);

		//  A port that is free for both UDP and TCP
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
		Thread u = new Thread(new UDPProsessor(server,0),"TestNsLookupUDP");
		u.setDaemon(true);
		u.start();
		Thread t = new Thread(new TCPProsessor(server,0),"TestNsLookupTCP");
		t.setDaemon(true);
		t.start();
	}

	@AfterAll
	public static void stopServer() throws Exception {
		NsLookup.setOut(System.out);
		UDPProsessor.getSock().close();
		TCPProsessor.getServerSocket().close();
		for(File f : dir.listFiles()) {
			f.delete();
		}
		dir.delete();
	}

	/** Run one NsLookup session and return its output lines (blank lines removed). */
	private static List<String> session(String ... commands) throws Exception {
		StringBuilder in = new StringBuilder();
		for(String c : commands) {
			in.append(c).append('\n');
		}
		in.append("quit\n");
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		NsLookup.setOut(new PrintStream(out, true, "UTF-8"));
		NsLookup.setIn(new BufferedReader(new StringReader(in.toString())));
		System.setProperty("echoCommand","true");
		try {
			NsLookup.main(new String[] {"-s","127.0.0.1","-p",String.valueOf(port)});
		} finally {
			System.clearProperty("echoCommand");
			NsLookup.setOut(System.out);
		}
		List<String> ret = new ArrayList<String>();
		for(String line : out.toString("UTF-8").split("\n")) {
			line = line.trim();
			if( !line.isEmpty() ) {
				ret.add(line);
			}
		}
		return ret;
	}

	private static String find(List<String> lines, String prefix) {
		for(String l : lines) {
			if( l.startsWith(prefix) ) {
				return l;
			}
		}
		return null;
	}

	private static List<String> addresses(List<String> lines) {
		List<String> ret = new ArrayList<String>();
		for(String l : lines) {
			int idx = l.indexOf("Address: ");
			if( idx > 0 ) {
				ret.add(l.substring(idx+9).trim());
			}
		}
		Collections.sort(ret);
		return ret;
	}

	@Test
	public void authoritativeAnswer() throws Exception {
		List<String> out = session("www.nslookup.test");
		assertEquals("> www.nslookup.test", out.get(0), out.toString());
		assertTrue(out.contains("Authoritative answer:"), out.toString());
		assertEquals("Answer count = 1", find(out,"Answer count"));
		assertEquals("[10.0.0.80]", addresses(out).toString());
		assertEquals("NsLookup done", out.get(out.size()-1), "quit ends the session");
	}

	@Test
	public void severalNamesAndRecords() throws Exception {
		List<String> out = session("multi.nslookup.test www.nslookup.test");
		assertEquals("[10.0.0.1, 10.0.0.2, 10.0.0.80]", addresses(out).toString(), out.toString());
	}

	@Test
	public void queryType() throws Exception {
		List<String> out = session("set type=MX", "nslookup.test");
		String mx = null;
		for(String l : out) {
			if( l.startsWith("nslookup.test MX") ) {
				mx = l;
			}
		}
		assertTrue(mx != null && mx.contains("mail.nslookup.test"), out.toString());
	}

	@Test
	public void missingName() throws Exception {
		List<String> out = session("nope.nslookup.test");
		assertTrue(find(out,"Answer for") == null, "no answer printed: "+out);
		assertEquals(DNS.ERRORNAMES[DNS.NAME_ERROR], out.get(1), out.toString());
	}

	@Test
	public void referralBackToTheSameServerEnds() throws Exception {
		//  Used to follow the referral to this server again and again until
		//  StackOverflowError.
		List<String> out = session("host.sub.nslookup.test");
		assertTrue(out.contains("Non-authoritative answer:"), out.toString());
		assertEquals("Answer count = 0", find(out,"Answer count"), out.toString());
		assertTrue(find(out,"sub.nslookup.test NS") != null, "the referral is shown: "+out);
		assertFalse(out.toString().contains("StackOverflowError"), out.toString());
	}

	@Test
	public void serverOptionSkipsRootServers() throws Exception {
		//  With -s the root servers are not contacted (there is no network here).
		long start = System.currentTimeMillis();
		List<String> out = session("set all");
		assertTrue(find(out,"server=") != null, out.toString());
		assertTrue(out.toString().contains("port="+port), out.toString());
		assertTrue(System.currentTimeMillis()-start < 5000, "no root server queries");
	}
}
