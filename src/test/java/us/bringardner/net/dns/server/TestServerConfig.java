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

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;


/**
 * Offline tests for server configuration: each test starts the real server
 * (initServer) on random loopback ports with a set of properties and checks
 * the sockets it opened.
 */
public class TestServerConfig {

	/** Properties every test needs; tests add their own on top. */
	private static Map<String,String> base(File dir) {
		Map<String,String> p = new HashMap<String,String>();
		p.put(DnsServer.PROP_DNS_DIR, dir.getAbsolutePath());
		p.put(DnsServer.PROP_ZONE_DIR, new File(dir,"zones").getAbsolutePath());
		p.put(DnsServer.PROP_DEFAULT_ZONE, "cfg.test");
		p.put(DnsServer.PROP_PORT, "0");
		p.put(DnsServer.PROP_ADMIN_PORT, "0");
		p.put(DnsServer.PROP_UDP_PROC_COUNT, "1");
		p.put(DnsServer.PROP_TCP_PROC_COUNT, "1");
		p.put("JDns.resolvers", "1");
		return p;
	}

	/** Runs body against a started server, then stops it and restores system properties. */
	private interface Body {
		void run(DnsServer server) throws Exception;
	}

	private static void withServer(Map<String,String> extra, Body body) throws Exception {
		File dir = Files.createTempDirectory("cfg").toFile();
		File zones = new File(dir,"zones");
		zones.mkdirs();
		try(FileWriter w = new FileWriter(new File(zones,"cfg.test.txt"))) {
			w.write("@\tIN\tSOA\tns1.cfg.test. postmaster.cfg.test. (\n"
					+"\t\t\t1 ; serial\n\t\t\t3600 ; refresh\n\t\t\t1800 ; retry\n"
					+"\t\t\t1209600 ; expire\n\t\t\t300 ) ; minimum\n\n"
					+"\t\tNS\tns1\n"
					+"ns1\tIN\tA\t10.0.0.53\n");
		}
		Map<String,String> props = base(dir);
		props.putAll(extra);
		Map<String,String> saved = new HashMap<String,String>();
		String [] alsoClear = {DnsServer.PROP_USE_BATABASE, DnsServer.PROP_JDBC_URL, DnsServer.PROP_UDP_TIMEOUT,
				DnsServer.PROP_TCP_TIMEOUT, DnsServer.PROP_TIMEOUT, DnsServer.PROP_BIND_ADDRESS,
				DnsServer.PROP_TCP_BIND_ADDRESS, DnsServer.PROP_ADMIN_BIND_ADDRESS};
		for(String k : alsoClear) {
			saved.put(k, System.getProperty(k));
			System.clearProperty(k);
		}
		for(Map.Entry<String,String> e : props.entrySet()) {
			if( !saved.containsKey(e.getKey()) ) {
				saved.put(e.getKey(), System.getProperty(e.getKey()));
			}
			System.setProperty(e.getKey(), e.getValue());
		}
		DnsServer server = new DnsServer();
		try {
			server.initServer();
			body.run(server);
		} finally {
			assertTrue(server.stopAndWait(10_000), "server threads did not stop");
			DnsServer.setShutdown(false);
			for(Map.Entry<String,String> e : saved.entrySet()) {
				if( e.getValue() == null ) {
					System.clearProperty(e.getKey());
				} else {
					System.setProperty(e.getKey(), e.getValue());
				}
			}
			for(File f : zones.listFiles()) {
				f.delete();
			}
			zones.delete();
			for(File f : dir.listFiles()) {
				f.delete();
			}
			dir.delete();
		}
	}

	private static Map<String,String> props(String ... kv) {
		Map<String,String> m = new HashMap<String,String>();
		for(int i=0; i< kv.length; i+=2 ) {
			m.put(kv[i], kv[i+1]);
		}
		return m;
	}

	@Test
	public void udpTimeoutIsUsedForUdpOnly() throws Exception {
		// JDns.udpTimeout used to overwrite the general timeout: UDP kept the
		// general value and TCP got the UDP one.
		withServer(props(DnsServer.PROP_TIMEOUT,"5000", DnsServer.PROP_UDP_TIMEOUT,"1234"), s -> {
			assertEquals(1234, UDPProsessor.getSock().getSoTimeout());
			assertEquals(5000, TCPProsessor.getServerSocket().getSoTimeout());
		});
	}

	@Test
	public void tcpTimeoutAndDefaults() throws Exception {
		withServer(props(DnsServer.PROP_TIMEOUT,"3000", DnsServer.PROP_TCP_TIMEOUT,"4321"), s -> {
			assertEquals(3000, UDPProsessor.getSock().getSoTimeout());
			assertEquals(4321, TCPProsessor.getServerSocket().getSoTimeout());
		});
	}

	@Test
	public void tcpBindAddressIsUsed() throws Exception {
		// JDns.tcpBindAddress used to be read and then ignored
		withServer(props(DnsServer.PROP_BIND_ADDRESS,"127.0.0.1", DnsServer.PROP_TCP_BIND_ADDRESS,"0.0.0.0"), s -> {
			assertTrue(UDPProsessor.getSock().getLocalAddress().isLoopbackAddress());
			assertTrue(TCPProsessor.getServerSocket().getInetAddress().isAnyLocalAddress(),
					"TCP bound to "+TCPProsessor.getServerSocket().getInetAddress());
		});
	}

	@Test
	public void adminListensOnLoopbackByDefault() throws Exception {
		withServer(props(), s -> {
			try(ServerSocket admin = s.createAdminSocket()) {
				assertTrue(admin.getInetAddress().isLoopbackAddress(), "admin bound to "+admin.getInetAddress());
			}
		});
	}

	@Test
	public void adminBindAddressConfigurable() throws Exception {
		withServer(props(DnsServer.PROP_ADMIN_BIND_ADDRESS,"0.0.0.0"), s -> {
			try(ServerSocket admin = s.createAdminSocket()) {
				assertTrue(admin.getInetAddress().isAnyLocalAddress());
			}
		});
	}

	@Test
	public void badNumberNamesTheProperty() throws Exception {
		IOException ex = assertThrows(IOException.class, () ->
			withServer(props(DnsServer.PROP_TCP_BACKLOG,"ten"), s -> {}));
		assertTrue(ex.getMessage().contains(DnsServer.PROP_TCP_BACKLOG), ex.getMessage());
	}

	@Test
	public void emptyValueMeansDefault() throws Exception {
		withServer(props(DnsServer.PROP_TCP_TIMEOUT,"  ", DnsServer.PROP_TIMEOUT,"2500"), s -> {
			assertEquals(2500, TCPProsessor.getServerSocket().getSoTimeout());
		});
	}

	/** Names of live threads started by the server (UDPProc*, TCPProc*, ResolverThread*). */
	private static java.util.List<String> serverThreads() {
		java.util.List<String> ret = new java.util.ArrayList<String>();
		for(Thread t : Thread.getAllStackTraces().keySet()) {
			String n = t.getName();
			if( t.isAlive() && (n.startsWith("UDPProc") || n.startsWith("TCPProc") || n.startsWith("ResolverThread")) ) {
				ret.add(n);
			}
		}
		return ret;
	}

	@Test
	public void stopAndWaitEndsAllServerThreads() throws Exception {
		// Long socket timeouts: stop() alone left these threads blocked for up to 30s
		withServer(props(DnsServer.PROP_TIMEOUT,"30000"), s -> {
			assertTrue(!serverThreads().isEmpty(), "server started its threads");
		});
		assertEquals("[]", serverThreads().toString(), "threads still running after stopAndWait");
	}

	@Test
	public void databaseOnlyWhenConfigured() throws Exception {
		withServer(props(), s -> {
			assertTrue(!s.useDatabase(), "no flag, no JDBC URL: no database");
			System.setProperty(DnsServer.PROP_JDBC_URL, "jdbc:none://nowhere");
			assertTrue(s.useDatabase(), "no flag, JDBC URL set: database");
			System.setProperty(DnsServer.PROP_USE_BATABASE, "false");
			assertTrue(!s.useDatabase(), "explicit false wins");
			System.setProperty(DnsServer.PROP_USE_BATABASE, "true");
			assertTrue(s.useDatabase());
		});
	}

	@Test
	public void missingDatabaseIsSqlExceptionNotNpe() throws Exception {
		withServer(props(), s -> {
			System.setProperty(DnsServer.PROP_USE_BATABASE, "true");
			// No JDBC URL: used to be a NullPointerException from a null Connection
			SQLException ex = assertThrows(SQLException.class, () -> s.addOrUpdateDynamic("host.cfg.test","10.0.0.9"));
			assertTrue(ex.getMessage().contains(DnsServer.PROP_JDBC_URL), ex.getMessage());
			// nothing is served that the store didn't accept (rec #19)
			assertTrue(s.getDynamic("host.cfg.test") == null);
		});
	}
}
