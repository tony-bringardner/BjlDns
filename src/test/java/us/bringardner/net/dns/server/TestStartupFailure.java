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

import java.io.File;
import java.io.FileWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A server that can't start reports why through awaitStarted() and stops what
 * it had started, instead of calling System.exit() (rec #34).
 * If System.exit() were still called, this test run would end here.
 */
public class TestStartupFailure {

	private File dir;
	private File zones;
	private final Map<String,String> saved = new HashMap<String,String>();

	private void set(String key, String value) {
		if( !saved.containsKey(key) ) {
			saved.put(key, System.getProperty(key));
		}
		if( value == null ) {
			System.clearProperty(key);
		} else {
			System.setProperty(key, value);
		}
	}

	@BeforeEach
	public void setup() throws Exception {
		dir = Files.createTempDirectory("startfail").toFile();
		zones = new File(dir,"zones");
		zones.mkdirs();
		try(FileWriter w = new FileWriter(new File(zones,"sf.test.txt"))) {
			w.write("@\tIN\tSOA\tns1.sf.test. postmaster.sf.test. (\n"
					+"\t\t\t1 ; serial\n\t\t\t3600 ; refresh\n\t\t\t1800 ; retry\n"
					+"\t\t\t1209600 ; expire\n\t\t\t300 ) ; minimum\n\n"
					+"\t\tNS\tns1\n"
					+"ns1\tIN\tA\t10.0.0.53\n");
		}
		set(DnsServer.PROP_DNS_DIR, dir.getAbsolutePath());
		set(DnsServer.PROP_ZONE_DIR, zones.getAbsolutePath());
		set(DnsServer.PROP_DEFAULT_ZONE, "sf.test");
		set(DnsServer.PROP_PORT, "0");
		set(DnsServer.PROP_ADMIN_PORT, "0");
		set(DnsServer.PROP_UDP_PROC_COUNT, "1");
		set(DnsServer.PROP_TCP_PROC_COUNT, "1");
		set("JDns.resolvers", "1");
		for(String k : new String[] {DnsServer.PROP_USE_BATABASE, DnsServer.PROP_JDBC_URL, DnsServer.PROP_BIND_ADDRESS,
				DnsServer.PROP_UDP_BIND_ADDRESS, DnsServer.PROP_TCP_BIND_ADDRESS, DnsServer.PROP_ADMIN_BIND_ADDRESS,
				DnsServer.PROP_UDP_PORT, DnsServer.PROP_TCP_PORT}) {
			set(k, null);
		}
		DnsServer.setShutdown(false);
	}

	@AfterEach
	public void cleanup() {
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

	private static boolean workerThreadsAlive() {
		for(Thread t : Thread.getAllStackTraces().keySet()) {
			String n = t.getName();
			if( t.isAlive() && (n.startsWith("UDPProc") || n.startsWith("TCPProc")) ) {
				return true;
			}
		}
		return false;
	}

	@Test
	public void missingZoneDirIsReportedNotExit() throws Exception {
		set(DnsServer.PROP_ZONE_DIR, new File(dir,"no-such-dir").getAbsolutePath());
		DnsServer server = new DnsServer();
		server.start(true);		//  stand-alone used to call System.exit(-1)
		DnsServer.StartupException ex = assertThrows(DnsServer.StartupException.class, () -> server.awaitStarted(30_000));
		assertEquals(-1, ex.getExitCode());
		assertTrue(ex.getMessage().contains("no-such-dir"), ex.getMessage());
		assertFalse(server.isRunning());
	}

	@Test
	public void adminPortInUseStopsWhatWasStarted() throws Exception {
		try(ServerSocket taken = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
			set(DnsServer.PROP_ADMIN_PORT, String.valueOf(taken.getLocalPort()));
			DnsServer server = new DnsServer();
			server.start(true);		//  stand-alone used to call System.exit(-2)
			DnsServer.StartupException ex = assertThrows(DnsServer.StartupException.class, () -> server.awaitStarted(30_000));
			assertEquals(-2, ex.getExitCode());
			assertFalse(server.isRunning());
			assertFalse(workerThreadsAlive(), "UDP/TCP threads started by initServer were stopped");
			assertFalse(DnsServer.isShutdown(), "the JVM wide shutdown flag is not set by a failed start");
		} finally {
			DnsServer.setAdminPort(9999);
		}
	}

	@Test
	public void successfulStartReturns() throws Exception {
		DnsServer server = new DnsServer();
		server.start();
		try {
			server.awaitStarted(30_000);
			assertTrue(server.isRunning());
		} finally {
			assertTrue(server.stopAndWait(10_000));
			DnsServer.setShutdown(false);
			DnsServer.setAdminPort(9999);
		}
	}
}
