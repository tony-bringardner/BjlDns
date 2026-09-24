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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.DriverPropertyInfo;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Logger;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Offline tests: dynamic entries change in memory only after the store
 * (database, or the dynamic file without one) has been written.
 * A tiny in-memory JDBC driver stands in for MySQL.
 */
public class TestDynamicStore {

	/** name -> "ip|status" rows of the dynamic_dns table */
	static final Map<String,String> rows = new HashMap<String,String>();
	static volatile boolean failNext = false;

	public static class FakeDriver implements Driver {
		public Connection connect(String url, Properties info) {
			if( !acceptsURL(url) ) {
				return null;
			}
			return (Connection)Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] {Connection.class},
					(proxy, m, args) -> {
						if( m.getName().equals("prepareStatement") ) {
							return statement((String)args[0]);
						}
						return defaultValue(m.getReturnType());
					});
		}
		public boolean acceptsURL(String url) {
			return url != null && url.startsWith("jdbc:fakedns:");
		}
		public DriverPropertyInfo[] getPropertyInfo(String url, Properties info) {
			return new DriverPropertyInfo[0];
		}
		public int getMajorVersion() {
			return 1;
		}
		public int getMinorVersion() {
			return 0;
		}
		public boolean jdbcCompliant() {
			return false;
		}
		public Logger getParentLogger() throws SQLFeatureNotSupportedException {
			throw new SQLFeatureNotSupportedException();
		}
	}

	private static Object defaultValue(Class<?> t) {
		if( t == boolean.class ) {
			return false;
		}
		if( t == int.class ) {
			return 0;
		}
		if( t == long.class ) {
			return 0L;
		}
		return null;
	}

	/** Handles the two statements DnsServer uses: insert and update of dynamic_dns. */
	private static PreparedStatement statement(String sql) {
		Map<Integer,Object> params = new HashMap<Integer,Object>();
		return (PreparedStatement)Proxy.newProxyInstance(TestDynamicStore.class.getClassLoader(), new Class<?>[] {PreparedStatement.class},
				(proxy, m, args) -> {
					String n = m.getName();
					if( n.startsWith("set") && args != null && args.length == 2 ) {
						params.put((Integer)args[0], args[1]);
						return null;
					}
					if( n.equals("executeUpdate") ) {
						if( failNext ) {
							failNext = false;
							throw new SQLException("simulated database failure");
						}
						// positions as in DnsServer: 1 ip, 2 lastUpdate, 3 status, 4 name
						String name = (String)params.get(4);
						String value = params.get(1)+"|"+params.get(3);
						synchronized (rows) {
							if( sql.trim().toLowerCase().startsWith("insert") ) {
								rows.put(name, value);
								return 1;
							}
							if( rows.containsKey(name) ) {
								rows.put(name, value);
								return 1;
							}
							return 0;
						}
					}
					return defaultValue(m.getReturnType());
				});
	}

	private static File dir;
	private static File zoneFile;
	private static File dynFile;
	private static final Map<String,String> saved = new HashMap<String,String>();
	private static final String [] PROPS = {DnsServer.PROP_USE_BATABASE, DnsServer.PROP_JDBC_URL, DnsServer.PROP_DYNAMIC, "JDns.jdbcClass"};

	@BeforeAll
	public static void setup() throws Exception {
		DriverManager.registerDriver(new FakeDriver());
		dir = Files.createTempDirectory("dynstore").toFile();
		zoneFile = new File(dir,"dyn2.test.txt");
		try(FileWriter w = new FileWriter(zoneFile)) {
			w.write("@\tIN\tSOA\tns1.dyn2.test. postmaster.dyn2.test. (\n"
					+"\t\t\t1 ; serial\n\t\t\t3600 ; refresh\n\t\t\t1800 ; retry\n"
					+"\t\t\t1209600 ; expire\n\t\t\t300 ) ; minimum\n\n"
					+"\t\tNS\tns1\n"
					+"ns1\tIN\tA\t10.0.0.53\n");
		}
		dynFile = new File(dir,"dynamic.txt");
		for(String k : PROPS) {
			saved.put(k, System.getProperty(k));
		}
		System.clearProperty("JDns.jdbcClass");
		System.setProperty(DnsServer.PROP_DYNAMIC, dynFile.getAbsolutePath());
	}

	@AfterAll
	public static void cleanup() {
		for(String k : PROPS) {
			if( saved.get(k) == null ) {
				System.clearProperty(k);
			} else {
				System.setProperty(k, saved.get(k));
			}
		}
		for(File f : dir.listFiles()) {
			f.delete();
		}
		dir.delete();
	}

	private static DnsServer server(boolean database) throws IOException {
		rows.clear();
		failNext = false;
		dynFile.delete();
		if( database ) {
			System.setProperty(DnsServer.PROP_USE_BATABASE, "true");
			System.setProperty(DnsServer.PROP_JDBC_URL, "jdbc:fakedns:test");
		} else {
			System.setProperty(DnsServer.PROP_USE_BATABASE, "false");
			System.clearProperty(DnsServer.PROP_JDBC_URL);
		}
		DnsServer s = new DnsServer();
		s.addZone(new Zone(zoneFile));
		return s;
	}

	private static String address(DnsServer s, String name) {
		return s.getDynamic(name) == null ? null : s.getDynamic(name).get(0).getAddressString();
	}

	// ------------------------------------------------------------ database

	@Test
	public void failedInsertChangesNothing() throws Exception {
		DnsServer s = server(true);
		failNext = true;
		assertThrows(SQLException.class, () -> s.addOrUpdateDynamic("a.dyn2.test","10.1.0.1"));
		assertNull(s.getDynamic("a.dyn2.test"), "not served when the database didn't store it");
		assertTrue(rows.isEmpty());
	}

	@Test
	public void failedUpdateKeepsOldAddress() throws Exception {
		DnsServer s = server(true);
		s.addOrUpdateDynamic("b.dyn2.test","10.1.0.1");
		assertEquals("10.1.0.1|active", rows.get("b.dyn2.test"));
		failNext = true;
		assertThrows(SQLException.class, () -> s.addOrUpdateDynamic("b.dyn2.test","10.1.0.2"));
		assertEquals("10.1.0.1", address(s,"b.dyn2.test"), "memory matches the database");
		assertEquals("10.1.0.1|active", rows.get("b.dyn2.test"));
		s.addOrUpdateDynamic("b.dyn2.test","10.1.0.2");
		assertEquals("10.1.0.2", address(s,"b.dyn2.test"));
		assertEquals("10.1.0.2|active", rows.get("b.dyn2.test"));
	}

	@Test
	public void failedRemoveKeepsEntry() throws Exception {
		DnsServer s = server(true);
		s.addOrUpdateDynamic("c.dyn2.test","10.1.0.3");
		failNext = true;
		assertThrows(IOException.class, () -> s.removeDynamic("c.dyn2.test"));
		assertEquals("10.1.0.3", address(s,"c.dyn2.test"), "still served, still active in the database");
		assertEquals("10.1.0.3|active", rows.get("c.dyn2.test"));
		s.removeDynamic("c.dyn2.test");
		assertNull(s.getDynamic("c.dyn2.test"));
		assertEquals("10.1.0.3|deleted", rows.get("c.dyn2.test"));
	}

	@Test
	public void updateWithoutRowInsertsIt() throws Exception {
		// An entry known only in memory (e.g. from the dynamic file): the
		// update touched 0 rows and was silently lost before
		DnsServer s = server(true);
		assertNotNull(s.addDynamic("d.dyn2.test","10.1.0.4"));
		s.addOrUpdateDynamic("d.dyn2.test","10.1.0.5");
		assertEquals("10.1.0.5|active", rows.get("d.dyn2.test"));
		assertEquals("10.1.0.5", address(s,"d.dyn2.test"));
	}

	@Test
	public void invalidAddressChangesNothing() throws Exception {
		DnsServer s = server(true);
		assertThrows(IllegalArgumentException.class, () -> s.addOrUpdateDynamic("e.dyn2.test","10.1.0.999"));
		assertNull(s.getDynamic("e.dyn2.test"));
		assertTrue(rows.isEmpty(), "rejected before anything was stored");
	}

	// ------------------------------------------------------------ no database: the file

	@Test
	public void withoutDatabaseChangesAreSavedToTheFile() throws Exception {
		DnsServer s = server(false);
		s.addOrUpdateDynamic("f.dyn2.test","10.2.0.1");
		s.addOrUpdateDynamic("g.dyn2.test","10.2.0.2");
		s.addOrUpdateDynamic("f.dyn2.test","10.2.0.3");
		s.removeDynamic("g.dyn2.test");
		assertTrue(dynFile.exists(), "admin changes used to exist only in memory");

		// A restart loads them back (loading from the file never worked before)
		DnsServer restarted = new DnsServer();
		restarted.addZone(new Zone(zoneFile));
		restarted.loadDynamic();
		assertEquals("10.2.0.3", address(restarted,"f.dyn2.test"));
		assertNull(restarted.getDynamic("g.dyn2.test"));

		String [] leftovers = dir.list((d, n) -> n.endsWith(".tmp"));
		assertEquals(0, leftovers.length, "temporary files are cleaned up");
	}

	@Test
	public void badLineInFileIsSkipped() throws Exception {
		DnsServer s = server(false);
		try(FileWriter w = new FileWriter(dynFile)) {
			w.write("bad.dyn2.test=not.an.address\n");
			w.write("good.dyn2.test=10.3.0.1\n");
			w.write("elsewhere.example=10.3.0.2\n");
		}
		s.loadDynamic();
		assertEquals("10.3.0.1", address(s,"good.dyn2.test"));
		assertNull(s.getDynamic("bad.dyn2.test"));
		assertNull(s.getDynamic("elsewhere.example"), "not one of our domains");
	}
}
