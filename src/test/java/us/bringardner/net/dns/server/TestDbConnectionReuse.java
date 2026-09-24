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
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Offline: the server keeps one JDBC connection and reuses it (it used to
 * open and close one per operation), replacing it when it is no longer
 * valid or after an error.
 */
public class TestDbConnectionReuse {

	static final AtomicInteger opened = new AtomicInteger();
	static final AtomicInteger closed = new AtomicInteger();
	static volatile boolean valid = true;
	static volatile boolean failNext = false;

	public static class ReuseDriver implements Driver {
		public Connection connect(String url, Properties info) {
			if( !acceptsURL(url) ) {
				return null;
			}
			opened.incrementAndGet();
			boolean [] isClosed = {false};
			return (Connection)Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] {Connection.class},
					(proxy, m, args) -> {
						switch(m.getName()) {
						case "prepareStatement":
							return statement();
						case "isValid":
							return valid && !isClosed[0];
						case "isClosed":
							return isClosed[0];
						case "close":
							if( !isClosed[0] ) {
								isClosed[0] = true;
								closed.incrementAndGet();
							}
							return null;
						default:
							return defaultValue(m.getReturnType());
						}
					});
		}
		public boolean acceptsURL(String url) {
			return url != null && url.startsWith("jdbc:fakereuse:");
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

	/** Every update "changes" one row. */
	private static PreparedStatement statement() {
		return (PreparedStatement)Proxy.newProxyInstance(TestDbConnectionReuse.class.getClassLoader(), new Class<?>[] {PreparedStatement.class},
				(proxy, m, args) -> {
					if( m.getName().equals("executeUpdate") ) {
						if( failNext ) {
							failNext = false;
							throw new SQLException("simulated failure");
						}
						return 1;
					}
					return defaultValue(m.getReturnType());
				});
	}

	private static File dir;
	private static File zoneFile;
	private static final Map<String,String> saved = new HashMap<String,String>();
	private static final String [] PROPS = {DnsServer.PROP_USE_BATABASE, DnsServer.PROP_JDBC_URL, DnsServer.PROP_DYNAMIC, "JDns.jdbcClass"};

	@BeforeAll
	public static void setup() throws Exception {
		DriverManager.registerDriver(new ReuseDriver());
		dir = Files.createTempDirectory("dbreuse").toFile();
		zoneFile = new File(dir,"reuse.test.txt");
		try(FileWriter w = new FileWriter(zoneFile)) {
			w.write("@\tIN\tSOA\tns1.reuse.test. postmaster.reuse.test. (\n"
					+"\t\t\t1 ; serial\n\t\t\t3600 ; refresh\n\t\t\t1800 ; retry\n"
					+"\t\t\t1209600 ; expire\n\t\t\t300 ) ; minimum\n\n"
					+"\t\tNS\tns1\n"
					+"ns1\tIN\tA\t10.0.0.53\n");
		}
		for(String k : PROPS) {
			saved.put(k, System.getProperty(k));
		}
		System.clearProperty("JDns.jdbcClass");
		System.setProperty(DnsServer.PROP_DYNAMIC, new File(dir,"dynamic.txt").getAbsolutePath());
		System.setProperty(DnsServer.PROP_USE_BATABASE, "true");
		System.setProperty(DnsServer.PROP_JDBC_URL, "jdbc:fakereuse:test");
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

	private static DnsServer server() throws Exception {
		valid = true;
		failNext = false;
		DnsServer s = new DnsServer();
		s.addZone(new Zone(zoneFile));
		return s;
	}

	@Test
	public void oneConnectionForManyUpdates() throws Exception {
		DnsServer s = server();
		int before = opened.get();
		for(int i=1; i <= 50; i++ ) {
			s.addOrUpdateDynamic("h"+(i%5)+".reuse.test", "10.2.0."+i);
		}
		assertEquals(1, opened.get()-before, "was one connection per statement (50+)");
		assertEquals(1, s.getDbConnectionsOpened());
		int closedBefore = closed.get();
		s.closeDbConnection();
		assertEquals(closedBefore+1, closed.get(), "closed on shutdown");
	}

	@Test
	public void invalidConnectionIsReplaced() throws Exception {
		DnsServer s = server();
		s.addOrUpdateDynamic("a.reuse.test", "10.2.1.1");
		int closedBefore = closed.get();
		valid = false;   //  e.g. the database dropped an idle connection
		try {
			s.addOrUpdateDynamic("a.reuse.test", "10.2.1.2");
		} finally {
			valid = true;
		}
		assertEquals(2, s.getDbConnectionsOpened());
		assertEquals(closedBefore+1, closed.get(), "the stale one was closed");
		s.closeDbConnection();
	}

	@Test
	public void errorDropsTheConnection() throws Exception {
		DnsServer s = server();
		s.addOrUpdateDynamic("b.reuse.test", "10.2.2.1");
		failNext = true;
		assertThrows(SQLException.class, () -> s.addOrUpdateDynamic("b.reuse.test", "10.2.2.2"));
		s.addOrUpdateDynamic("b.reuse.test", "10.2.2.3");
		assertEquals(2, s.getDbConnectionsOpened(), "a new connection after the failure");
		assertEquals("10.2.2.3", s.getDynamic("b.reuse.test").get(0).getAddressString());
		s.closeDbConnection();
	}

	@Test
	public void concurrentUpdatesShareIt() throws Exception {
		DnsServer s = server();
		Thread [] t = new Thread[8];
		AtomicInteger errors = new AtomicInteger();
		for(int i=0; i < t.length; i++ ) {
			final int n = i;
			t[i] = new Thread(() -> {
				for(int j=1; j <= 25; j++ ) {
					try {
						s.addOrUpdateDynamic("c"+n+".reuse.test", "10.3."+n+"."+j);
					} catch(Exception ex) {
						errors.incrementAndGet();
					}
				}
			});
			t[i].start();
		}
		for(Thread x : t) {
			x.join(10_000);
		}
		assertEquals(0, errors.get());
		assertEquals(1, s.getDbConnectionsOpened());
		assertTrue(s.getDynamic("c3.reuse.test").get(0).getAddressString().equals("10.3.3.25"));
		s.closeDbConnection();
	}
}
