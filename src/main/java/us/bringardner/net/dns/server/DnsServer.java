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
 *
 *
 * ~version~V000.01.04-V000.00.05-V000.00.00-
 */
package us.bringardner.net.dns.server;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

import javax.net.ServerSocketFactory;

import us.bringardner.net.dns.A;
import us.bringardner.net.dns.Cname;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.DnsBaseClass;
import us.bringardner.net.dns.Edns;
import us.bringardner.net.dns.Header;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.Mx;
import us.bringardner.net.dns.Name;
import us.bringardner.net.dns.Ns;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.Section;
import us.bringardner.net.dns.Soa;
import us.bringardner.net.dns.Svcb;
import us.bringardner.net.dns.Tsig;
import us.bringardner.net.dns.Utility;
import us.bringardner.net.dns.dnssec.Canonical;
import us.bringardner.net.dns.dnssec.DnssecKey;
import us.bringardner.net.dns.resolve.QueryData;
import us.bringardner.core.util.AddressMatcher;
import us.bringardner.net.dns.resolve.Resolver;
import us.bringardner.io.IoUtils;

/**
 * A DNS Server
 * Creation date: (8/26/2001 5:26:49 AM)
 * @author: Tony Bringardner
 */
public class DnsServer  extends DnsBaseClass implements Runnable
{
	public static final String PROP_DEFAULT_ZONE = "JDns.master.zone";
	public static final String PROP_DNS_PROPERTIES = "JDns.properties";
	private static final String DEFAULT_PROPERTIES_FILE_NAME = "JDns.properties";
	public static final String PROP_ADMIN_PORT = "JDns.adminPort";
	public static final String PROP_DEBUG = "JDns.debug";
	public static final String PROP_JDNS_RA = "JDns.ra";

	public static final String PROP_PORT = "JDns.dnsPort";	
	public static final String PROP_BIND_ADDRESS = "JDns.bindAddress";
	public static final String PROP_TIMEOUT = "JDns.timeout";

	public static final String PROP_UDP_BIND_ADDRESS = "JDns.udp.bindAddress";
	public static final String PROP_UDP_PORT = "JDns.udpPort";
	public static final String PROP_UDP_TIMEOUT = "JDns.udpTimeout";
	/** Largest UDP response in bytes (default 512, RFC 1035). Larger answers are truncated. */
	public static final String PROP_UDP_MAX_RESPONSE = "JDns.udpMaxResponse";
	public static final String PROP_EDNS_UDP_SIZE = "JDns.ednsUdpSize";
	public static final String PROP_ZONE_CUT_REFERRALS = "JDns.zoneCutReferrals";

	public static final String PROP_TCP_PORT = "JDns.tcpPort";	
	public static final String PROP_TCP_BIND_ADDRESS = "JDns.tcpBindAddress";
	public static final String PROP_TCP_BACKLOG = "JDns.tcpBacklog";
	public static final String PROP_TCP_TIMEOUT = "JDns.tcpTimeout";
	/** Most TCP connections served at once (default 64). */
	public static final String PROP_TCP_MAX_CONNECTIONS = "JDns.tcpMaxConnections";
	/** An idle TCP connection is closed after this many ms (default 10000). */
	public static final String PROP_TCP_IDLE_TIMEOUT = "JDns.tcpIdleTimeout";
	/** Address the admin port listens on. Default: loopback only. Use 0.0.0.0 for all interfaces. */
	public static final String PROP_ADMIN_BIND_ADDRESS = "JDns.adminBindAddress";
	public static final String PROP_JDBC_URL = "JDns.jdbcURL";
	/** JDBC driver class to load (optional with JDBC 4 drivers). */
	public static final String PROP_JDBC_CLASS = "JDns.jdbcClass";
	public static final String PROP_JDBC_USER = "JDns.jdbcUser";
	public static final String PROP_JDBC_PASSWORD = "JDns.jdbcPassword";
	/**
	 * Shared secret for the admin port (challenge-response, see AdminAuth).
	 * Without it only clients on this machine may use the admin port.
	 */
	public static final String PROP_ADMIN_SECRET = "JDns.adminSecret";
	/**
	 * true: the admin port uses TLS (SSLServerSocketFactory.getDefault(),
	 * configured with the standard javax.net.ssl.keyStore / keyStorePassword
	 * properties). DnsAdminClient reads the same property and then uses
	 * SSLSocketFactory.getDefault() (javax.net.ssl.trustStore).
	 */
	public static final String PROP_ADMIN_TLS = "JDns.adminTls";
	/** Most admin sessions at once (default 8). */
	public static final String PROP_ADMIN_MAX_CONNECTIONS = "JDns.adminMaxConnections";
	/** An idle admin session is closed after this many ms (default 600000). */
	public static final String PROP_ADMIN_IDLE_TIMEOUT = "JDns.adminIdleTimeout";
	/** Longest admin command line in bytes (default 8192); a longer one ends the session. */
	public static final String PROP_ADMIN_MAX_LINE = "JDns.adminMaxLine";
	/** With JDns.adminSecret set, a session that has not authenticated after this many ms is closed (default 30000). */
	public static final String PROP_ADMIN_AUTH_TIMEOUT = "JDns.adminAuthTimeout";




	public static final String PROP_DNS_DIR = "JDns.dnsDir";
	public static final String PROP_DYNAMIC = "JDns.dynamicFileName";
	public static final String PROP_ZONE_DIR = "JDns.zone.dir";
	/** Addresses / networks allowed to transfer zones (AXFR), e.g. "192.0.2.2, 10.0.0.0/8". Default: none. */
	public static final String PROP_AXFR_ALLOW = "JDns.axfrAllow";
	/** Secondaries to send NOTIFY to when a zone is loaded or its serial changes, e.g. "192.0.2.2, [2001:db8::2]:53". */
	public static final String PROP_NOTIFY = "JDns.notify";
	/** TSIG keys (RFC 8945): "name:algorithm:base64secret" entries, e.g. "xfr.example:hmac-sha256:c2VjcmV0..." */
	public static final String PROP_TSIG_KEYS = "JDns.tsigKeys";
	/** A file of TSIG keys, one "name algorithm base64secret" per line (keeps secrets out of the properties). */
	public static final String PROP_TSIG_KEY_FILE = "JDns.tsigKeyFile";
	/** TSIG keys (names) whose signed requests may transfer zones, from any address. */
	public static final String PROP_AXFR_KEYS = "JDns.axfrKeys";
	/** Largest clock difference (seconds) accepted in a TSIG signed request, and the fudge we sign with (default 300). */
	public static final String PROP_TSIG_FUDGE = "JDns.tsigFudge";
	/** TSIG keys (names) whose signed UPDATE requests may change zones (RFC 2136). */
	public static final String PROP_UPDATE_KEYS = "JDns.updateKeys";
	/** Addresses / networks allowed to send unsigned UPDATE requests (default: none; prefer keys). */
	public static final String PROP_UPDATE_ALLOW = "JDns.updateAllow";
	/** TSIG key (name) to sign NOTIFY messages with. */
	public static final String PROP_NOTIFY_KEY = "JDns.notifyKey";
	/** Attempts per NOTIFY (default 5). */
	public static final String PROP_NOTIFY_RETRIES = "JDns.notifyRetries";
	/** First wait (ms) for a NOTIFY answer, doubled after each attempt (default 2000). */
	public static final String PROP_NOTIFY_TIMEOUT = "JDns.notifyTimeout";
	public static final String PROP_USE_DATABASE = "JDns.useDataBase";
	/** Directory of the zones' DNSSEC keys (K&lt;zone&gt;.+alg+tag.key and .private). Default: the zone directory. A zone with keys is signed. */
	public static final String PROP_DNSSEC_KEY_DIR = "JDns.dnssecKeyDir";
	/** How long DNSSEC signatures are valid, e.g. 14d (the default); zones are signed again when a quarter of it is left. */
	public static final String PROP_DNSSEC_VALIDITY = "JDns.dnssecValidity";
	/** Zones to sign with NSEC3 instead of NSEC: a list of zone names, or * for all. Default: none. */
	public static final String PROP_DNSSEC_NSEC3 = "JDns.dnssecNsec3";
	/** NSEC3 extra hash iterations (default 0, as RFC 9276 recommends; at most 100). */
	public static final String PROP_DNSSEC_NSEC3_ITERATIONS = "JDns.dnssecNsec3Iterations";
	/** NSEC3 salt in hex, or - for none (the default, as RFC 9276 recommends). */
	public static final String PROP_DNSSEC_NSEC3_SALT = "JDns.dnssecNsec3Salt";

	public static final String STATUS_ACTIVE = "active";
	public static final String STATUS_DELETED = "deleted";

	private static final String SQL_SELECT_ALL = "select name,ip,lastUpdate from dynamic_dns   where status = '"+STATUS_ACTIVE+"'";
	private static final String SQL_CREATE_DYN_DNS = "insert into dynamic_dns (ip,lastUpdate,status,name ) values(?,?,?,?)";
	private static final String SQL_UPDATE_DYN_DNS = "update dynamic_dns set ip=? ,lastUpdate=?,status=? where name=?";
	private static final int POS_IP = 1;
	private static final int POS_LAST_UPDATE = 2;
	private static final int POS_STATUS = 3;
	private static final int POS_NAME = 4;
	/** UDP listener threads (was UDPProcCount, still read). */
	public static final String PROP_UDP_PROC_COUNT = "JDns.udpProcCount";
	/** TCP acceptor threads (was TCPProcCount, still read). */
	public static final String PROP_TCP_PROC_COUNT = "JDns.tcpProcCount";
	/** Host DnsAdminClient connects to (was the system property "name", still read). */
	public static final String PROP_ADMIN_HOST = "JDns.adminHost";
	public static final String DEFAULT_DNS_DIR = "/data/services/dns/config";


	private static ServerSocketFactory serverSocketFactory=ServerSocketFactory.getDefault();
	private static volatile int adminPort = 9999;
	//  Where the admin port listens (set in initServer, default loopback)
	private volatile InetAddress adminBindAddress = InetAddress.getLoopbackAddress();
	//  Limits concurrent admin sessions (each had its own unbounded thread)
	private volatile java.util.concurrent.Semaphore adminSlots = new java.util.concurrent.Semaphore(8);
	private volatile int adminIdleTimeout = 10*60*1000;
	private volatile int adminMaxLine = DnsAdminProcessor.DEFAULT_MAX_LINE;
	private volatile int adminAuthTimeout = DnsAdminProcessor.DEFAULT_AUTH_TIMEOUT;
	//  UDP/TCP processor threads started by initServer (for stopAndWait)
	private final List<Thread> workers = new java.util.concurrent.CopyOnWriteArrayList<Thread>();
	private static volatile boolean shutdown = false;
	private static volatile boolean _debug = true;
	private boolean standAlone=false;
	//  Startup outcome for awaitStarted(): the latch opens when run() is either
	//  serving or has given up; startupFailure says which.
	private volatile java.util.concurrent.CountDownLatch startLatch = new java.util.concurrent.CountDownLatch(1);
	private volatile StartupException startupFailure;
	private java.util.Date startTime = new java.util.Date();

	//  Recursion Available
	private volatile boolean recursionAvailable = true;


	private Thread thread;	

	//  Directory where all DNS info is stored
	private File dnsDir;

	/**
	 * Immutable snapshot of the zones being served. Queries read one snapshot;
	 * a reload builds a complete new one and publishes it in a single volatile
	 * write, so a query never sees a half-loaded (or empty) set of zones.
	 */
	private static final class ZoneSet {
		static final ZoneSet EMPTY = new ZoneSet(Collections.<String,Zone>emptyMap(), null, Collections.<String,Zone>emptyMap());
		/** lower case zone name -> zone (unmodifiable) */
		final Map<String, Zone> zones;
		final Zone defaultZone;
		/** zone file name -> zone loaded from it (unmodifiable) */
		final Map<String, Zone> byFile;

		ZoneSet(Map<String, Zone> zones, Zone defaultZone, Map<String, Zone> byFile) {
			this.zones = zones;
			this.defaultZone = defaultZone;
			this.byFile = byFile;
		}
	}

	// This information applies to all auth zones unless otherwise defined
	private volatile ZoneSet zoneSet = ZoneSet.EMPTY;
	//  zone file name -> lastModified, as seen by the last load attempt (successful or not)
	private volatile Map<String, Long> lastSeenZoneFiles = null;


	// These servers are used to forward requests
	//private ArrayList forwarders;

	//  lower case domain -> domain. Read by query threads, written by admin threads.
	private final Map<String, String> common = new ConcurrentHashMap<String, String>();

	/**
	 * Dynamic A records: lower case name -> unmodifiable list holding one A.
	 * Read by query threads, written by admin threads and the DB/file reload.
	 * The A objects are never modified after they are published; an address
	 * change replaces the entry (see putDynamic).
	 */
	private final Map<String, List<A>> dynamic = new ConcurrentHashMap<String, List<A>>();
	//  Zone transfer allow-list (JDns.axfrAllow) and NOTIFY sender (JDns.notify)
	private volatile AddressMatcher axfrAllow = AddressMatcher.NONE;
	private volatile Tsig.KeyRing tsigKeys = Tsig.KeyRing.EMPTY;
	private volatile int tsigFudge = Tsig.DEFAULT_FUDGE;
	private volatile java.util.Set<String> axfrKeys = Collections.emptySet();
	private volatile java.util.Set<String> updateKeys = Collections.emptySet();
	private volatile AddressMatcher updateAllow = AddressMatcher.NONE;
	private volatile ZoneNotifier notifier;
	/** Largest message of a zone transfer (a transfer is several messages). */
	static final int AXFR_MESSAGE_SIZE = 16*1024;
	//  Serializes check-then-act updates of dynamic entries
	private final Object dynamicLock = new Object();

	//  Timeout for admin cycles
	private long acceptTimeout = 60000; //  one minute
	private long dynamicConfigRefreash = acceptTimeout * 5;


	//  Number of UDP Processor to create
	private int UDPProcCount = 10;
	private UDPProsessor [] UDPProcs;

	private volatile boolean running = false;

	//  TCP acceptor threads. Connections are served by a separate pool
	//  (JDns.tcp.maxConnections), so one acceptor is enough; it was 4.
	private int TCPProcCount = 1;

	//  Answer names at or below a delegation (NS records below the apex)
	//  with a referral. JDns.zoneCutReferrals=false restores the old
	//  behaviour for zones that list NS records on ordinary hosts.
	private volatile boolean zoneCutReferrals = true;

	public boolean isZoneCutReferrals() {
		return zoneCutReferrals;
	}

	public void setZoneCutReferrals(boolean on) {
		zoneCutReferrals = on;
	}

	/** Number of TCP acceptor threads (property TCPProcCount). */
	public int getTcpProcCount() {
		return TCPProcCount;
	}	
	private TCPProsessor [] TCPProcs;
	private String defaultZoneName;
	private File dynamicFile;
	private long dynamicLoaded;
	private File zoneDir;


	/**
	 * Server constructor comment.
	 */
	public DnsServer() {


	}

	/**
	 * Add a domain to our domain list
	 **/
	public void addDomain(String domain) {
		common.put(domain.toLowerCase(),domain);
	}

	/*
	 * Add a new Zone to the global data
	 */
	public synchronized void addZone(Zone zone) {
		ZoneSet cur = zoneSet;
		reloadDnssecKeys();
		Map<String, Zone> zones = new HashMap<String, Zone>(cur.zones);
		String key = zone.getName().toLowerCase();
		zones.put(key,zone);
		//  Signed if the key directory has keys for it
		zones.put(key, prepareZone(zone, cur.zones.get(key), true, zones));
		zoneSet = new ZoneSet(Collections.unmodifiableMap(zones), cur.defaultZone, cur.byFile);
	}


	public boolean isStandAlone() {
		return standAlone;
	}

	public void setStandAlone(boolean standAlone) {
		this.standAlone = standAlone;


	}

	public boolean isRunning() {
		return running;
	}

	/**
	 * Why the server could not start (see {@link DnsServer#awaitStarted(long)}).
	 * The exit code is what main() exits with: -1 when the configuration, zones or
	 * UDP/TCP sockets could not be set up, -2 when the admin socket could not be opened.
	 */
	public static class StartupException extends IOException {
		private static final long serialVersionUID = 1L;
		private final int exitCode;

		public StartupException(String message, Throwable cause, int exitCode) {
			super(message, cause);
			this.exitCode = exitCode;
		}

		public int getExitCode() {
			return exitCode;
		}
	}

	/**
	 * Wait until the server started by {@link #start()} is serving.
	 * 
	 * @param timeoutMs how long to wait (0 or less: no limit)
	 * @throws StartupException if the server could not start; everything it had
	 *   started (UDP/TCP threads, resolver) has been stopped again
	 * @throws IOException if it has not finished starting within timeoutMs
	 */
	public void awaitStarted(long timeoutMs) throws IOException, InterruptedException {
		java.util.concurrent.CountDownLatch latch = startLatch;
		if( timeoutMs <= 0 ) {
			latch.await();
		} else if( !latch.await(timeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS) ) {
			throw new IOException("DNS server did not start within "+timeoutMs+" ms");
		}
		StartupException ex = startupFailure;
		if( ex != null ) {
			throw ex;
		}
	}

	/**
	 * 
	 * Creation date: (6/16/2003 9:29:24 AM)
	 * @return int
	 */
	public static int getAdminPort() {
		return adminPort;
	}

	/*
	 * This dose not use the Jmail.Database
	 * Factory because the connection will not remain open
	 */
	/**
	 * Open a JDBC connection from JDns.jdbcClass / jdbcURL / jdbcUser / jdbcPassword.
	 * @throws SQLException if it can't be opened. (It used to log and return
	 * null, and every caller then failed with a NullPointerException.)
	 */
	//  One JDBC connection, kept open and reused (it used to be opened and
	//  closed for every load, update and delete). Guarded by dbLock; database
	//  work is rare (reloads, dynamic updates) so it is simply serialized.
	private final Object dbLock = new Object();
	private Connection dbConnection;
	private long dbConnectionsOpened;
	static final int DB_VALID_TIMEOUT_SECONDS = 2;

	/** Work done with the shared connection. */
	interface SqlWork<T> {
		T run(Connection con) throws SQLException;
	}

	/**
	 * Run work with the shared connection: opened on first use, checked with
	 * isValid() before reuse (the database may have closed an idle one) and
	 * reopened if needed. After an SQLException the connection is closed, so
	 * the next call starts with a fresh one.
	 * Lock order is dynamicLock, then dbLock (the dynamic update methods
	 * call this while holding dynamicLock), so work must not take dynamicLock.
	 */
	<T> T withConnection(SqlWork<T> work) throws SQLException {
		synchronized (dbLock) {
			Connection con = dbConnection;
			if( con != null && !isUsable(con) ) {
				IoUtils.closeQuietly(con);
				con = dbConnection = null;
			}
			if( con == null ) {
				con = getConnection();
				dbConnection = con;
				dbConnectionsOpened++;
			}
			try {
				return work.run(con);
			} catch(SQLException | RuntimeException ex) {
				IoUtils.closeQuietly(con);
				dbConnection = null;
				throw ex;
			}
		}
	}

	/** How many JDBC connections have been opened (for tests and status). */
	long getDbConnectionsOpened() {
		synchronized (dbLock) {
			return dbConnectionsOpened;
		}
	}

	/** Close the shared JDBC connection (on shutdown). */
	void closeDbConnection() {
		synchronized (dbLock) {
			IoUtils.closeQuietly(dbConnection);
			dbConnection = null;
		}
	}

	private static boolean isUsable(Connection con) {
		try {
			return con.isValid(DB_VALID_TIMEOUT_SECONDS);
		} catch(SQLException ex) {
			return false;
		} catch(AbstractMethodError ex) {
			//  Very old (pre JDBC 4) driver without isValid
			try {
				return !con.isClosed();
			} catch(SQLException e) {
				return false;
			}
		}
	}


	private Connection getConnection() throws SQLException {
		String jdbcClass = stringProperty(PROP_JDBC_CLASS);
		String url = stringProperty(PROP_JDBC_URL);
		String user = getProperty(PROP_JDBC_USER);
		String password = getProperty(PROP_JDBC_PASSWORD);
		if( url == null ) {
			throw new SQLException(PROP_JDBC_URL+" is not set");
		}
		if( jdbcClass != null ) {
			try {
				Class.forName(jdbcClass);
			} catch(ClassNotFoundException ex) {
				throw new SQLException("JDBC driver class not found: "+jdbcClass, ex);
			}
		}
		return DriverManager.getConnection(url,user,password);
	}

	/**
	 * 
	 * Creation date: (6/16/2003 9:29:24 AM)
	 * @return javax.net.ServerSocketFactory
	 */
	public static javax.net.ServerSocketFactory getServerSocketFactory() {
		return serverSocketFactory;
	}

	public java.util.Date getStartTime() {
		return startTime;
	}

	/**
	 * Find the closest Zone that matches this Question (Section)
	 **/
	public TCPProsessor [] getTCPProsessors() {
		return TCPProcs;
	}

	/**
	 * Find the closest Zone that matches this Question (Section)
	 **/
	public UDPProsessor [] getUDPProsessors() {
		return UDPProcs;
	}

	/**
	 * Find the closest Zone that matches this Question (Section)
	 **/
	public Zone getZone(String zoneName) {

		Zone ret = zoneSet.zones.get(zoneName.toLowerCase());


		return ret;
	}

	/**
	 * Find the closest Zone that matches this Question (Section)
	 **/
	public  Zone getZone(Section question) {


		Zone ret = null;
		Name target = question.getNameAsName();

		while( target != null && (ret=getZone(target.toString()))== null ) {
			target = target.getParentName();
		}
		return ret;
	}

	/**
	 * Find the closest Zone that matches this Question (Section)
	 **/
	public Map<String, Zone> getZones() {
		//  unmodifiable snapshot
		return zoneSet.zones;
	}

	/**
	 * Initialize the server from properties
	 * @throws IOException 
	 */

	public void initServer() throws IOException 	{

		if(UDPProcs != null ) {
			logError("init called when UDPProcs is not null");
			return;
		}

		//First find and load any external property file 
		String propertyFile = getProperty(PROP_DNS_PROPERTIES,DEFAULT_PROPERTIES_FILE_NAME);

		//  Look for a file that may change these values.
		File f = new File(propertyFile).getCanonicalFile();;


		Properties prop1 = System.getProperties();
		//  First load the properties from the file
		if( f.exists() ) {
			log("Loading properties from "+f);
			InputStream in = new FileInputStream(f);
			try {
				Properties prop2 = new Properties();
				prop2.load(in);

				//  Override with system properties
				for(Object key  : prop1.keySet()) {
					prop2.setProperty(key.toString(), prop1.getProperty(key.toString()));
				}
				log("Here are the properties we're using");
				for(Entry<Object, Object> e : prop2.entrySet()) {
					log(e.getKey()+"="+e.getValue());
				}

				System.setProperties(prop2);
				// logging config may have changed
				setLogger(null);
			} finally {
				in.close();	
			}
		} else {
			log("Properties do not exits file="+f);
		}


		String tmp = null;	

		initFromProperties();
		if(!dnsDir.exists()) {
			throw new IOException("dnsDir does not exist ="+dnsDir);
		}

		loadZones();
		loadCommon();
		loadDynamic();

		int alltimeout = intProperty(PROP_TIMEOUT, 5000);
		int dnsPort = intProperty(PROP_PORT, Message.DNSPORT);

		InetAddress bindAddress = InetAddress.getLoopbackAddress();
		if( (tmp=stringProperty(PROP_BIND_ADDRESS)) != null) {
			bindAddress = createBindAddress(tmp);
		}

		//  ---- UDP (each setting falls back to the general one)
		int udpPort = intProperty(PROP_UDP_PORT, dnsPort);
		InetAddress udpAddress = bindAddress;
		if( (tmp=stringProperty(PROP_UDP_BIND_ADDRESS)) != null) {
			udpAddress = createBindAddress(tmp);
		}
		//  (JDns.udpTimeout used to overwrite the general timeout instead of
		//  setting the UDP one, so it changed the TCP timeout and not UDP's)
		int udpTimeout = intProperty(PROP_UDP_TIMEOUT, alltimeout);
		UDPProsessor.setMaxResponseSize(intProperty(PROP_UDP_MAX_RESPONSE, UDPProsessor.getMaxResponseSize()));
		Edns.setServerUdpSize(intProperty(PROP_EDNS_UDP_SIZE, Edns.DEFAULT_UDP_SIZE));
		String refs = stringProperty(PROP_ZONE_CUT_REFERRALS);
		if( refs != null ) {
			zoneCutReferrals = refs.trim().toLowerCase().startsWith("t");
		}

		UDPProcs = new UDPProsessor[UDPProcCount];
		Thread t = null;
		log("UDP BindAddress = "+udpAddress+":"+udpPort+" timeout="+udpTimeout+" maxResponse="+UDPProsessor.getMaxResponseSize());
		UDPProsessor.initUDPProsessor(udpPort,udpAddress,udpTimeout);

		for(int i=0; i< UDPProcs.length; i++ ) {
			UDPProcs[i] = new UDPProsessor(this,i);
			t = new Thread(UDPProcs[i]);
			t.setName("UDPProc"+i);
			workers.add(t);
			t.start();
		}

		//  ---- TCP
		TCPProcs = new TCPProsessor[TCPProcCount];
		int tcpPort = intProperty(PROP_TCP_PORT, dnsPort);
		int backlog = intProperty(PROP_TCP_BACKLOG, 10);
		//  (JDns.tcpBindAddress used to be read and then ignored)
		InetAddress tcpAddress = bindAddress;
		if( (tmp=stringProperty(PROP_TCP_BIND_ADDRESS)) != null) {
			tcpAddress = createBindAddress(tmp);
		}
		int tcpTimeout = intProperty(PROP_TCP_TIMEOUT, alltimeout);
		int tcpMaxConnections = intProperty(PROP_TCP_MAX_CONNECTIONS, TCPProsessor.DEFAULT_MAX_CONNECTIONS);
		int tcpIdleTimeout = intProperty(PROP_TCP_IDLE_TIMEOUT, TCPProsessor.DEFAULT_IDLE_TIMEOUT);

		log("TCP BindAddress = "+tcpAddress+":"+tcpPort+" backlog="+backlog+" timeout="+tcpTimeout
				+" maxConnections="+tcpMaxConnections+" idleTimeout="+tcpIdleTimeout);
		TCPProsessor.initTCPProsessor(tcpPort,backlog,tcpAddress,tcpTimeout,tcpMaxConnections,tcpIdleTimeout);

		for(int i=0; i< TCPProcs.length; i++ ) {
			TCPProcs[i] = new TCPProsessor(this,i);
			t = new Thread(TCPProcs[i]);
			t.setName("TCPProc"+i);
			workers.add(t);
			t.start();
		}

		us.bringardner.net.dns.resolve.Resolver.initResolver();


		//  ---- Admin (the socket is opened in run())
		setAdminPort(intProperty(PROP_ADMIN_PORT, getAdminPort()));
		serverSocketFactory = adminSocketFactory(stringProperty(PROP_ADMIN_TLS), serverSocketFactory);
		if( serverSocketFactory instanceof javax.net.ssl.SSLServerSocketFactory ) {
			log("Admin port uses TLS");
		}
		adminBindAddress = InetAddress.getLoopbackAddress();
		if( (tmp=stringProperty(PROP_ADMIN_BIND_ADDRESS)) != null) {
			adminBindAddress = createBindAddress(tmp);
		}
		adminSlots = new java.util.concurrent.Semaphore(Math.max(1, intProperty(PROP_ADMIN_MAX_CONNECTIONS, 8)));
		adminIdleTimeout = intProperty(PROP_ADMIN_IDLE_TIMEOUT, adminIdleTimeout);
		adminMaxLine = intProperty(PROP_ADMIN_MAX_LINE, adminMaxLine);
		adminAuthTimeout = intProperty(PROP_ADMIN_AUTH_TIMEOUT, adminAuthTimeout);
		if( stringProperty(PROP_ADMIN_SECRET) == null && !adminBindAddress.isLoopbackAddress() ) {
			logError("Admin port listens on "+adminBindAddress+" but "+PROP_ADMIN_SECRET
					+" is not set: only clients on this machine will be accepted");
		}

		log("JDns Server init Complete");
	}  

	/** @return the trimmed property value, or null if it is not set or empty */
	private String stringProperty(String name) {
		String ret = getProperty(name);
		if( ret != null ) {
			ret = ret.trim();
			if( ret.isEmpty() ) {
				ret = null;
			}
		}
		return ret;
	}

	/**
	 * @return the integer value of a property, or def if it is not set or empty
	 * @throws IOException naming the property if the value is not a number
	 */
	int intProperty(String name, int def) throws IOException {
		String tmp = stringProperty(name);
		if( tmp == null ) {
			return def;
		}
		try {
			return Integer.parseInt(tmp);
		} catch(NumberFormatException ex) {
			throw new IOException("Invalid number for "+name+": '"+tmp+"'");
		}
	}

	public InetAddress getAdminBindAddress() {
		return adminBindAddress;
	}

	/**
	 * Start an admin session for an accepted connection, or turn it away if
	 * JDns.adminMaxConnections sessions are already open.
	 * @return true if a session was started
	 */
	boolean handleAdminConnection(Socket clientSocket) {
		final java.util.concurrent.Semaphore slots = adminSlots;
		if( !slots.tryAcquire() ) {
			log("Refused admin connection from "+clientSocket.getInetAddress()+": too many admin sessions");
			try {
				clientSocket.getOutputStream().write("-Too many admin connections\r\n".getBytes());
				clientSocket.close();
			} catch(IOException ex) {
			}
			return false;
		}
		try {
			DnsAdminProcessor admin = new DnsAdminProcessor(this,clientSocket);
			admin.setTimeout(adminIdleTimeout);
			admin.setMaxLine(adminMaxLine);
			admin.setAuthTimeout(adminAuthTimeout);
			admin.setOnFinish(slots::release);
			admin.start();
			return true;
		} catch(IOException | RuntimeException ex) {
			slots.release();
			log("Can't start admin session",ex);
			IoUtils.closeQuietly(clientSocket);
			return false;
		}
	}

	/** Longest admin line in bytes (initServer reads JDns.adminMaxLine). */
	void setAdminMaxLine(int maxLine) {
		adminMaxLine = maxLine;
	}

	/** ms an admin client has to authenticate (initServer reads JDns.adminAuthTimeout). */
	void setAdminAuthTimeout(int ms) {
		adminAuthTimeout = ms;
	}

	//  JDns.notifyKey (applied by setNotifyTargets)
	private volatile String notifyKeyName;

	/** The TSIG keys (initServer reads JDns.tsigKeys and JDns.tsigKeyFile). */
	public Tsig.KeyRing getTsigKeys() {
		return tsigKeys;
	}

	public void setTsigKeys(Tsig.KeyRing keys) {
		tsigKeys = keys == null ? Tsig.KeyRing.EMPTY : keys;
		if( !tsigKeys.isEmpty() ) {
			log("TSIG keys: "+tsigKeys.size());
		}
	}

	/** Largest clock difference (seconds) for TSIG, 1-65535 (initServer reads JDns.tsigFudge). */
	public int getTsigFudge() {
		return tsigFudge;
	}

	public void setTsigFudge(int seconds) {
		tsigFudge = Tsig.checkFudge(seconds);
	}

	/** TSIG keys whose signed requests may transfer zones (initServer reads JDns.axfrKeys). */
	public void setAxfrKeys(String list) {
		axfrKeys = keyNames(list, PROP_AXFR_KEYS);
	}

	/** TSIG keys whose signed UPDATE requests may change zones (initServer reads JDns.updateKeys). */
	public void setUpdateKeys(String list) {
		updateKeys = keyNames(list, PROP_UPDATE_KEYS);
	}

	/** Who may send unsigned UPDATE requests (initServer reads JDns.updateAllow). */
	public void setUpdateAllow(String list) {
		updateAllow = AddressMatcher.parse(list);
	}

	private java.util.Set<String> keyNames(String list, String prop) {
		java.util.Set<String> ret = new java.util.HashSet<String>();
		if( list != null ) {
			for(String k : list.trim().split("[,\\s]+")) {
				if( !k.isEmpty() ) {
					Tsig.Key key = tsigKeys.get(k);
					if( key == null ) {
						throw new IllegalArgumentException(prop+" names an unknown TSIG key: "+k);
					}
					ret.add(key.getName());
				}
			}
		}
		return Collections.unmodifiableSet(ret);
	}

	/** The TSIG key to sign NOTIFY with (set before setNotifyTargets). */
	public void setNotifyKey(String name) {
		notifyKeyName = name;
	}

	/** Who may transfer zones (initServer reads JDns.axfrAllow). */
	public void setAxfrAllow(String list) {
		axfrAllow = AddressMatcher.parse(list);
		if( !axfrAllow.isEmpty() ) {
			log("Zone transfers allowed for "+axfrAllow);
		}
	}

	/** Where to send NOTIFY (initServer reads JDns.notify); null or empty: nowhere. */
	public void setNotifyTargets(String list, int retries, int timeoutMs) {
		ZoneNotifier old = notifier;
		Tsig.Key key = null;
		String kn = notifyKeyName;
		if( kn != null && !kn.trim().isEmpty() ) {
			key = tsigKeys.get(kn.trim());
			if( key == null ) {
				throw new IllegalArgumentException(PROP_NOTIFY_KEY+" names an unknown TSIG key: "+kn);
			}
		}
		ZoneNotifier n = new ZoneNotifier(list, retries, timeoutMs, key, tsigFudge);
		notifier = n.getTargets().isEmpty() ? null : n;
		if( old != null ) {
			old.shutdown();
		}
	}

	/** The NOTIFY sender, or null if JDns.notify is not set. */
	public ZoneNotifier getNotifier() {
		return notifier;
	}

	/** Set the most admin sessions at once (initServer reads JDns.adminMaxConnections). */
	void setAdminMaxConnections(int max) {
		adminSlots = new java.util.concurrent.Semaphore(Math.max(1, max));
	}

	/** Admin sessions that can still be opened. */
	public int getAvailableAdminSlots() {
		return adminSlots.availablePermits();
	}

	/**
	 * Open the admin listener on adminPort / adminBindAddress.It used to
	 * listen on every interface regardless of the DNS bind address.
	 */
	ServerSocket createAdminSocket() throws IOException {
		return getServerSocketFactory().createServerSocket(getAdminPort(), 50, adminBindAddress);
	}

	private InetAddress createBindAddress(String tmp) throws UnknownHostException {
		InetAddress ret = InetAddress.getLoopbackAddress();
		if( tmp.equals("localhost")) {
			//  Kept for compatibility, but surprising: "localhost" here means
			//  this host's own name/address, not the loopback interface
			ret = InetAddress.getLocalHost();
			logError("Bind address 'localhost' means this host's address "+ret
					+" (reachable from the network), not the loopback; use 127.0.0.1 to listen on loopback only");
		} else {
			ret = InetAddress.getByName(tmp);
		}
		if( ret == null) {
			ret = InetAddress.getLocalHost();
		}
		return ret;
	}

	/**
	 * Initialize the server from properties
	 */
	private void initFromProperties() {
		String tmp = null;
		try {
			Tsig.KeyRing keys = Tsig.KeyRing.parse(stringProperty(PROP_TSIG_KEYS));
			String keyFile = stringProperty(PROP_TSIG_KEY_FILE);
			if( keyFile != null ) {
				File f = new File(keyFile);
				if( !f.isAbsolute() ) {
					//  Relative to JDns.dnsDir, like the other files
					f = new File(getProperty(PROP_DNS_DIR,DEFAULT_DNS_DIR), keyFile);
				}
				keys = keys.with(Tsig.KeyRing.load(f));
			}
			setTsigKeys(keys);
			setTsigFudge(intProperty(PROP_TSIG_FUDGE, Tsig.DEFAULT_FUDGE));
			setAxfrKeys(stringProperty(PROP_AXFR_KEYS));
			setUpdateKeys(stringProperty(PROP_UPDATE_KEYS));
			setUpdateAllow(stringProperty(PROP_UPDATE_ALLOW));
			setAxfrAllow(stringProperty(PROP_AXFR_ALLOW));
			notifyKeyName = stringProperty(PROP_NOTIFY_KEY);
			String kd = stringProperty(PROP_DNSSEC_KEY_DIR);
			setDnssecKeyDir(kd == null ? null : new File(kd));
			String validity = stringProperty(PROP_DNSSEC_VALIDITY);
			if( validity != null ) {
				setDnssecValidity(Utility.toSeconds(validity));
			}
			setDnssecNsec3(stringProperty(PROP_DNSSEC_NSEC3),
					us.bringardner.net.dns.dnssec.Nsec3Params.parse(intProperty(PROP_DNSSEC_NSEC3_ITERATIONS, 0),
							stringProperty(PROP_DNSSEC_NSEC3_SALT)));
			setNotifyTargets(stringProperty(PROP_NOTIFY),
					intProperty(PROP_NOTIFY_RETRIES, ZoneNotifier.DEFAULT_RETRIES),
					intProperty(PROP_NOTIFY_TIMEOUT, ZoneNotifier.DEFAULT_TIMEOUT));
		} catch(IOException ex) {
			throw new IllegalArgumentException(ex);
		}
		if( (tmp=getProperty(PROP_DEBUG)) != null) {
			_debug = tmp.toLowerCase().equals("true");
		}

		if( (tmp=getProperty(PROP_JDNS_RA)) != null) {
			recursionAvailable = tmp.toLowerCase().equals("true");
		}

		dnsDir=new File(getProperty(PROP_DNS_DIR,DEFAULT_DNS_DIR));

		if( (tmp=us.bringardner.net.dns.RenamedProperty.get(PROP_UDP_PROC_COUNT, "UDPProcCount")) != null)  {
			try { UDPProcCount =Integer.parseInt(tmp.trim()); } catch(Exception ex) {
				logError("Invalid number for "+PROP_UDP_PROC_COUNT+": '"+tmp+"', using "+UDPProcCount);
			}
		}
		if( (tmp=us.bringardner.net.dns.RenamedProperty.get(PROP_TCP_PROC_COUNT, "TCPProcCount")) != null)  {
			try { TCPProcCount =Integer.parseInt(tmp.trim()); } catch(Exception ex) {
				logError("Invalid number for "+PROP_TCP_PROC_COUNT+": '"+tmp+"', using "+TCPProcCount);
			}
		}

	}

	/*
	 *  Look for the smallest common value (a.b.c.com could match .com, c.com or b.c.com)
	 */
	private boolean isCommon(Section question) {
		boolean ret = false;
		Name name = new Name(question.getName().toLowerCase());
		while(!ret && name != null ) {
			ret = isCommon(name);
			if( !ret ) {
				name = name.getParentName();
			}
		}


		return ret;

	}

	public boolean isCommon(Name name)  {
		//System.out.println("isCommon start name="+name);
		boolean ret = false;
		while(!ret && name != null ) {
			//System.out.println("isCommon loop name="+name);
			ret = common.containsKey(name.toString().toLowerCase());
			if( !ret ) {
				name = name.getParentName();
			}
		}
		//System.out.println("isCommon end name="+name+" ret="+ret);

		return ret;

	}

	/**
	 * 
	 * Creation date: (6/16/2003 10:38:48 AM)
	 * @return boolean
	 */
	public static boolean isDebug() {
		return _debug;
	}

	/**
	 * 
	 * Creation date: (6/27/2003 6:47:28 AM)
	 * @return boolean
	 */
	public boolean isRecursionAvailable() {
		return recursionAvailable;
	}

	/**
	 * 
	 * Creation date: (6/16/2003 10:38:48 AM)
	 * @return boolean
	 */
	public static boolean isShutdown() {
		return shutdown;
	}

	/**
	 * DNS Server supports a list of domains that have a common configuration
	 * dramatically reducing the administrative effort.
	 */
	private void loadCommon() {

		if( useDatabase()) {
			try {
				List<String> names = withConnection(con -> {
					List<String> ret = new ArrayList<String>();
					try(Statement stmt = con.createStatement();
							ResultSet rs = stmt.executeQuery("select name from domains")) {
						while( rs.next() ) {
							ret.add(rs.getString(1));
						}
					}
					return ret;
				});
				for(String name : names) {
					common.put(name.toLowerCase(),name);
					log("Install common domain ="+name);
				}
			} catch (Throwable ex) {
				log("Database not availible",ex);
			}
		}

	}

	void loadDynamic() {
		try {
			if( !loadDynamicFromDb()) {
				dynamicFile = loadDynamicFromFile(false);
			}
		} catch(Throwable ex) {
			logError("Could not load dynamic from db. Calling loadFromFile", ex);
			try {
				dynamicFile = loadDynamicFromFile(false);
			} catch (IOException e) {
				logError("Could not load dynamic from file.", e);
			}
		}
		dynamicLoaded = System.currentTimeMillis();
		flushDynamicSigning();
	}

	
	/**
	 * Add or change a dynamic entry. The store (database, or the dynamic file
	 * when there is no database) is written FIRST; memory changes only if that
	 * succeeds, so a failed write leaves the old state everywhere. (Memory used
	 * to change first: a failed write left the server answering with an
	 * address the store didn't have.)
	 * 
	 * @throws SQLException if the database write fails (nothing is changed)
	 */
	public void addOrUpdateDynamic(String name, String ip) throws ClassNotFoundException, SQLException {
		synchronized (dynamicLock) {
			List<A> dyn = getDynamic(name);
			if(dyn == null ) {
				//  Validates the domain and the address; nothing is published yet
				A a = buildDynamic(name, ip);
				if( a == null ) {
					logError("-Undefined domain for "+name);
					return;
				}
				createDynamic(name,ip);
				storeDynamicFileOrThrow(withEntry(a));
				putDynamic(a);
			} else {
				A old = dyn.get(0);
				A a = old;
				if( !ip.equals(old.getAddressString())) {
					a = copyWithAddress(old, ip);
				}
				//  Keep track of the last time we were contacted. If there is no
				//  row (the entry came from the dynamic file), insert one.
				if( saveDynamic(name,ip,STATUS_ACTIVE) == 0 ) {
					createDynamic(name,ip);
				}
				if( a != old ) {
					storeDynamicFileOrThrow(withEntry(a));
					putDynamic(a);
				}
			}
		}
		flushDynamicSigning();
	}

	/** storeDynamicFile, with an I/O failure reported like a database failure. */
	private void storeDynamicFileOrThrow(Map<String, List<A>> after) throws SQLException {
		try {
			storeDynamicFile(after);
		} catch(IOException ex) {
			throw new SQLException("Could not write the dynamic file: "+ex.getMessage(), ex);
		}
	}

	/** The dynamic entries as they would be with a added or replaced. */
	private Map<String, List<A>> withEntry(A a) {
		Map<String, List<A>> ret = new HashMap<String, List<A>>(dynamic);
		ret.put(dynamicKey(a.getName()), Collections.singletonList(a));
		return ret;
	}

	/** @return rows updated, or -1 if no database is used */
	private int saveDynamic(String name, String ip, String status) throws ClassNotFoundException, SQLException {
		int ret = -1;
		if( useDatabase()) {
			ret = withConnection(con -> {
				try(PreparedStatement stmt = con.prepareStatement(SQL_UPDATE_DYN_DNS)) {
					stmt.setString(POS_NAME, name);
					stmt.setString(POS_IP, ip);
					stmt.setString(POS_STATUS, status);
					stmt.setTimestamp(POS_LAST_UPDATE, new Timestamp(System.currentTimeMillis()));
					return stmt.executeUpdate();
				}
			});
		}
		return ret;
	}
	private void createDynamic(String name, String ip) throws ClassNotFoundException, SQLException {
		if( useDatabase()) {
			withConnection(con -> {
				try(PreparedStatement stmt = con.prepareStatement(SQL_CREATE_DYN_DNS)) {
					stmt.setString(POS_NAME, name);
					stmt.setString(POS_IP, ip);
					stmt.setString(POS_STATUS, STATUS_ACTIVE);
					stmt.setTimestamp(POS_LAST_UPDATE, new Timestamp(System.currentTimeMillis()));
					return stmt.executeUpdate();
				}
			});
		}
	}

	/**
	 * JDns.useDataBase=true/false decides. If it is not set, the database is
	 * used only when JDns.jdbcURL is configured. (The old default was 'true',
	 * so a server without a database tried to connect on every dynamic update
	 * and reload, logged errors and hit NullPointerExceptions.)
	 */
	boolean useDatabase() {
		String flag = stringProperty(PROP_USE_DATABASE);
		if( flag != null ) {
			return flag.toLowerCase().startsWith("t");
		}
		return stringProperty(PROP_JDBC_URL) != null;
	}

	private boolean loadDynamicFromDb() throws ClassNotFoundException, SQLException {
		boolean ret = false;
		if( useDatabase()) {
			log("Loading dynamic from database");
			//  Read the rows first, then update memory: dynamicLock is never
			//  taken while the database connection is held (see withConnection)
			List<String[]> dbRows = withConnection(con -> {
				List<String[]> list = new ArrayList<String[]>();
				try(Statement stmt = con.createStatement();
						ResultSet rs = stmt.executeQuery(SQL_SELECT_ALL)) {
					while(rs.next()) {
						list.add(new String[] {rs.getString(1), rs.getString(2)});
					}
				}
				return list;
			});
			{
				for(String [] row : dbRows) {
					String name = row[0];
					String ip = row[1];
					synchronized (dynamicLock) {
						List<A> dyn = getDynamic(name);
						if( dyn != null ) {
							A a = dyn.get(0);
							String old = a.getAddressString();
							if( !ip.equals(old)) {
								replaceDynamicAddress(a, ip);
								ret = true;
							}
						} else {
							addDynamic(name,ip);
							ret = true;
						}
					}
					log("Dynamic "+name+" "+ip+" ret="+ret);
				}
				if( ret ) {
					try {
						dynamicFile = saveDynamicToFile();
					} catch (IOException e) {
						logError("Could not save dynamic to file",e);
					}
				}
			}
		}
		return ret;
	}

	/** The dynamic entries file (JDns.dynamicFileName, relative to the DNS directory). */
	private File dynamicFilePath() {
		String fileName = getProperty(PROP_DYNAMIC,"dynamic.txt");
		File ret = new File(fileName);
		if( !ret.isAbsolute() ) {
			ret = new File(dnsDir,fileName);
		}
		return ret;
	}

	private File loadDynamicFromFile(boolean saveNew) throws IOException {
		File ret = dynamicFilePath();
		log("Loading dynamic "+PROP_DYNAMIC+"= "+ret);

		if( ret.exists() ) {
			BufferedReader in = new BufferedReader(new FileReader(ret));
			try {
				Properties p = new Properties();				
				p.load(in);
				for(Object key : p.keySet()) {
					String name = key.toString();
					//  The address comes from the file (it used to be read with
					//  getProperty(name), i.e. from the system properties, so every
					//  entry got a null address and loading failed).
					String ip = p.getProperty(name);
					if( getDynamic(name) == null) {
						try {
							if( saveNew) {
								addOrUpdateDynamic(name, ip);
							} else {
								addDynamic(name, ip);
								log("Loading dynamic from file "+name+" "+ip);
							}
						} catch (ClassNotFoundException | SQLException e) {
							throw new IOException(e);
						} catch (RuntimeException e) {
							//  One bad line (e.g. an invalid address) doesn't stop the rest
							logError("Skipping dynamic entry "+name+"="+ip+" in "+ret+": "+e.getMessage());
						}
					}
				}				
			} finally {
				IoUtils.closeQuietly(in);
			}
		}

		return ret;
	}

	public File saveDynamicToFile() throws IOException {
		return saveDynamicToFile(dynamic);
	}

	/**
	 * Write entries (name -> [A]) to the dynamic file. The file is written to
	 * a temporary file and renamed, so a crash or a concurrent reader never
	 * sees a half-written file.
	 */
	private File saveDynamicToFile(Map<String, List<A>> entries) throws IOException {
		File ret = dynamicFilePath();
		log(PROP_DYNAMIC+"= "+ret);
		File dir = ret.getAbsoluteFile().getParentFile();
		if( dir != null && !dir.isDirectory() ) {
			//  (createTempFile only said "No such file or directory")
			throw new IOException("Can't save dynamic entries: the directory of "+ret+" does not exist. "
					+"A relative "+PROP_DYNAMIC+" is relative to "+PROP_DNS_DIR+" ("+dnsDir+")");
		}
		File tmp = File.createTempFile(ret.getName(), ".tmp", dir);
		try {
			PrintStream out = new PrintStream(new FileOutputStream(tmp));
			try {
				out.println("# Dynamic entries saved at "+(new Date()));
				for(Map.Entry<String, List<A>> e : new java.util.TreeMap<String, List<A>>(entries).entrySet()) {
					out.println(e.getKey()+"="+e.getValue().get(0).getAddressString());
				}
			} finally {
				out.close();
			}
			if( out.checkError() ) {
				throw new IOException("Error writing "+tmp);
			}
			try {
				java.nio.file.Files.move(tmp.toPath(), ret.toPath(),
						java.nio.file.StandardCopyOption.REPLACE_EXISTING, java.nio.file.StandardCopyOption.ATOMIC_MOVE);
			} catch(java.nio.file.AtomicMoveNotSupportedException ex) {
				java.nio.file.Files.move(tmp.toPath(), ret.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
			}
		} finally {
			tmp.delete();
		}
		return ret;
	}

	/**
	 * Without a database the dynamic file is the store: write the entries as
	 * they will be after a change, before the change is made in memory.
	 * (Admin changes used to exist only in memory and were lost on restart.)
	 */
	private void storeDynamicFile(Map<String, List<A>> after) throws IOException {
		if( !useDatabase() ) {
			dynamicFile = saveDynamicToFile(after);
			//  Our own write is not a change to reload
			dynamicLoaded = dynamicFile.lastModified();
		}
	}


	private File [] getZoneFiles() {
		File [] ret = 	zoneDir.listFiles(new FilenameFilter() {
			@Override
			public boolean accept(File dir, String name) {
				return name.endsWith(".txt") && !name.startsWith(".");
			}
		});


		return ret;
	}

	/** Zone file name -> stamp (see zoneStamp) for the zone files in zoneDir now. */
	private Map<String, Long> currentZoneFiles() {
		Map<String, Long> ret = new HashMap<String, Long>();
		File [] list = zoneDir == null ? null : getZoneFiles();
		if( list != null ) {
			ZoneSet cur = zoneSet;
			for(File f : list) {
				ret.put(f.getName(), zoneStamp(f.lastModified(), cur.byFile.get(f.getName())));
			}
		}
		return ret;
	}

	/**
	 * A zone file's timestamp combined with those of the files it reads with
	 * $INCLUDE, so editing an included file reloads the zone.
	 */
	static long zoneStamp(long modified, Zone z) {
		long ret = modified;
		if( z != null ) {
			for(File inc : z.getIncludedFiles()) {
				ret = ret*31 + inc.lastModified();
			}
		}
		return ret;
	}

	/**
	 * @return true if a zone file was added, removed or modified since the last
	 * load attempt. A file that failed to load does not cause another reload
	 * until it changes (it used to trigger a full reload every admin cycle).
	 */
	boolean shouldReloadZones() {
		Map<String, Long> seen = lastSeenZoneFiles;
		if( zoneDir == null || seen == null ) {
			return true;
		}
		return !currentZoneFiles().equals(seen) || dnssecKeysChanged();
	}

	/**
	 * Load (or reload) all zones from zoneDir and publish them atomically.
	 * <ul>
	 * <li>Files whose timestamp has not changed reuse the Zone already loaded.</li>
	 * <li>If a changed file fails to parse, the previous version of that zone
	 *     is kept (logged); a new file that fails is skipped (logged).</li>
	 * <li>If the default zone can't be found the new set is not published:
	 *     the server keeps serving the previous zones and an IOException is thrown.</li>
	 * </ul>
	 */
	synchronized void loadZones() throws IOException {
		String dirName = getProperty(PROP_ZONE_DIR,"zones");
		log("Loading zonez "+PROP_ZONE_DIR+"= "+dirName);
		zoneDir = new File(dirName).getCanonicalFile();

		Map<String, Long> seen = new HashMap<String, Long>();
		reloadDnssecKeys();
		try {
			if( !zoneDir.exists() ) {
				throw new IOException(PROP_ZONE_DIR+" ="+zoneDir+" does not exist!!! exiting from "+getClass().getName());
			}
			File [] list = getZoneFiles(); 
			if( list == null || list.length == 0 ) {
				throw new IOException("Can't find zone file! Must have at lease a default Zone.  seraching in ("+zoneDir+") exiting from "+getClass().getName());			
			}
			defaultZoneName = getProperty(PROP_DEFAULT_ZONE,null);
			log(PROP_DEFAULT_ZONE+"= "+defaultZoneName);
			if( defaultZoneName == null || (defaultZoneName=defaultZoneName.trim()).isEmpty()) {
				throw new IOException("Manditory property, "+PROP_DEFAULT_ZONE+" is not defined");
			}

			ZoneSet old = zoneSet;
			Map<String, Long> oldSeen = lastSeenZoneFiles;
			Map<String, Zone> zones = new HashMap<String, Zone>();
			Map<String, Zone> byFile = new HashMap<String, Zone>();

			for(File file : list) {
				String fileName = file.getName();
				//  Read the timestamp before the file so an edit made while we
				//  read it triggers another reload.
				long modified = file.lastModified();

				Zone prev = old.byFile.get(fileName);
				Long prevModified = oldSeen == null ? null : oldSeen.get(fileName);
				Zone z = null;
				if( prev != null && prevModified != null && prevModified.longValue() == zoneStamp(modified, prev) ) {
					z = prev;
				} else {
					try {
						z = new Zone(file);
						log("Adding Zone "+z.getName());
					} catch (Throwable e) {
						if( prev != null ) {
							logError("Error loading zone from "+file+", still serving the previous version",e);
							z = prev;
						} else {
							logError("Error loading zone from "+file,e);
						}
					}
				}

				//  The stamp uses the $INCLUDE files of the version now in use
				seen.put(fileName, zoneStamp(modified, z != null ? z : prev));
				if( z != null ) {
					byFile.put(fileName, z);
					Zone dup = zones.put(z.getName().toLowerCase(),z);
					if( dup != null && dup != z ) {
						logError("Zone "+z.getName()+" is defined by more than one file, using "+file);
					}
				}
			}

			//  DNSSEC: sign the zones that have keys (a zone whose data, keys and
			//  dynamic entries did not change keeps its signatures)
			Map<String, Zone> unsignedByName = new HashMap<String, Zone>();
			for(Map.Entry<String, Zone> e : zones.entrySet()) {
				unsignedByName.put(e.getKey(), e.getValue().getUnsigned());
			}
			for(Map.Entry<String, Zone> e : new ArrayList<Map.Entry<String, Zone>>(byFile.entrySet())) {
				Zone loaded = e.getValue();
				Zone served = prepareZone(loaded, old.byFile.get(e.getKey()), false, unsignedByName);
				if( served != loaded ) {
					e.setValue(served);
					String k = loaded.getName().toLowerCase();
					if( zones.get(k) == loaded ) {
						zones.put(k, served);
					}
				}
			}

			Zone def = zones.get(defaultZoneName.toLowerCase());
			if( def == null ) {
				logError("Can't find default zone '"+defaultZoneName+"'! Must have at lease a default.  seraching in ("+zoneDir+")");
				throw new IOException("use '"+PROP_ZONE_DIR+"' or '"+PROP_DEFAULT_ZONE+"' to set correctly");			
			}

			//  Publish everything at once
			zoneSet = new ZoneSet(Collections.unmodifiableMap(zones), def, Collections.unmodifiableMap(byFile));

			//  NOTIFY secondaries about new zones and changed serials (RFC 1996)
			ZoneNotifier n = notifier;
			if( n != null ) {
				for(Zone z : zones.values()) {
					Zone before = old.zones.get(z.getName().toLowerCase());
					if( before == null || before.getSoa().getSerial() != z.getSoa().getSerial() ) {
						n.notifyZone(z);
					}
				}
			}
		} finally {
			//  Remember what we looked at, even on failure, so we only try again when something changes
			lastSeenZoneFiles = seen;
		}
	}

	public Zone getDefaultZone() {
		return zoneSet.defaultZone;
	}

	/**
	 * 
	 * Creation date: (8/26/2001 12:39:33 PM)
	 * @param args java.lang.String[]
	 */
	public static void main(String[] args) {
		//  Log dead threads; on a JVM error (e.g. OutOfMemoryError) stop the
		//  process so a supervisor restarts it (see FatalErrorHandler)
		FatalErrorHandler.install(!"false".equalsIgnoreCase(
				System.getProperty(FatalErrorHandler.PROP_EXIT_ON_FATAL_ERROR,"true").trim()));

		us.bringardner.net.dns.server.DnsServer svr = new DnsServer();
		svr.start(true);
		try {
			svr.awaitStarted(0);
		} catch (StartupException e) {
			//  Only the program's entry point decides to end the process
			//  (a non-zero code, so a supervisor can restart it).
			svr.logError("Exiting with "+e.getExitCode());
			System.exit(e.getExitCode());
		} catch (IOException | InterruptedException e) {
			svr.logError("Exiting with -1", e);
			System.exit(-1);
		}

		while(svr.isRunning()) {
			try {
				Thread.sleep(1000);
			} catch (Exception e) {
				svr.logError("Fatal server error",e);
			}
		}

		svr.log("Exiting DNsServer.main shutdown="+DnsServer.isShutdown());

	}

	public List<Message> query(QueryData req) {
		List<Message> ret = new ArrayList<Message>();		
		/* RFC 1034 Section 4.3.2. Algorithm
		1. Set or clear the value of recursion available in the response
			depending on whether the name server is willing to provide
			recursive service.  If recursive service is available and
			requested via the RD bit in the query, go to step 5,
			otherwise step 2.
		 */

		Message reqMsg = req.getMessage();
		Header hdr = reqMsg.getHeader().copy();	
		hdr.setRA(recursionAvailable);
		hdr.setAA(false);


		if( !reqMsg.isQuery() ) {
			//  A response (QR=1) is never answered (RFC 1035 4.1.1). It used to
			//  get a REFUSED reply, so a spoofed response sent to two servers
			//  could bounce between them.
			final int qr = reqMsg.getQuestionCount();
			log(() -> "Ignored a response (QR=1, "+qr+" questions) from "+req.getClient());
		} else if( reqMsg.getQuestionCount() != 1 ) {
			ret.add(questionCountError(req, hdr));
		} else if( hdr.getOPCODE() == DNS.UPDATE ) {
			ret.add(update(req, hdr));
		} else if( hdr.getOPCODE() != DNS.QUERY ) {
			//  NOTIFY, UPDATE, IQUERY, STATUS...: NOTIMP (RFC 1035 4.1.1,
			//  RFC 2136 2.2). They used to be answered as ordinary queries, so
			//  e.g. nsupdate was told NOERROR and assumed its update was made.
			Message  retMsg = new Message();
			retMsg.setHeader(hdr);
			retMsg.setMessageTypeResponse();
			for(Section s : reqMsg.getQuestion()) {
				retMsg.setQuestion(s);
			}
			retMsg.setResponseCodeNotImplemented();
			ret.add(retMsg);
		} else {
			List<Section> v = reqMsg.getQuestion();
			for(Section s : v) {
				/* RFC 1034 Section 4.3.2. Algorithm
					2. Search the available zones for the zone which is the nearest
						ancestor to QNAME.  If such a zone is found, go to step 3,
	 					otherwise step 4.
				 */
				Message  retMsg = new Message();
				retMsg.setHeader(hdr);
				retMsg.setResponseCodeNoError();
				retMsg.setMessageTypeResponse();
				retMsg.setQuestion(s);
				if( s.getType() == DNS.AXFR || s.getType() == DNS.IXFR ) {
					ret.addAll(zoneTransfer(req, s, retMsg));
					continue;
				}
				retMsg = step2(req,retMsg);
				if( retMsg != null && req.getCnameTarget() != null ) {
					retMsg = completeOutOfZoneCname(req, retMsg);
				}
				if( retMsg != null && req.getEdns().isDnssecOk() ) {
					//  DNSSEC records for the parts of the answer from signed zones
					DnssecResponder.apply(retMsg, s.getName(), s.getType(), n -> getZoneFor(new Name(n)));
				}
				ret.add(retMsg);
			}			
		}
		return ret;
	}


	//  Requests answered FORMERR because they did not have exactly one question
	private static final java.util.concurrent.atomic.AtomicLong questionCountErrors = new java.util.concurrent.atomic.AtomicLong();

	/** Requests answered FORMERR because QDCOUNT (ZOCOUNT for UPDATE) was not 1. */
	public static long getQuestionCountErrors() {
		return questionCountErrors.get();
	}

	/**
	 * FORMERR for a request that does not have exactly one question (RFC 9619;
	 * for UPDATE, one zone, RFC 2136 3.1.1). The response has no question
	 * section, so it is never bigger than a header (plus OPT / TSIG).
	 * <p>
	 * Every question used to get its own response, and each one answered the
	 * first question again: one 2 KB UDP packet with about 400 copies of a
	 * 5 byte question got about 400 responses (reflection amplification),
	 * or filled the resolver backlog in one go. A request without a question
	 * threw IndexOutOfBoundsException, logged with a stack trace each time.
	 */
	private Message questionCountError(QueryData req, Header hdr) {
		questionCountErrors.incrementAndGet();
		final int n = req.getMessage().getQuestionCount();
		log(() -> "FORMERR for a request with "+n+" questions from "+req.getClient());
		Message ret = new Message();
		ret.setHeader(hdr);
		ret.setMessageTypeResponse();
		ret.getHeader().setTC(false);
		ret.setResponseCodeFormatError();
		return ret;
	}

	/**
	 * Delete a domain from our domain list
	 **/
	public Object removeDomain(String domain) {
		return common.remove(domain.toLowerCase());
	}


	public void run() {
		
		//  A failure to start is reported to awaitStarted() (main() turns it into
		//  the process exit code). This used to call System.exit() here when
		//  started stand-alone, which also ended any program or test run that
		//  embedded the server.
		try {
			initServer();
		} catch (Throwable e1) {
			failedToStart(new StartupException("Can't init server: "+e1, e1, -1));
			return;
		}

		running = true;
		ServerSocket svrSock = null;
		setState("Running Enter");

		try {
			int port = getAdminPort();
			svrSock = createAdminSocket();
			svrSock.setSoTimeout((int)acceptTimeout);
			log("Started dnsAdmin on "+adminBindAddress+":"+port);
			setState("Running got socket");
		} catch(IOException ex) {
			failedToStart(new StartupException("Can't create admin socket on "+adminBindAddress+":"+getAdminPort()+": "+ex, ex, -2));
			return;
		}
		startLatch.countDown();
		try {
			serve(svrSock);
		} finally {
			IoUtils.closeQuietly(svrSock);
		}
	}

	/**
	 * Record why the server could not start, stop what initServer() had already
	 * started, and release awaitStarted().
	 */
	private void failedToStart(StartupException ex) {
		logError(ex.getMessage(), ex.getCause());
		setState("Failed to start");
		running = false;
		try {
			closeListeners();
			TCPProsessor.shutdownConnections(2000);
			for(Thread w : workers) {
				w.join(5000);
			}
			workers.clear();
			Resolver.shutDown();
			closeDbConnection();
		} catch(InterruptedException ie) {
			Thread.currentThread().interrupt();
		} catch(RuntimeException re) {
			logError("Error cleaning up after a failed start", re);
		} finally {
			startupFailure = ex;
			startLatch.countDown();
		}
	}

	/**
	 * Close the UDP and TCP listening sockets. Their threads end when the socket
	 * is closed, without setting the (JVM wide) shutdown flag.
	 */
	private static void closeListeners() {
		java.net.DatagramSocket udp = UDPProsessor.getSock();
		if( udp != null ) {
			udp.close();
		}
		ServerSocket tcp = TCPProsessor.getServerSocket();
		if( tcp != null ) {
			IoUtils.closeQuietly(tcp);
		}
	}

	/** The admin loop: serve admin connections and periodic reloads until stopped. */
	private void serve(ServerSocket svrSock) {



		//boolean outOfMemory = false;

		long dynUpdate = System.currentTimeMillis();

		while( running && !isShutdown()) {

			if( (System.currentTimeMillis()-dynUpdate) >= dynamicConfigRefreash) {
				try {
					loadDynamicFromDb();
					if( dynamicFile != null && dynamicFile.exists()) {
						dynamicLoaded = dynamicFile.lastModified();
					}
				} catch (Throwable e) {
					logError("Can't refreash dynamic dns",e);
				}
				dynUpdate = System.currentTimeMillis();
			} else if( dynamicFile != null && dynamicFile.lastModified()>dynamicLoaded) {
				try {
					dynamicFile =  loadDynamicFromFile(true);
				} catch (IOException e) {
				}
				if( dynamicFile != null && dynamicFile.exists()) {
					dynamicLoaded = dynamicFile.lastModified();
				}				
			}
			if( shouldReloadZones()) {
				try {
					loadZones();
				} catch (IOException e) {
					logError("Error reloading zones", e);
				}
			}
			try {
				flushDynamicSigning();
				resignDue(System.currentTimeMillis()/1000);
			} catch(RuntimeException e) {
				logError("Error signing zones", e);
			}

			try {
				setState("Waiting for admin connection");
				Socket clientSocket = svrSock.accept();
				if( clientSocket != null ) {
					handleAdminConnection(clientSocket);
					setState("Processing conneciton");
				}

			} catch(Exception ex) {
				//Ignore exceptions
			}

		}
		System.out.println("JDNS Server After loop");
		running = false;
		setState("Running Exit");


	}
	/**
	 * 
	 * Creation date: (6/16/2003 9:29:24 AM)
	 * @param newAdminPort int
	 */
	public static void setAdminPort(int newAdminPort) {
		adminPort = newAdminPort;
	}
	/**
	 * 
	 * Creation date: (6/27/2003 6:40:02 AM)
	 * @param newDebug boolean
	 */
	public static void setDebug(boolean newDebug) {
		_debug = newDebug;
	}
	/**
	 * 
	 * Creation date: (6/27/2003 6:47:28 AM)
	 * @param newRa boolean
	 */
	public void setRecursionAvailable(boolean newRa) {
		recursionAvailable = newRa;
	}
	/**
	 * 
	 * Creation date: (6/16/2003 9:29:24 AM)
	 * @param newServerSocketFactory javax.net.ServerSocketFactory
	 */
	/**
	 * The admin listener's factory: JDns.adminTls=true replaces the default
	 * (plain) factory with SSLServerSocketFactory.getDefault(); a factory set
	 * with setServerSocketFactory is kept.
	 */
	static ServerSocketFactory adminSocketFactory(String tlsProperty, ServerSocketFactory current) {
		if( tlsProperty != null && tlsProperty.trim().toLowerCase().startsWith("t")
				&& current == ServerSocketFactory.getDefault() ) {
			return javax.net.ssl.SSLServerSocketFactory.getDefault();
		}
		return current;
	}

	public static void setServerSocketFactory(javax.net.ServerSocketFactory newServerSocketFactory) {
		serverSocketFactory = newServerSocketFactory;
	}
	/**
	 * 
	 * Creation date: (6/16/2003 10:38:48 AM)
	 * @param newShutdown boolean
	 */
	public static void setShutdown(boolean newShutdown) {
		shutdown = newShutdown;
	}

	public void start() {
		start(false);
	}

	/**
	 * Start the server in its own thread. Use {@link #awaitStarted(long)} to wait
	 * until it is serving (or to learn why it could not start).
	 * 
	 * @param standAlone kept for compatibility; a failed start no longer exits the JVM
	 *   (main() does that, using awaitStarted()).
	 */
	public void start(boolean standAlone) {
		if( !running ) {
			this.standAlone = standAlone;
			startupFailure = null;
			startLatch = new java.util.concurrent.CountDownLatch(1);
			thread = new Thread(this);
			thread.setName("DNS-Server");
			thread.setDaemon(true);
			thread.start();

			setState("Started");

		}
	}

	/* RFC 1034 Section 4.3.2. Algorithm
	2. Search the available zones for the zone which is the nearest
		ancestor to QNAME.  If such a zone is found, go to step 3,
		otherwise step 4.
	 */


	private Message step2(QueryData query, Message ret) {

		Section question = query.getQuestion();
		//Section original=null;

		Zone zone = getZone(question);
		if( zone != null && question.getType() == DNS.DS && zone.isApex(question.getName()) ) {
			//  The DS of a zone we serve is in its parent (RFC 4035 3.1.4.1):
			//  answer from the parent zone if we serve that too
			Name parent = question.getNameAsName().getParentName();
			Zone p = parent == null ? null : getZoneFor(parent);
			if( p != null ) {
				zone = p;
			}
		}
		if( zone == null ) {
			if( isCommon(question) ) {
				zone = getDefaultZone();
			}
		}

		if( zone != null ) {
			ret.setAuthorityAnswerOn();
			ret = step3(query,ret,zone);

		} else {
			if( !recursionAvailable ) {
				//  Not our name and we don't recurse: REFUSED (RFC 8906 3.1.5).
				//  It used to be NXDOMAIN, claiming that names we are not
				//  authoritative for (e.g. google.com) don't exist.
				ret.setResponseCodeRefused();
			} else {
				ret = step4And5(query , ret);
			}
		}

		ret = step6(query,ret);

		return ret;
	}

	@SuppressWarnings("unused")
	private Section convertToDefault(Section question1) {
		Section ret = new Section(question1);

		// Change this to the default domain
		String parts1 [] = defaultZoneName.split("[.]");
		String parts2 [] = question1.getName().split("[.]");
		for(int idx1=parts1.length-1, idx2=parts2.length-1; idx1 >= 0 && idx2>=0; idx1--,idx2--) {
			parts2[idx2] = parts1[idx1];
		}
		StringBuilder tmp = new StringBuilder();
		for(int idx=0; idx < parts2.length; idx++) {
			if( idx > 0) {
				tmp.append('.');
			}
			tmp.append(parts2[idx]);
		}
		ret.setName(tmp.toString());

		return ret;
	}

	/**
	 * @return true if name is the apex of the zone we answer from: the zone's
	 * own name, or a 'common' domain served from the default zone.
	 */
	private boolean isZoneApex(String name, Zone zone) {
		String n = name.toLowerCase();
		return n.equals(zone.getName().toLowerCase()) || common.containsKey(n);
	}

	/* RFC 1034
   3. Start matching down, label by label, in the zone.The
      matching process can terminate several ways:

         a. If the whole of QNAME is matched, we have found the
            node.

            If the data at the node is a CNAME, and QTYPE doesn't
            match CNAME, copy the CNAME RR into the answer section
            of the response, change QNAME to the canonical name in
            the CNAME RR, and go back to step 1.

            Otherwise, copy all RRs which match QTYPE into the
            answer section and go to step 6.

         b. If a match would take us out of the authoritative data,
            we have a referral.  This happens when we encounter a
            node with NS RRs marking cuts along the bottom of a
            zone.

            Copy the NS RRs for the subzone into the authority
            section of the reply.  Put whatever addresses are
            available into the additional section, using glue RRs
            if the addresses are not available from authoritative
            data or the cache.  Go to step 4.

         c. If at some label, a match is impossible (i.e., the
            corresponding label does not exist), look to see if a
            the "*" label exists.

            If the "*" label does not exist, check whether the name
            we are looking for is the original QNAME in the query

            or a name we have followed due to a CNAME.  If the name
            is original, set an authoritative name error in the
            response and exit.  Otherwise just exit.

            If the "*" label does exist, match RRs at that node
            against QTYPE.  If any match, copy them into the answer
            section, but set the owner of the RR to be QNAME, and
            not the node with the "*" label.  Go to step 6.

	 */
	/**
	 * The zone's SOA as the answer for 'targetName': for a domain served by
	 * the default (common) zone it gets that domain's name.
	 */
	private static Soa soaFor(Zone zone, Name targetName) {
		Soa soa = zone.getSoa();
		RR realrr = soa.copy();
		realrr.replaceWildCards(targetName);
		String domain = soa.getName();
		String target = targetName.toString();

		// Set the SOA info to the hosted name
		if( !domain.equals(target)){
			//  must be common
			((Soa)realrr).setName(target);
			((Soa)realrr).setRname("postmaster."+target);
		}
		return (Soa)realrr;
	}

	private Message step3(QueryData query, Message ret, Zone zone)
	{

		boolean doNs = true;
		Section question = query.getQuestion();
		Name targetName = question.getNameAsName();
		String target = question.getName().toLowerCase();
		//System.out.println("Step3 "+target+" zone="+zone.getName());

		RR rr = null;
		int type = question.getType();
		int myType = 0;

		//  RFC 1034 4.3.2 step 3b: at or below a zone cut (NS records at a name
		//  below the apex) our data is not authoritative; answer with a
		//  referral. It used to answer NXDOMAIN for names below the cut, and
		//  an authoritative empty answer (A queries) at the cut itself.
		//  A dynamic entry for the name still wins.
		if( zoneCutReferrals && !dynamic.containsKey(target) ) {
			List<RR> cut = zone.findDelegation(target);
			if( cut != null && type == DNS.DS && cut.get(0).getName().equalsIgnoreCase(stripDot(target)) ) {
				//  DS records live in the parent, at the delegation (RFC 4035
				//  3.1.4.1): answer from here, not with a referral
				ret.setResponseCodeNoError();
				for(RR d : zone.exactRecords(target)) {
					if( d.getType() == DNS.DS ) {
						ret.addAnswer(d.copy());
					}
				}
				if( ret.getAnswerCount() == 0 ) {
					ret.addAuthority(zone.getNegativeSoa());
				}
				return ret;
			}
			if( cut != null ) {
				return referral(ret, zone, cut);
			}
		}

		//  In a signed zone only the apex has an SOA: other names get NODATA
		//  (validators reject the renamed SOA the default zone makes up)
		boolean signedName = zone.getSigned() != null && zone.contains(target);
		//  Only a zone apex (or a domain served by the default zone) has an SOA:
		//  other names get NODATA / NXDOMAIN with the SOA in the authority
		//  section. (Every name used to get an SOA named after itself, so a
		//  client looking for the zone of www.example.com, as nsupdate does,
		//  took www.example.com for a zone.)
		if( type == DNS.SOA && isZoneApex(target, zone) && !(signedName && !zone.isApex(target)) ) {
			Soa soa = zone.getSoa();
			ret.addAnswer(soaFor(zone, targetName));
			//  (MNAME and RNAME used to be swapped in Soa; see Soa.toByteArray)
			String dnsServer = soa.getMname();
			RR realrr = zone.getMatchingRR(dnsServer,DNS.A);
			if( realrr != null ) {
				ret.addAdditional(realrr);
			}

			return ret;
		}

		//  Check for a dynamic entry.

		List<A> list1 = dynamic.get(target);
		//System.out.println(target+" list="+list1);
		List<RR> list = null;
		if( list1 != null ) {
			list = new ArrayList<RR>(list1);			
		}

		if( list == null ) {
			//  No dynamic entry then do a normal search.
			list = zone.getMatchingRRs(targetName);
		}
		//  ANY at the apex includes the SOA (the zone keeps it apart from the
		//  other records, so it was left out); the apex exists even when the
		//  SOA is its only record
		boolean apexAny = type == DNS.QTYPE_ALL && isZoneApex(target, zone) && !dynamic.containsKey(target);
		if( apexAny ) {
			ret.addAnswer(soaFor(zone, targetName));
			if( list == null ) {
				list = new ArrayList<RR>();
			}
		}
		//System.out.println(target+" list 2="+list1);
		if( list == null ) {
			//  We are authoritative for this zone and the name has no records.
			//  NXDOMAIN (RFC 1034 4.3.2 step 3c), unless it is an empty
			//  non-terminal (has names below it), which exists: NODATA.
			//  Either way the SOA goes in the authority section (RFC 2308 3).
			//  After a CNAME this also sets the final RCODE (RFC 6604).
			if( signedName ? zone.getSigned().isEmptyNonTerminal(target) : zone.hasNamesBelow(target) ) {
				//  (in a signed zone a name with only a wildcard below it exists too, RFC 4592 2.2.2)
				ret.setResponseCodeNoError();
			} else {
				ret.setResponseCodeNameError();
			}
			ret.addAuthority(zone.getNegativeSoa());
		} else {

			//  Since we found the name it's not a name error even if we may not have the type
			ret.setResponseCodeNoError();
			//  A wildcard match in a signed zone (RFC 4592): the records get the
			//  query name as owner, however many labels the '*' stands for; the
			//  wildcard's NSEC is not part of the answer
			boolean fromWildcard = signedName && !list.isEmpty() && list.get(0).getNameAsName().hasWildCard()
					&& !targetName.hasWildCard();

			for(int i=0,sz=list.size(); i< sz; i++ ) {
				rr = (RR)list.get(i);
				if( fromWildcard && rr.getType() == DNS.NSEC ) {
					continue;
				}
				if( (myType=rr.getType()) == type || myType == DNS.CNAME || type == DNS.QTYPE_ALL)  {
					//  Just in case the match is a wild card
					RR realrr = rr.copy();
					realrr.replaceWildCards(targetName);
					if( fromWildcard ) {
						realrr.setName(targetName.toString());
					}
					ret.addAnswer(realrr);

					switch (myType ) {
					case DNS.MX:
						//  Need to add more stuff
						Mx mx = (Mx)realrr;
						RR aa = zone.getMatchingRR(mx.getExchange(),DNS.A);
						if( aa != null ) {
							ret.addAdditional(aa);
						}
						break;

					case DNS.CNAME:
						if( type != DNS.CNAME) {
							//  Follow the CNAME (RFC 1034 4.3.2 step 3a), but never
							//  in a loop (a -> b -> a) or past MAX_CNAME_CHAIN,
							//  which used to recurse until StackOverflowError.
							String cname = ((Cname)realrr).getCname();
							if( query.followCname(cname) ) {
								Section next = new Section(cname,type,question.getDnsClass());
								if( isLocalName(next) ) {
									//  Chase it in our own zones; the request's question
									//  is restored afterwards (it used to stay changed).
									query.setQuestion(next);
									try {
										step2(query,ret);
									} finally {
										query.setQuestion(question);
									}
								} else {
									//  The chain leaves our zones: stop here. query()
									//  completes it through the resolver when recursion is
									//  available and desired, as ONE response. (It used to
									//  send the CNAME alone and then a second response for
									//  the target's question with the same ID.)
									query.setCnameTarget(next);
								}
							} else {
								logError("CNAME loop or chain too long at "+target+" -> "+cname
										+" (followed "+query.getCnameCount()+"), answering with the chain so far");
							}
						}
						break;
					case DNS.NS:

						Ns ns = (Ns)realrr;
						aa = zone.getMatchingRR(ns.getNs(),DNS.A);
						if( aa != null ) {
							ret.addAdditional(aa);
						}

						break;
					default :
						//  Nothing to do here
					}
				}  else if( myType == DNS.NS && type != DNS.A) {
					RR realrr = rr.copy();
					realrr.replaceWildCards(targetName);
					ret.addAuthority(realrr);
					Ns ns = (Ns)realrr;
					RR aa = zone.getMatchingRR(ns.getNs(),DNS.A);
					if( aa != null ) {
						realrr = aa.copy();
						realrr.replaceWildCards(targetName);
						ret.addAdditional(realrr);
					}
				}
			}
		}



		//  NODATA at the zone apex: the loop above put the zone's own NS records
		//  in the authority section, which other resolvers read as a referral
		//  (to the same servers). RFC 2308 2.2: answer with the SOA instead.
		//  (NS records at any other name are a delegation and are kept.)
		if( ret.getAnswerCount() == 0 && ret.isResponseCodeNoError() && list != null
				&& isZoneApex(target, zone) ) {
			ret.getAuthority().clear();
			ret.getAdditional().clear();
		}

		if( doNs && ret.getNSCount() == 0 ) {
			if( ret.isResponseCodeNameError() ) {
				ret.addAuthority(zone.getNegativeSoa());
			} else {
				//  No ns records.  Add the domain info
				zone.setLocalInfo(ret);
			}
		}
		return ret;
	}

	/**
	 * A referral: the delegation's NS records in the authority section and
	 * the addresses we have for them (glue) in the additional section, not
	 * authoritative, NOERROR (RFC 1034 4.3.2 step 3b, RFC 1035 6.2.6).
	 * After a CNAME from our own data the answer section is kept (and so is
	 * AA, which covers the CNAME).
	 */
	private Message referral(Message ret, Zone zone, List<RR> cut) {
		if( ret.getAnswerCount() == 0 ) {
			ret.getHeader().setAA(false);
		}
		ret.setResponseCodeNoError();
		for(RR rr : cut) {
			ret.addAuthority(rr.copy());
		}
		for(RR rr : cut) {
			String host = ((Ns)rr).getNs();
			for(int t : new int[] {DNS.A, DNS.AAAA}) {
				RR glue = zone.getMatchingRR(host, t);
				if( glue != null ) {
					RR g = glue.copy();
					g.replaceWildCards(new Name(host));
					ret.addAdditional(g);
				}
			}
		}
		return ret;
	}

	/*

   4. Start matching down in the cache.  If QNAME is found in the
      cache, copy all RRs attached to it that match QTYPE into the
      answer section.  If there was no delegation from
      authoritative data, look for the best one from the cache, and
      put it in the authority section.  Go to step 6.

     5. Using the local resolver or a copy of its algorithm (see
      resolver section of this memo) to answer the query.  Store
      the results, including any intermediate CNAMEs, in the answer
      section of the response.


	 */
	private Message step4And5(QueryData question, Message msg)
	{
		//  Only if we support recurtion
		Message ret = msg;


		if( recursionAvailable && question.getMessage().isRecursiveDesired() ) {
			//  The resolver has the cache.  So it takes care of 4 & 5
			question.getMessage().setAuthorityAnswerOff();
			if( question.getPort() == -1 ) {
				//  TCP: resolve in this (TCP processor) thread. TCP used to get an
				//  empty NOERROR answer, which since UDP truncation (rec #12) is
				//  what a client got after retrying a large recursive answer.
				ret = resolveNow(question);
			} else if( (ret = cachedAnswer(question)) != null ) {
				//  Answered from the cache in this thread
			} else if( us.bringardner.net.dns.resolve.ResolverThread.addQuery(question) ) {
				//  A resolver thread will answer
				ret = null;
			} else {
				//  Backlog full: say so now instead of dropping the query
				logBacklogFull();
				ret = us.bringardner.net.dns.resolve.ResolverThread.failure(question, DNS.SERVER_ERROR);
			}
		} else {
			//  Recursion available but not desired, and not our name:
			//  REFUSED (it used to be an empty NOERROR answer).
			ret.setResponseCodeRefused();
		}
		if( ret != null ) {
			ret.setID(msg.getID());
		}

		return ret;

	}

	/**
	 * A recursive answer from the cache (no network, already validated when
	 * validation is on), shaped for the client; null if a resolver thread is
	 * needed.
	 */
	private Message cachedAnswer(QueryData question) {
		us.bringardner.net.dns.resolve.Resolver.Answer a;
		try {
			a = us.bringardner.net.dns.resolve.ResolverThread.cachedFor(question, question.getQuestion());
		} catch(RuntimeException ex) {
			logError("Cache lookup failed for "+question.getQuestion(), ex);
			return null;
		}
		if( a == null || a.msg == null ) {
			return null;
		}
		us.bringardner.net.dns.resolve.ResolverThread.finish(a.msg, question, a.result, false);
		return a.msg;
	}

	/** @return true if the name is in one of our zones (or a 'common' domain) */
	private boolean isLocalName(Section s) {
		return getZone(s) != null || isCommon(s);
	}

	/**
	 * Our zone answered with a CNAME chain that ends outside our zones
	 * (req.getCnameTarget()).
	 * <ul>
	 * <li>No recursion (not available or not desired): the chain is the
	 *     authoritative answer, NOERROR; the client follows the rest.</li>
	 * <li>TCP: resolve the target now and answer chain + target.</li>
	 * <li>UDP: a resolver thread resolves the target and sends chain + target
	 *     (returns null: nothing to send now). If its backlog is full the
	 *     chain is sent as it is.</li>
	 * </ul>
	 */
	private Message completeOutOfZoneCname(QueryData req, Message partial) {
		if( !recursionAvailable || !req.getMessage().isRecursiveDesired() ) {
			req.setCnameTarget(null);
			return partial;
		}
		if( req.getPort() == -1 ) {
			us.bringardner.net.dns.resolve.Resolver.Answer a = resolveOrNull(req, req.getCnameTarget());
			req.setCnameTarget(null);
			Message ret = us.bringardner.net.dns.resolve.ResolverThread.completeCnameAnswer(partial, a == null ? null : a.msg);
			us.bringardner.net.dns.resolve.ResolverThread.finish(ret, req, a == null ? null : a.result, true);
			return ret;
		}
		req.setPartialAnswer(partial);
		if( us.bringardner.net.dns.resolve.ResolverThread.addQuery(req) ) {
			return null;
		}
		//  The chain alone is a valid answer: the client's resolver restarts
		//  the lookup at the target (RFC 1034 4.3.2 step 3a)
		logBacklogFull();
		req.setPartialAnswer(null);
		req.setCnameTarget(null);
		return partial;
	}

	private void logBacklogFull() {
		String msg = us.bringardner.net.dns.resolve.ResolverThread.backlogFullWarning();
		if( msg != null ) {
			logError(msg);
		}
	}

	/** Resolve (and validate) in the calling thread; null if it fails. */
	private us.bringardner.net.dns.resolve.Resolver.Answer resolveOrNull(QueryData req, Section s) {
		try {
			return us.bringardner.net.dns.resolve.ResolverThread.resolveFor(req, s);
		} catch(RuntimeException | StackOverflowError ex) {
			logError("Resolver failed for "+s, ex);
			return null;
		}
	}

	/**
	 * Resolve a recursive query in the calling thread (used for TCP).
	 * @return the answer, or SERVFAIL if it could not be resolved
	 */
	private Message resolveNow(QueryData question) {
		Message ret = null;
		us.bringardner.net.dns.resolve.Resolver.Answer a = resolveOrNull(question, question.getQuestion());
		if( a != null ) {
			ret = a.msg;
		}
		if( ret == null ) {
			ret = us.bringardner.net.dns.resolve.ResolverThread.failure(question, DNS.SERVER_ERROR);
		}
		us.bringardner.net.dns.resolve.ResolverThread.finish(ret, question, a == null ? null : a.result, false);
		return ret;
	}

	/*
  6. Using local data only, attempt to add other RRs which may be
      useful to the additional section of the query.  Exit.
	 */

	/**
	 * A zone transfer (AXFR, RFC 5936; IXFR is answered with the whole zone,
	 * as RFC 1995 4 allows). Only for clients in JDns.axfrAllow or requests
	 * signed with a TSIG key in JDns.axfrKeys, only over TCP,
	 * and only for the name of a zone we serve; otherwise REFUSED.
	 * <p>
	 * The answer is the SOA, every record of the zone (dynamic entries
	 * replace the zone's records at their name, as in normal answers), and the
	 * SOA again, split over as many messages as needed.
	 * An IXFR over UDP gets only the SOA, which tells the client to use TCP
	 * (or that it is up to date).
	 * 
	 * @param empty a NOERROR response with the question, used for the first message
	 */
	List<Message> zoneTransfer(QueryData req, Section question, Message empty) {
		List<Message> ret = new ArrayList<Message>();
		Zone zone = getZone(question.getName());
		boolean tcp = req.getPort() < 0;
		//  By address (JDns.axfrAllow) or by TSIG key (JDns.axfrKeys, from anywhere)
		String key = req.getTsigKey();
		boolean allowed = axfrAllow.matches(req.getClient()) || (key != null && axfrKeys.contains(key));
		if( zone == null || !allowed || (!tcp && question.getType() == DNS.AXFR) ) {
			final String why = zone == null ? "not our zone" : !allowed ? "client not in "+PROP_AXFR_ALLOW+" and not signed with a key in "+PROP_AXFR_KEYS : "AXFR over UDP";
			log(() -> "Zone transfer of "+question.getName()+" for "+req.getClient()+" refused: "+why);
			empty.setResponseCodeRefused();
			ret.add(empty);
			return ret;
		}
		empty.setAuthorityAnswerOn();
		Soa soa = zone.getSoa();
		if( !tcp ) {
			//  IXFR over UDP
			empty.addAnswer(soa.copy());
			ret.add(empty);
			return ret;
		}

		List<RR> records = new ArrayList<RR>();
		records.add(soa.copy());
		java.util.Set<String> dynNames = new java.util.HashSet<String>();
		for(Map.Entry<String, List<A>> e : dynamic.entrySet()) {
			if( getZoneFor(new Name(e.getKey())) == zone ) {
				dynNames.add(e.getKey());
				records.addAll(e.getValue());
			}
		}
		List<Name> names = zone.getNames();
		List<List<RR>> rrs = zone.getRrs();
		for(int i=0; i < names.size() && i < rrs.size(); i++ ) {
			boolean dyn = dynNames.contains(names.get(i).toString().toLowerCase());
			for(RR rr : rrs.get(i)) {
				//  (a dynamic entry replaces the records at its name, but not the NSEC of a signed zone)
				if( rr.getType() != DNS.SOA && (!dyn || rr.getType() == DNS.NSEC) ) {
					records.add(rr);
				}
			}
		}
		SignedZone sz = zone.getSigned();
		if( sz != null ) {
			for(List<us.bringardner.net.dns.Rrsig> sigs : sz.allSigs().values()) {
				records.addAll(sigs);
			}
			records.addAll(sz.allNsec3());
			//  In canonical name order, each name's records together (as other
			//  servers send a signed zone; some tools expect it)
			RR first = records.get(0);
			List<RR> rest = new ArrayList<RR>(records.subList(1, records.size()));
			Map<RR, String> keys = new java.util.IdentityHashMap<RR, String>();
			for(RR rr : rest) {
				keys.put(rr, Canonical.sortKey(rr.getName()));
			}
			rest.sort((x, y) -> keys.get(x).compareTo(keys.get(y)));
			records.clear();
			records.add(first);
			records.addAll(rest);
		}
		records.add(soa.copy());

		Message cur = empty;
		int size = Header.LEN + question.size();
		for(RR rr : records) {
			int rrSize = estimateSize(rr);
			if( size + rrSize > AXFR_MESSAGE_SIZE && cur.getAnswerCount() > 0 ) {
				ret.add(cur);
				cur = new Message();
				cur.setHeader(empty.getHeader().copy());
				cur.setMessageTypeResponse();
				cur.setAuthorityAnswerOn();
				cur.setResponseCodeNoError();
				size = Header.LEN;
			}
			cur.addAnswer(rr);
			size += rrSize;
		}
		ret.add(cur);
		final int n = records.size();
		final int m = ret.size();
		log(() -> "Zone transfer of "+zone.getName()+" (serial "+Integer.toUnsignedString(soa.getSerial())+") to "+req.getClient()+": "+n+" records in "+m+" messages");
		return ret;
	}

	/** Upper bound of a record's size on the wire (without name compression). */
	private static int estimateSize(RR rr) {
		Message m = new Message();
		m.addAnswer(rr);
		return m.toByteArray().length - Header.LEN;
	}

	/**
	 * A dynamic update (RFC 2136). Allowed for requests signed with a key in
	 * JDns.updateKeys, or from an address in JDns.updateAllow; REFUSED
	 * otherwise. The changes are appended to the zone's journal (the zone
	 * file is never rewritten) before the new zone is published; the serial
	 * goes up and the secondaries get a NOTIFY.
	 */
	Message update(QueryData req, Header hdr) {
		Message reqMsg = req.getMessage();
		Message ret = new Message();
		ret.setHeader(hdr);
		ret.setMessageTypeResponse();
		Section zs = ZoneUpdater.zoneSection(reqMsg);
		for(Section s : reqMsg.getQuestion()) {
			ret.setQuestion(s);
		}
		if( zs == null ) {
			ret.setResponseCodeFormatError();
			return ret;
		}
		String key = req.getTsigKey();
		boolean allowed = (key != null && updateKeys.contains(key)) || updateAllow.matches(req.getClient());
		if( !allowed ) {
			log(() -> "UPDATE of "+zs.getName()+" from "+req.getClient()+" refused: not signed with a key in "+PROP_UPDATE_KEYS+" and not in "+PROP_UPDATE_ALLOW);
			ret.setResponseCodeRefused();
			return ret;
		}
		synchronized(this) {
			String zn = zs.getName();
			Zone zone = getZone(zn.endsWith(".") ? zn.substring(0, zn.length()-1) : zn);
			if( zone == null || zs.getDnsClass() != zone.getSoa().getDnsClass() ) {
				ret.getHeader().setRCODE(ZoneUpdater.NOTAUTH);
				return ret;
			}
			if( zone.getSigned() != null && zone.getSigned().isPresigned() ) {
				//  We have no keys to sign the change with
				log(() -> "UPDATE of "+zs.getName()+" refused: the zone is signed elsewhere");
				ret.setResponseCodeRefused();
				return ret;
			}
			ZoneUpdater.Result r;
			try {
				//  (a signed zone is updated without its DNSSEC records, then signed again)
				r = ZoneUpdater.apply(zone.getUnsigned(), reqMsg);
			} catch(RuntimeException ex) {
				//  e.g. a record the zone file reader can't take: nothing was changed
				logError("UPDATE of "+zone.getName()+" failed", ex);
				ret.setResponseCodeServerFailure();
				return ret;
			}
			if( r.changed() ) {
				try {
					writeJournal(zone, r.journal, req);
				} catch(IOException ex) {
					logError("Can't write the journal of "+zone.getName()+"; the update was not made", ex);
					ret.setResponseCodeServerFailure();
					return ret;
				}
				Zone served = prepareZone(r.zone, zone, true, zoneSet.zones);
				publishUpdatedZone(zone, served);
				final int n = r.journal.size();
				log(() -> "UPDATE of "+zone.getName()+" from "+req.getClient()+(key == null ? "" : " key "+key)
						+": "+n+" journal entries, serial "+Integer.toUnsignedString(r.zone.getSoa().getSerial()));
				ZoneNotifier nf = notifier;
				if( nf != null ) {
					nf.notifyZone(served);
				}
			}
			ret.getHeader().setRCODE(r.rcode);
		}
		return ret;
	}

	/** Append the changes to the zone's journal (created with the zone file's serial as its base). */
	private void writeJournal(Zone zone, List<String> lines, QueryData req) throws IOException {
		writeJournal(zone, lines, "from "+req.getClient()+(req.getTsigKey() != null ? " key "+req.getTsigKey() : ""));
	}

	/** Append lines to the zone's journal; why is written as a comment. */
	private void writeJournal(Zone zone, List<String> lines, String why) throws IOException {
		File jnl = zone.getJournalFile();
		if( jnl == null ) {
			//  A zone that was not loaded from a file (only kept in memory)
			return;
		}
		boolean create = !jnl.exists();
		try(FileOutputStream out = new FileOutputStream(jnl, true)) {
			StringBuilder b = new StringBuilder();
			if( create ) {
				b.append("; Dynamic updates of ").append(zone.getName()).append(" (RFC 2136), applied on top of ")
					.append(zone.getMasterFile().getName()).append(".\n; Edit the zone file and raise its serial to start over.\n");
				b.append("base ").append(Integer.toUnsignedString(zone.getSoa().getSerial())).append('\n');
			}
			b.append("; ").append(new Date()).append(' ').append(why).append('\n');
			for(String l : lines) {
				b.append(l).append('\n');
			}
			out.write(b.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
			out.getFD().sync();
		}
	}

	/** Replace a zone with its updated version, in one step. */
	private void publishUpdatedZone(Zone old, Zone updated) {
		ZoneSet cur = zoneSet;
		Map<String, Zone> zones = new HashMap<String, Zone>(cur.zones);
		zones.put(updated.getName().toLowerCase(), updated);
		Map<String, Zone> byFile = new HashMap<String, Zone>(cur.byFile);
		for(Map.Entry<String, Zone> e : cur.byFile.entrySet()) {
			if( e.getValue() == old ) {
				byFile.put(e.getKey(), updated);
			}
		}
		Zone def = cur.defaultZone == old ? updated : cur.defaultZone;
		zoneSet = new ZoneSet(Collections.unmodifiableMap(zones), def, Collections.unmodifiableMap(byFile));
	}

	/** Most SVCB/HTTPS AliasMode records followed for the additional section. */
	static final int MAX_SVCB_ALIAS_CHAIN = 8;

	/**
	 * Additional section processing for SVCB and HTTPS answers (RFC 9460 4.2):
	 * for each one in the answer, add the addresses (A and AAAA) of its
	 * target, when we are authoritative for the target, so the client does
	 * not need another query. For AliasMode records the target's own SVCB /
	 * HTTPS records are added too, and their targets' addresses, following at
	 * most MAX_SVCB_ALIAS_CHAIN aliases. Nothing is added twice, and nothing
	 * that is already in the answer.
	 */
	private Message step6(QueryData question, Message ret) {
		if( ret == null || !ret.isAuthority() || ret.getAnswerCount() == 0 ) {
			return ret;
		}
		java.util.Set<String> have = new java.util.HashSet<String>();
		for(RR rr : ret.getAnswer()) {
			have.add(rrKey(rr));
		}
		for(RR rr : ret.getAdditional()) {
			have.add(rrKey(rr));
		}
		java.util.Set<String> visited = new java.util.HashSet<String>();
		List<RR> answers = new ArrayList<RR>(ret.getAnswer());
		for(RR rr : answers) {
			if( rr instanceof Svcb ) {
				addSvcbAdditional(ret, (Svcb)rr, have, visited, 0);
			}
		}
		return ret;
	}

	private void addSvcbAdditional(Message ret, Svcb svcb, java.util.Set<String> have, java.util.Set<String> visited, int depth) {
		String target = svcb.getTarget();
		if( target.isEmpty() ) {
			if( svcb.isAliasMode() ) {
				//  AliasMode with "." : the service is not available (RFC 9460 2.5.1)
				return;
			}
			//  ServiceMode with "." : the owner name
			target = svcb.getName();
		}
		String key = target.toLowerCase()+"/"+svcb.getType();
		if( !visited.add(key) ) {
			return;
		}
		Name targetName = new Name(target);
		Zone zone = getZoneFor(targetName);
		if( zone == null ) {
			return;
		}
		if( svcb.isAliasMode() && depth < MAX_SVCB_ALIAS_CHAIN ) {
			for(RR rr : localRRs(zone, targetName, svcb.getType())) {
				if( addOnce(ret, rr, have) ) {
					addSvcbAdditional(ret, (Svcb)rr, have, visited, depth+1);
				}
			}
		}
		List<RR> addresses = new ArrayList<RR>();
		List<A> dyn = dynamic.get(dynamicKey(target));
		if( dyn != null ) {
			addresses.addAll(dyn);
		} else {
			addresses.addAll(localRRs(zone, targetName, DNS.A));
		}
		addresses.addAll(localRRs(zone, targetName, DNS.AAAA));
		for(RR rr : addresses) {
			addOnce(ret, rr, have);
		}
	}

	/** Copies of the records of a type at a name in a zone (wildcards expanded). */
	private static List<RR> localRRs(Zone zone, Name name, int type) {
		List<RR> ret = new ArrayList<RR>();
		List<RR> list = zone.getMatchingRRs(name);
		if( list != null ) {
			for(RR rr : list) {
				if( rr.getType() == type ) {
					RR copy = rr.copy();
					copy.replaceWildCards(name);
					ret.add(copy);
				}
			}
		}
		return ret;
	}

	private static boolean addOnce(Message ret, RR rr, java.util.Set<String> have) {
		if( have.add(rrKey(rr)) ) {
			ret.addAdditional(rr);
			return true;
		}
		return false;
	}

	/** Name, type and rdata of a record, to recognise one that is already in the message. */
	private static String rrKey(RR rr) {
		String data;
		try {
			data = rr.getRdataAsString();
		} catch(RuntimeException ex) {
			byte [] r = rr.getRdata();
			data = r == null ? "" : java.util.Arrays.toString(r);
		}
		return new Name(rr.getName()).toString().toLowerCase()+"/"+rr.getType()+"/"+data;
	}

	/** @return a snapshot copy of the dynamic entries (lower case name -> [A]) */
	public Map<String, List<A>> getDynamic() {
		return new HashMap<String, List<A>>(dynamic);
	}

	/** Dynamic names are case-insensitive (the query path looks them up in lower case). */
	private static String dynamicKey(String name) {
		return name.toLowerCase();
	}

	public List<A> getDynamic(String name) {
		return dynamic.get(dynamicKey(name));
	}

	/** Publish a fully built A as the dynamic entry for its name. */
	private void putDynamic(A a) {
		dynamic.put(dynamicKey(a.getName()), Collections.singletonList(a));
		dynamicDirty = true;
	}

	/**
	 * Change a dynamic address by publishing a new A (the old object may be
	 * in use by a query thread and is never modified).
	 */
	private A replaceDynamicAddress(A old, String ip) {
		A a = copyWithAddress(old, ip);
		putDynamic(a);
		return a;
	}

	/** A new A like old but with another address (old is not modified). */
	private static A copyWithAddress(A old, String ip) {
		A a = new A(old.getName());
		a.setAddress(ip);
		a.setTTL(old.getTTL());
		return a;
	}

	/**
	 * Add a dynamic entry and set teh TTY from the correct zone
	 * 
	 * @param name, fully qualified dns name
	 * @param addr, ip address 
	 * @return the A entry created or null if the domain is not valid
	 */
	public A addDynamic(String name, String addr) {
		A ret = buildDynamic(name, addr);
		if( ret != null ) {
			putDynamic(ret);
			flushDynamicSigning();
		}
		return ret;
	}

	/**
	 * Build (but don't publish) a dynamic A with the TTL of its zone.
	 * @return null if the name is not in one of our domains
	 * @throws IllegalArgumentException if the address is invalid
	 */
	private A buildDynamic(String name, String addr) {
		A ret = null;
		Name nn = new Name(name);
		Zone zone = getZoneFor(nn);
		if( zone == null &&  isCommon(nn) ) {
			zone = getDefaultZone();
		}
		if( zone != null ) {
			ret = new A(name);
			ret.setAddress(addr);
			ret.setTTL(zone.getSoa().getTTL());
		}
		return ret;
	}

	/**
	 * Get the zone for the fully qualified dns name by traversing
	 * the name dot by dot to find the domain.
	 * 
	 * @param nn, The fqdns name
	 * @return the correct zone or null if the name is not in a valid domain.
	 */
	// ------------------------------------------------------------ DNSSEC

	private volatile File dnssecKeyDir;
	private volatile int dnssecValidity = ZoneSigner.DEFAULT_VALIDITY;
	private volatile Map<String, List<DnssecKey>> dnssecKeys = Collections.emptyMap();
	private volatile long dnssecKeyStamp = Long.MIN_VALUE;
	//  A dynamic entry changed: signed zones may need signing again
	private volatile boolean dynamicDirty;

	/** The directory of the DNSSEC keys; null for the default (the zone directory). */
	public void setDnssecKeyDir(File dir) {
		dnssecKeyDir = dir;
		dnssecKeyStamp = Long.MIN_VALUE;
	}

	/** The directory the DNSSEC keys are read from (null if there is none yet). */
	public File getDnssecKeyDir() {
		File d = dnssecKeyDir;
		return d != null ? d : zoneDir;
	}

	/** How long signatures are valid, in seconds (at least an hour). */
	public void setDnssecValidity(int seconds) {
		if( seconds < 3600 ) {
			throw new IllegalArgumentException(PROP_DNSSEC_VALIDITY+" must be at least an hour: "+seconds);
		}
		dnssecValidity = seconds;
	}

	public int getDnssecValidity() {
		return dnssecValidity;
	}

	//  NSEC3: the zones (lower case) or "*", and the parameters
	private volatile java.util.Set<String> nsec3Zones = Collections.emptySet();
	private volatile us.bringardner.net.dns.dnssec.Nsec3Params nsec3Params = us.bringardner.net.dns.dnssec.Nsec3Params.DEFAULT;

	/**
	 * Sign these zones with NSEC3 (RFC 5155) instead of NSEC.
	 * 
	 * @param zones zone names separated by commas or spaces, "*" for every
	 *        zone, null or empty for none
	 */
	public void setDnssecNsec3(String zones, us.bringardner.net.dns.dnssec.Nsec3Params params) {
		java.util.Set<String> set = new java.util.HashSet<String>();
		if( zones != null ) {
			for(String z : zones.split("[,\\s]+")) {
				if( !z.trim().isEmpty() ) {
					set.add(z.trim().equals("*") ? "*" : Canonical.key(z.trim()));
				}
			}
		}
		if( params.getIterations() > 0 || params.getSalt().length > 0 ) {
			log("NSEC3 with "+params.getIterations()+" iterations and a salt: RFC 9276 recommends 0 iterations and no salt");
		}
		nsec3Params = params;
		nsec3Zones = Collections.unmodifiableSet(set);
	}

	/** The NSEC3 parameters for a zone, or null to use NSEC. */
	us.bringardner.net.dns.dnssec.Nsec3Params nsec3For(String zone) {
		java.util.Set<String> z = nsec3Zones;
		return z.contains("*") || z.contains(Canonical.key(zone)) ? nsec3Params : null;
	}

	/** The keys found for each zone (lower case name, no trailing dot). */
	public Map<String, List<DnssecKey>> getDnssecKeys() {
		return dnssecKeys;
	}

	private boolean dnssecKeysChanged() {
		return DnssecKey.dirStamp(getDnssecKeyDir()) != dnssecKeyStamp;
	}

	/** Read the key directory again if a key file was added, removed or changed. */
	synchronized void reloadDnssecKeys() {
		File dir = getDnssecKeyDir();
		long stamp = DnssecKey.dirStamp(dir);
		if( stamp == dnssecKeyStamp ) {
			return;
		}
		List<String> errors = new ArrayList<String>();
		Map<String, List<DnssecKey>> keys = DnssecKey.loadDir(dir, errors);
		for(String e : errors) {
			logError("DNSSEC key "+e);
		}
		for(Map.Entry<String, List<DnssecKey>> e : keys.entrySet()) {
			final String z = e.getKey();
			final String list = e.getValue().toString();
			log(() -> "DNSSEC keys for "+z+": "+list);
		}
		dnssecKeys = keys;
		dnssecKeyStamp = stamp;
	}

	/**
	 * The dynamic entries in a zone (not in a zone below it that we also
	 * serve): name -> records.
	 */
	private Map<String, List<? extends RR>> dynamicIn(Zone z, Map<String, Zone> zones) {
		Map<String, List<? extends RR>> ret = new java.util.TreeMap<String, List<? extends RR>>();
		String apex = Canonical.key(z.getName());
		for(Map.Entry<String, List<A>> e : dynamic.entrySet()) {
			String n = Canonical.key(e.getKey());
			if( !Canonical.isBelow(n, apex, true) ) {
				continue;
			}
			//  The closest zone we serve for the name must be this one
			String p = n;
			boolean mine = true;
			while( !p.equals(apex) ) {
				if( zones.containsKey(p) ) {
					mine = false;
					break;
				}
				p = p.substring(p.indexOf('.')+1);
			}
			if( mine ) {
				ret.put(n, e.getValue());
			}
		}
		return ret;
	}

	private static String fingerprint(Map<String, List<? extends RR>> dyn) {
		StringBuilder b = new StringBuilder();
		for(Map.Entry<String, List<? extends RR>> e : dyn.entrySet()) {
			b.append(e.getKey());
			for(RR rr : e.getValue()) {
				b.append(' ').append(rr.getTTL()).append(' ').append(Zone.rdataText(rr));
			}
			b.append('\n');
		}
		return b.toString();
	}

	/**
	 * The zone to serve for a loaded (or updated) zone: signed if the key
	 * directory has keys for it, as it is otherwise.
	 * 
	 * @param current the zone served now under that name, or null. It is
	 *        kept if its data, keys and dynamic entries are unchanged (unless
	 *        force), and if signing fails while its signatures are still valid.
	 * @param zones the zones (by lower case name) that will be served
	 */
	Zone prepareZone(Zone loaded, Zone current, boolean force, Map<String, Zone> zones) {
		Zone unsigned = loaded.getUnsigned();
		String name = Canonical.key(unsigned.getName());
		List<DnssecKey> keys = dnssecKeys.get(name);
		SignedZone cs = current == null ? null : current.getSigned();
		if( unsigned.isPresigned() ) {
			//  Signed elsewhere: served as it is
			if( cs != null && cs.unsigned == unsigned ) {
				return current;
			}
			if( keys != null && !keys.isEmpty() ) {
				logError("DNSSEC: "+name+" is signed in its zone file; the keys in "+getDnssecKeyDir()+" are not used for it");
			}
			ZoneSigner.Result r = ZoneSigner.presigned(unsigned, System.currentTimeMillis()/1000);
			for(String w : r.warnings) {
				logError("DNSSEC: "+w);
			}
			SignedZone sz = r.zone.getSigned();
			log(() -> "DNSSEC: "+name+" was signed elsewhere ("+sz.mode+", "+sz.rrsigCount+" signatures), valid until "
					+new Date(sz.expires*1000));
			return r.zone;
		}
		if( keys == null || keys.isEmpty() ) {
			if( cs != null ) {
				logError("DNSSEC: no keys for "+name+" any more, serving it unsigned");
			}
			return unsigned;
		}
		long now = System.currentTimeMillis()/1000;
		Map<String, List<? extends RR>> dyn = dynamicIn(unsigned, zones);
		String fp = fingerprint(dyn);
		us.bringardner.net.dns.dnssec.Nsec3Params nsec3 = nsec3For(name);
		String mode = nsec3 == null ? "NSEC" : "NSEC3 "+nsec3;
		if( !force && cs != null && cs.unsigned == unsigned && cs.keyId.equals(ZoneSigner.keyId(keys, now))
				&& cs.dynamicFingerprint.equals(fp) && cs.mode.equals(mode) ) {
			return current;
		}
		try {
			long start = System.currentTimeMillis();
			ZoneSigner.Result r = ZoneSigner.sign(unsigned, dyn, fp, keys, now, dnssecValidity, nsec3);
			for(String w : r.warnings) {
				logError("DNSSEC: "+w);
			}
			SignedZone sz = r.zone.getSigned();
			final long ms = System.currentTimeMillis()-start;
			log(() -> "DNSSEC: signed "+name+" with "+sz.mode+" (serial "+Integer.toUnsignedString(unsigned.getSoa().getSerial())+", "
					+sz.size()+" names, "+sz.rrsigCount+" signatures, "+ms+" ms), valid until "
					+new Date(sz.expires*1000));
			return r.zone;
		} catch(RuntimeException ex) {
			if( cs != null && cs.expires > now && cs.unsigned == unsigned ) {
				logError("DNSSEC: can't sign "+name+" ("+ex.getMessage()+"), still serving the previous signatures", ex);
				return current;
			}
			logError("DNSSEC: can't sign "+name+" ("+ex.getMessage()+"), serving it unsigned", ex);
			return unsigned;
		}
	}

	/** Sign again the signed zones whose dynamic entries changed. */
	void flushDynamicSigning() {
		if( !dynamicDirty ) {
			return;
		}
		synchronized(this) {
			dynamicDirty = false;
			ZoneSet cur = zoneSet;
			for(Zone z : cur.zones.values()) {
				SignedZone sz = z.getSigned();
				if( sz != null && sz.isPresigned() ) {
					if( !dynamicIn(sz.unsigned, cur.zones).isEmpty() ) {
						logError("DNSSEC: "+sz.apex+" is signed elsewhere, so its dynamic entries are served without signatures"
								+" (validators will reject them)");
					}
					continue;
				}
				if( sz != null && !fingerprint(dynamicIn(sz.unsigned, cur.zones)).equals(sz.dynamicFingerprint) ) {
					publishUpdatedZone(z, prepareZone(sz.unsigned, z, true, cur.zones));
				}
			}
		}
	}

	/**
	 * Sign again, with the next serial, the zones whose signatures are due to
	 * be renewed (a quarter of their validity left) or whose keys reached a
	 * timing event (Publish, Activate, Inactive, Delete). The new serial is
	 * written to the zone's journal so it survives a restart, and the
	 * secondaries get a NOTIFY.
	 * 
	 * @param now seconds since 1970
	 * @return the number of zones signed
	 */
	synchronized int resignDue(long now) {
		int ret = 0;
		ZoneSet cur = zoneSet;
		for(Zone z : new ArrayList<Zone>(cur.zones.values())) {
			SignedZone sz = z.getSigned();
			if( sz != null && sz.isPresigned() ) {
				warnIfExpiring(sz, now);
				continue;
			}
			if( sz == null || now < sz.refreshAt ) {
				continue;
			}
			Zone base = sz.unsigned;
			Zone next = base.copyForUpdate();
			Soa soa = (Soa)base.getSoa().copy();
			soa.setSerial(soa.getSerial()+1);
			next.replaceSoa(soa);
			try {
				writeJournal(base, Collections.singletonList("serial "+Integer.toUnsignedString(soa.getSerial())),
						"signed again (DNSSEC signatures renewed)");
			} catch(IOException ex) {
				logError("DNSSEC: can't write the journal of "+base.getName()+"; not signed again", ex);
				continue;
			}
			Zone served = prepareZone(next, z, true, zoneSet.zones);
			publishUpdatedZone(z, served);
			ZoneNotifier nf = notifier;
			if( nf != null ) {
				nf.notifyZone(served);
			}
			ret++;
		}
		return ret;
	}

	//  zone -> when we last warned that its (presigned) signatures expire soon
	private final Map<String, Long> expiryWarned = new ConcurrentHashMap<String, Long>();
	/** Warn this long before the signatures of a zone signed elsewhere expire. */
	static final long PRESIGNED_WARNING = 3*24*3600;

	/**
	 * A zone signed elsewhere is never signed here: log (every 6 hours) when
	 * its signatures expire within 3 days, or have expired.
	 * @return true if a warning was logged
	 */
	boolean warnIfExpiring(SignedZone sz, long now) {
		if( sz.expires - now > PRESIGNED_WARNING ) {
			return false;
		}
		Long last = expiryWarned.get(sz.apex);
		if( last != null && now - last < 6*3600 ) {
			return false;
		}
		expiryWarned.put(sz.apex, now);
		if( sz.expires <= now ) {
			logError("DNSSEC: signatures of "+sz.apex+" (signed elsewhere) expired "+new Date(sz.expires*1000)
					+"; validators reject its answers until it is signed again and reloaded");
		} else {
			logError("DNSSEC: signatures of "+sz.apex+" (signed elsewhere) expire "+new Date(sz.expires*1000)
					+"; sign it again and replace the zone file");
		}
		return true;
	}

	private static String stripDot(String n) {
		return n.endsWith(".") ? n.substring(0, n.length()-1) : n;
	}

	private Zone getZoneFor(Name nn) {
		Zone ret = null;

		while(ret==null && nn != null ) {
			if( (ret = getZone(nn.toString())) == null ) {
				nn = nn.getParentName();
			}
		}
		return ret;
	}


	public void stop() 	{
		running = false;
		shutdown = true;
		Thread t = thread;
		if( t != null && t != Thread.currentThread() ) {
			t.interrupt();
		}
		Resolver.shutDown();
	}

	/**
	 * Stop the server and wait (up to timeoutMs in total) for the threads it
	 * started to finish. The listening sockets are closed so threads blocked
	 * in receive()/accept() wake up at once instead of after their socket
	 * timeout (stop() alone left them running for up to that long, and they
	 * kept serving if the shutdown flag was cleared in the meantime).
	 * 
	 * @return true if every thread finished in time
	 */
	public boolean stopAndWait(long timeoutMs) throws InterruptedException {
		long deadline = System.currentTimeMillis()+timeoutMs;
		stop();
		closeDbConnection();
		closeListeners();
		ZoneNotifier n = notifier;
		if( n != null ) {
			n.shutdown();
		}
		long remaining = deadline - System.currentTimeMillis();
		boolean ret = TCPProsessor.shutdownConnections(Math.max(1, remaining));
		for(Thread w : workers) {
			long left = deadline - System.currentTimeMillis();
			if( left > 0 ) {
				w.join(left);
			}
			ret &= !w.isAlive();
		}
		long left = deadline - System.currentTimeMillis();
		ret &= Resolver.awaitShutdown(Math.max(1, left));
		return ret;
	}

	/**
	 * Remove a dynamic entry: the store first, then memory. (Memory used to
	 * go first; if the database write failed the entry was gone until the
	 * next database reload brought it back.)
	 */
	public void removeDynamic(String name) throws IOException  {
		synchronized (dynamicLock) {
			List<A> list = getDynamic(name);
			if( list == null) {
				return;
			}
			try {
				saveDynamic(name,list.get(0).getAddressString(),STATUS_DELETED);
			} catch (ClassNotFoundException | SQLException e) {
				throw new IOException(e);
			}
			Map<String, List<A>> after = new HashMap<String, List<A>>(dynamic);
			after.remove(dynamicKey(name));
			storeDynamicFile(after);
			dynamic.remove(dynamicKey(name));
			dynamicDirty = true;
		}
		flushDynamicSigning();
	}
}
