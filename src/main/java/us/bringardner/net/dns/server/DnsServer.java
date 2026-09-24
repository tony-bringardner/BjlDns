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
import java.io.FileNotFoundException;
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
import java.util.Iterator;
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
import us.bringardner.net.dns.resolve.QueryData;
import us.bringardner.net.dns.resolve.Resolver;

/**
 * A DNS Server
 * Creation date: (8/26/2001 5:26:49 AM)
 * @author: Tony Bringardner
 */
public class DnsServer  extends DnsBaseClass implements Runnable
{
	public static final String PROP_DEFAULT_ZONE = "JDns.master.zone";
	public static final String PROP_DNS_PROPERTIRS = "JDns.properties";
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
	/**
	 * Shared secret for the admin port (challenge-response, see AdminAuth).
	 * Without it only clients on this machine may use the admin port.
	 */
	public static final String PROP_ADMIN_SECRET = "JDns.adminSecret";
	/** Most admin sessions at once (default 8). */
	public static final String PROP_ADMIN_MAX_CONNECTIONS = "JDns.adminMaxConnections";
	/** An idle admin session is closed after this many ms (default 600000). */
	public static final String PROP_ADMIN_IDLE_TIMEOUT = "JDns.adminIdleTimeout";




	public static final String PROP_DNS_DIR = "JDns.dnsDir";
	public static final String PROP_DYNAMIC = "JDns.dynamicFileName";
	public static final String PROP_ZONE_DIR = "JDns.zone.dir";
	public static final String PROP_USE_BATABASE = "JDns.useDataBase";

	public static final String STATUS_ACTIVE = "active";
	public static final String STATUS_DELETED = "deleted";

	private static final String SQL_SELECT_ALL = "select name,ip,lastUpdate from dynamic_dns   where status = '"+STATUS_ACTIVE+"'";
	private static final String SQL_CREATE_DYN_DNS = "insert into dynamic_dns (ip,lastUpdate,status,name ) values(?,?,?,?)";
	private static final String SQL_UPDATE_DYN_DNS = "update dynamic_dns set ip=? ,lastUpdate=?,status=? where name=?";
	private static final int POS_IP = 1;
	private static final int POS_LAST_UPDATE = 2;
	private static final int POS_STATUS = 3;
	private static final int POS_NAME = 4;
	public static final String PROP_UDP_PROC_COUNT = "UDPProcCount";
	public static final String PROP_TCP_PROC_COUNT = "TCPProcCount";
	public static final String DEFAULT_DNS_DIR = "/data/services/dns/config";


	private static ServerSocketFactory serverSocketFactory=ServerSocketFactory.getDefault();
	private static volatile int adminPort = 9999;
	//  Where the admin port listens (set in initServer, default loopback)
	private volatile InetAddress adminBindAddress = InetAddress.getLoopbackAddress();
	//  Limits concurrent admin sessions (each had its own unbounded thread)
	private volatile java.util.concurrent.Semaphore adminSlots = new java.util.concurrent.Semaphore(8);
	private volatile int adminIdleTimeout = 10*60*1000;
	//  UDP/TCP processor threads started by initServer (for stopAndWait)
	private final List<Thread> workers = new java.util.concurrent.CopyOnWriteArrayList<Thread>();
	private static volatile boolean shutdown = false;
	private static volatile boolean _debug = true;
	private boolean standAlone=false;
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
		Map<String, Zone> zones = new HashMap<String, Zone>(cur.zones);
		zones.put(zone.getName().toLowerCase(),zone);
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
	private Connection getConnection() throws SQLException {
		String jdbcClass = stringProperty("JDns.jdbcClass");
		String url = stringProperty(PROP_JDBC_URL);
		String user = getProperty("JDns.jdbcUser");
		String password = getProperty("JDns.jdbcPassword");
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
		String propertyFile = getProperty(PROP_DNS_PROPERTIRS,DEFAULT_PROPERTIES_FILE_NAME);

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
		adminBindAddress = InetAddress.getLoopbackAddress();
		if( (tmp=stringProperty(PROP_ADMIN_BIND_ADDRESS)) != null) {
			adminBindAddress = createBindAddress(tmp);
		}
		adminSlots = new java.util.concurrent.Semaphore(Math.max(1, intProperty(PROP_ADMIN_MAX_CONNECTIONS, 8)));
		adminIdleTimeout = intProperty(PROP_ADMIN_IDLE_TIMEOUT, adminIdleTimeout);
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
			admin.setOnFinish(slots::release);
			admin.start();
			return true;
		} catch(IOException | RuntimeException ex) {
			slots.release();
			log("Can't start admin session",ex);
			try {
				clientSocket.close();
			} catch(IOException e) {
			}
			return false;
		}
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
		if( (tmp=getProperty(PROP_DEBUG)) != null) {
			_debug = tmp.toLowerCase().equals("true");
		}

		if( (tmp=getProperty(PROP_JDNS_RA)) != null) {
			recursionAvailable = tmp.toLowerCase().equals("true");
		}

		dnsDir=new File(getProperty(PROP_DNS_DIR,DEFAULT_DNS_DIR));

		if( (tmp=getProperty(PROP_UDP_PROC_COUNT)) != null)  {
			try { UDPProcCount =Integer.parseInt(tmp.trim()); } catch(Exception ex) {
				logError("Invalid number for "+PROP_UDP_PROC_COUNT+": '"+tmp+"', using "+UDPProcCount);
			}
		}
		if( (tmp=getProperty(PROP_TCP_PROC_COUNT)) != null)  {
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
			Connection con = null;
			Statement stmt = null;
			ResultSet rs = null;

			try {
				con = getConnection();
				stmt = con.createStatement();

				String sql = "select name from domains";

				rs = stmt.executeQuery(sql);

				while( rs.next() ) {
					String name = rs.getString(1);
					common.put(name.toLowerCase(),name);
					log("Install common domain ="+name);

				}
				try { rs.close(); } catch(Exception ex) {}


			} catch (Throwable ex) {
				log("Database not availible",ex);
			} finally {
				if( rs != null ) try { rs.close(); } catch(Exception ex) {}
				if( stmt != null ) try { stmt.close(); } catch(Exception ex) {}
				if( con != null ) try { con.close(); } catch(Exception ex) {}
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
	}

	/*
	private Connection getDynDnsConnection() throws ClassNotFoundException, SQLException {
		String driver = getProperty(PROP_DYNAMIC_DRIVER,"org.gjt.mm.mysql.Driver");
		String url = getProperty(PROP_DYNAMIC_URL,"jdbc:mysql://mail.bringardner.com:3306/email");
		String user = getProperty(PROP_DYNAMIC_USER,"tony");
		String password = getProperty(PROP_DYNAMIC_PASSWORD,"0000");
		Connection con = null;
		Class.forName(driver);
		con = DriverManager.getConnection(url, user, password);
		return con;
	}
	 */

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
			Connection con = null;
			PreparedStatement stmt = null;

			try {
				con = getConnection();
				stmt = con.prepareStatement(SQL_UPDATE_DYN_DNS);
				stmt.setString(POS_NAME, name);
				stmt.setString(POS_IP, ip);
				stmt.setString(POS_STATUS, status);
				stmt.setTimestamp(POS_LAST_UPDATE, new Timestamp(System.currentTimeMillis()));
				ret = stmt.executeUpdate();
			} finally {
				if( stmt != null ) {
					try { stmt.close(); } catch(Exception ee) {}
				}
				if( con != null ) {
					try { con.close(); } catch(Exception ee) {}
				}
			}
		}
		return ret;
	}
	private void createDynamic(String name, String ip) throws ClassNotFoundException, SQLException {
		Connection con = null;
		PreparedStatement stmt = null;

		if( useDatabase()) {
			try {
				con = getConnection();
				stmt = con	.prepareStatement(SQL_CREATE_DYN_DNS);
				stmt.setString(POS_NAME, name);
				stmt.setString(POS_IP, ip);
				stmt.setString(POS_STATUS, STATUS_ACTIVE);
				stmt.setTimestamp(POS_LAST_UPDATE, new Timestamp(System.currentTimeMillis()));
				stmt.executeUpdate();

			} finally {
				if( stmt != null ) {
					try { stmt.close(); } catch(Exception ee) {}
				}
				if( con != null ) {
					try { con.close(); } catch(Exception ee) {}
				}
			}
		}
	}

	/**
	 * JDns.useDataBase=true/false decides. If it is not set, the database is
	 * used only when JDns.jdbcURL is configured. (The old default was 'true',
	 * so a server without a database tried to connect on every dynamic update
	 * and reload, logged errors and hit NullPointerExceptions.)
	 */
	boolean useDatabase() {
		String flag = stringProperty(PROP_USE_BATABASE);
		if( flag != null ) {
			return flag.toLowerCase().startsWith("t");
		}
		return stringProperty(PROP_JDBC_URL) != null;
	}

	private boolean loadDynamicFromDb() throws ClassNotFoundException, SQLException {
		boolean ret = false;
		if( useDatabase()) {
			Connection con = null;
			Statement stmt = null;
			ResultSet rs = null;
			log("Loading dynamic from database");

			try {
				con = getConnection();
				stmt = con.createStatement();
				rs = stmt.executeQuery(SQL_SELECT_ALL);

				while(rs.next()) {
					String name = rs.getString(1);
					String ip = rs.getString(2);
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
			} finally {
				if( rs != null ) {
					try { rs.close(); } catch(Exception ee) {}
				}
				if( stmt != null ) {
					try { stmt.close(); } catch(Exception ee) {}
				}
				if( con != null ) {
					try { con.close(); } catch(Exception ee) {}
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
				try { in.close();} catch(Exception ex) {}
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

	/** Zone file name -> lastModified for the zone files in zoneDir now. */
	private Map<String, Long> currentZoneFiles() {
		Map<String, Long> ret = new HashMap<String, Long>();
		File [] list = zoneDir == null ? null : getZoneFiles();
		if( list != null ) {
			for(File f : list) {
				ret.put(f.getName(), f.lastModified());
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
		return !currentZoneFiles().equals(seen);
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
				seen.put(fileName, modified);

				Zone prev = old.byFile.get(fileName);
				Long prevModified = oldSeen == null ? null : oldSeen.get(fileName);
				Zone z = null;
				if( prev != null && prevModified != null && prevModified.longValue() == modified ) {
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

				if( z != null ) {
					byFile.put(fileName, z);
					Zone dup = zones.put(z.getName().toLowerCase(),z);
					if( dup != null && dup != z ) {
						logError("Zone "+z.getName()+" is defined by more than one file, using "+file);
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
		while(!svr.running) {
			try {
				Thread.sleep(50);
			} catch (InterruptedException e) {
				return;
			}
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


		//  Only queries are supported
		if( !reqMsg.isQuery() ) {
			Message  retMsg = new Message();
			retMsg.setHeader(hdr);
			retMsg.setResponseCodeRefused();
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
				retMsg = step2(req,retMsg);
				if( retMsg != null && req.getCnameTarget() != null ) {
					retMsg = completeOutOfZoneCname(req, retMsg);
				}
				ret.add(retMsg);
			}			
		}
		return ret;
	}


	/**
	 * Delete a domain from our domain list
	 **/
	public Object removeDomain(String domain) {
		return common.remove(domain.toLowerCase());
	}


	public void run() {
		
		try {
			initServer();
		} catch (Throwable e1) {
			log("Can't init server",e1);
			if( standAlone) {
				logError("Exiting with -1");
				System.exit(-1);				
			}
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
			log("Can't create server socket on port "+getAdminPort(),ex);
			setState("Failed to start");
			if( standAlone) {
				System.exit(-2);
			}
			return;
		}



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

	public void start(boolean standAlone) {
		if( !running ) {
			this.standAlone = standAlone;
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

		if( type == DNS.SOA ) {
			Soa soa = zone.getSoa();
			RR realrr = soa.copy();
			realrr.replaceWildCards(targetName);			
			ret.addAnswer(realrr);
			String domain = soa.getName();
			target = targetName.toString();

			// Set the SOA info to the hosted name
			if( !domain.equals(target)){
				//String postMaster = soa.getMname();
				//  must be common
				((Soa)realrr).setName(target);
				((Soa)realrr).setMname("postmaster."+target);
			}
			String dnsServer = soa.getRname();
			realrr = zone.getMatchingRR(dnsServer,DNS.A);
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
		//System.out.println(target+" list 2="+list1);
		if( list == null ) {
			//  We are authoritative for this zone and the name has no records.
			//  NXDOMAIN (RFC 1034 4.3.2 step 3c), unless it is an empty
			//  non-terminal (has names below it), which exists: NODATA.
			//  Either way the SOA goes in the authority section (RFC 2308 3).
			//  After a CNAME this also sets the final RCODE (RFC 6604).
			if( zone.hasNamesBelow(target) ) {
				ret.setResponseCodeNoError();
			} else {
				ret.setResponseCodeNameError();
			}
			ret.addAuthority(zone.getNegativeSoa());
		} else {

			//  Since we found the name it's not a name error even if we may not have the type
			ret.setResponseCodeNoError();

			for(int i=0,sz=list.size(); i< sz; i++ ) {
				rr = (RR)list.get(i);
				if( (myType=rr.getType()) == type || myType == DNS.CNAME || type == DNS.QTYPE_ALL)  {
					//  Just in case the match is a wild card
					RR realrr = rr.copy();
					realrr.replaceWildCards(targetName);
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
			Message resolved = resolveOrNull(req.getCnameTarget());
			req.setCnameTarget(null);
			return us.bringardner.net.dns.resolve.ResolverThread.completeCnameAnswer(partial, resolved);
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

	/** Resolve in the calling thread; null if it fails. */
	private Message resolveOrNull(Section s) {
		try {
			return Resolver.resolve(s);
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
		try {
			ret = Resolver.resolve(question.getQuestion());
		} catch(RuntimeException | StackOverflowError ex) {
			logError("Resolver failed for "+question.getQuestion(), ex);
		}
		if( ret == null ) {
			ret = us.bringardner.net.dns.resolve.ResolverThread.failure(question, DNS.SERVER_ERROR);
		}
		return ret;
	}

	/*
  6. Using local data only, attempt to add other RRs which may be
      useful to the additional section of the query.  Exit.
	 */

	private Message step6(QueryData question, Message ret) {

		//  Maybe add some referrals or add some NS records???

		//List<RR> list = ret.getAnswer();

		/*
		if( list != null ) {
			for(int i=0,sz=list.size(); i<sz; i++ ) {
				RR rr  = (RR)list.get(i);
				if( rr.getType() == DNS.NS) {
					msg.addAuthority(rr);
					Ns ns = (Ns)rr;
					RR aa = getMatchingRR(ns.getNs(),DNS.A);
					if( aa != null ) {
						msg.addAdditional(aa);
					}
				}
			}
		}
		 */

		return ret;

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
		if( t != null ) {
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
		java.net.DatagramSocket udp = UDPProsessor.getSock();
		if( udp != null ) {
			udp.close();
		}
		ServerSocket tcp = TCPProsessor.getServerSocket();
		if( tcp != null ) {
			try {
				tcp.close();
			} catch(IOException ex) {
			}
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
		}
	}
}
