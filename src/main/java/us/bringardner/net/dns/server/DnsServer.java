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
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;

import javax.net.ServerSocketFactory;

import us.bringardner.net.dns.A;
import us.bringardner.net.dns.Cname;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.DnsBaseClass;
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

	public static final String PROP_TCP_PORT = "JDns.tcpPort";	
	public static final String PROP_TCP_BIND_ADDRESS = "JDns.tcpBindAddress";
	public static final String PROP_TCP_BACKLOG = "JDns.tcpBacklog";
	public static final String PROP_TCP_TIMEOUT = "JDns.tcpTimeout";




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
	private static int adminPort = 9999;
	private static boolean shutdown = false;
	private static boolean _debug = true;
	private boolean standAlone=false;
	private java.util.Date startTime = new java.util.Date();

	//  Recursion Available
	private boolean recursionAvailable = true;


	private Thread thread;	

	//  Directory where all DNS info is stored
	private File dnsDir;

	// This information applies to all auth zones unless otherwise defined
	private Map<String, Zone> zones = new HashMap<String, Zone>();
	private Zone defaultZone;


	// These servers are used to forward requests
	//private ArrayList forwarders;

	private Map<String, String> common = new HashMap<String, String>();

	private Map<String, List<A>> dynamic = new HashMap<String, List<A>>();

	//  Timeout for admin cycles
	private long acceptTimeout = 60000; //  one minute
	private long dynamicConfigRefreash = acceptTimeout * 5;


	//  Number of UDP Processor to create
	private int UDPProcCount = 10;
	private UDPProsessor [] UDPProcs;

	private boolean running = false;

	private int TCPProcCount = 4;	
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
	public synchronized void addDomain(String domain) {
		common.put(domain.toLowerCase(),domain);
	}

	/*
	 * Add a new Zone to the global data
	 */
	public void addZone(Zone zone) {

		zones.put(zone.getName().toLowerCase(),zone);	

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
	private Connection getConnection() {
		Connection ret = null;

		try {
			String jdbcClass=getProperty("JDns.jdbcClass");
			String url = getProperty("JDns.jdbcURL");
			String user = getProperty("JDns.jdbcUser");
			String password = getProperty("JDns.jdbcPassword");
			Class.forName(jdbcClass);


			ret = DriverManager.getConnection(url,user,password);



		} catch(Exception ex) {
			log(ex,"Database Init");
		}

		return ret;
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

		Zone ret = (Zone)zones.get(zoneName.toLowerCase());


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
		return zones;
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

		int alltimeout = 5000;
		int dnsPort = Message.DNSPORT;
		if( (tmp=getProperty(PROP_PORT)) != null) {
			dnsPort = Integer.parseInt(tmp);
		}

		if( (tmp=getProperty(PROP_TIMEOUT)) != null) {
			alltimeout = Integer.parseInt(tmp);
		}

		InetAddress bindAddress = InetAddress.getLoopbackAddress();
		if( (tmp=getProperty(PROP_BIND_ADDRESS)) != null) {
			bindAddress = createBindAddress(tmp);
		}

		int port = dnsPort;
		if( (tmp=getProperty(PROP_UDP_PORT)) != null) {
			port = Integer.parseInt(tmp);
		}
		InetAddress address = bindAddress;
		if( (tmp=getProperty(PROP_UDP_BIND_ADDRESS)) != null) {
			address = createBindAddress(tmp);
		}

		int udpTimeout = alltimeout;
		if( (tmp=getProperty(PROP_UDP_TIMEOUT)) != null) {
			alltimeout = Integer.parseInt(tmp);
		}

		UDPProcs = new UDPProsessor[UDPProcCount];
		Thread t = null;
		log("UDP BindAddress = "+bindAddress+":"+port+" timout="+udpTimeout);
		UDPProsessor.initUDPProsessor(port,address,udpTimeout);

		for(int i=0; i< UDPProcs.length; i++ ) {
			UDPProcs[i] = new UDPProsessor(this,i);
			t = new Thread(UDPProcs[i]);
			t.setName("UDPProc"+i);
			t.start();
		}

		TCPProcs = new TCPProsessor[TCPProcCount];
		port = dnsPort;
		if( (tmp=getProperty(PROP_TCP_PORT)) != null) {
			port = Integer.parseInt(tmp);
		}
		int backlong = 10;
		if( (tmp=getProperty(PROP_TCP_BACKLOG)) != null) {
			backlong = Integer.parseInt(tmp);
		}

		if( (tmp=getProperty(PROP_TCP_BIND_ADDRESS)) != null) {
			address = createBindAddress(tmp);
		}

		int tcpTimeout = alltimeout;
		if( (tmp=getProperty(PROP_TCP_TIMEOUT)) != null) {
			tcpTimeout = Integer.parseInt(tmp);
		}

		log("TCP BindAddress = "+bindAddress+":"+port+" backlog="+backlong+" timout="+tcpTimeout);
		TCPProsessor.initTCPProsessor(port,backlong,bindAddress,tcpTimeout);

		for(int i=0; i< TCPProcs.length; i++ ) {
			TCPProcs[i] = new TCPProsessor(this,i);
			t = new Thread(TCPProcs[i]);
			t.setName("TCPProc"+i);
			t.start();
		}

		us.bringardner.net.dns.resolve.Resolver.initResolver();


		//  Init the server admin values

		if( (tmp=getProperty(PROP_ADMIN_PORT))!=null) {
			try {
				setAdminPort(Integer.parseInt(tmp));
			} catch(Exception ex) {}
		}

		log("JDns Server init Complete");
	}  

	private InetAddress createBindAddress(String tmp) throws UnknownHostException {
		InetAddress ret = InetAddress.getLoopbackAddress();
		if( tmp.equals("localhost")) {
			ret = InetAddress.getLocalHost();
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
			try { UDPProcCount =Integer.parseInt(tmp); } catch(Exception ex) {}
		}
		if( (tmp=getProperty(PROP_TCP_PROC_COUNT)) != null)  {
			try { TCPProcCount =Integer.parseInt(tmp); } catch(Exception ex) {}
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
					common.put(name,name);
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

	private void loadDynamic() {
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

	public void addOrUpdateDynamic(String name, String ip) throws ClassNotFoundException, SQLException {
		A a = null;
		List<A> dyn = getDynamic(name);

		if(dyn == null ) {
			a =	addDynamic(name, ip);
			if( a == null ) {
				logError("-Undefined domain for "+name);
				return;
			} else {
				createDynamic(name,ip);
				return;
			}
		} else {
			a = (A)dyn.get(0);
			String old = a.getAddressString();    		
			if( !ip.equals(old)) {
				a.setAddress(ip);
			}
		} 
		// Keep track of the last time we were contacted
		saveDynamic(name,ip,STATUS_ACTIVE);


	}

	private void saveDynamic(String name, String ip, String status) throws ClassNotFoundException, SQLException {
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

	private boolean useDatabase() {		
		return getProperty(PROP_USE_BATABASE,"true").toLowerCase().startsWith("t");
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
					List<A> dyn = getDynamic(name);
					if( dyn != null ) {
						A a = (A)dyn.get(0);
						String old = a.getAddressString();    		
						if( !ip.equals(old)) {
							a.setAddress(ip);
							ret = true;
						}
					} else {
						addDynamic(name,ip);
						ret = true;
					}
					log("Dynamic "+name+" "+ip+" ret="+ret);
				}
				if( ret ) {
					try {
						dynamicFile = saveDynamicToFile();
					} catch (FileNotFoundException e) {
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

	private File loadDynamicFromFile(boolean saveNew) throws IOException {
		String fileName = getProperty(PROP_DYNAMIC,"dynamic.txt");
		log("Loading dynamic "+PROP_DYNAMIC+"= "+fileName);

		File ret = new File(fileName);
		if( !ret.isAbsolute() ) {
			ret = new File(dnsDir,fileName);
		}

		if( ret.exists() ) {
			BufferedReader in = new BufferedReader(new FileReader(ret));
			try {
				Properties p = new Properties();				
				p.load(in);
				for(Object key : p.keySet()) {
					String name = key.toString();
					if( getDynamic(name) == null) {
						if( saveNew) {
							try {
								addOrUpdateDynamic(name, getProperty(name));								
							} catch (ClassNotFoundException | SQLException e) {								
								throw new IOException(e);
							}
						} else {
							addDynamic(name, getProperty(name));
							log("Loading dynamic from file "+name+" "+getProperty(name));

						}
					}
				}				
			} finally {
				try { in.close();} catch(Exception ex) {}
			}
		}

		return ret;
	}


	public File saveDynamicToFile() throws FileNotFoundException {
		String fileName = getProperty(PROP_DYNAMIC,"dynamic.txt");

		log(PROP_DYNAMIC+"= "+fileName);


		File ret = new File(fileName);
		if( !ret.isAbsolute() ) {
			ret = new File(dnsDir,fileName);
		}

		PrintStream out = new PrintStream(new FileOutputStream(ret));
		try {
			out.println("# Dynamic entries saved at "+(new Date()));
			for (Iterator<String> it = dynamic.keySet().iterator(); it.hasNext();) {
				String name = (String) it.next();
				List<A> list = dynamic.get(name);
				A a = (A)list.get(0);
				out.println(name+"="+a.getAddressString());
			}
		} finally {
			try {
				out.close();
			} catch (Exception e) {
			}
		}


		return ret;
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

	boolean shouldReloadZones() {
		boolean ret = false;
		if( zoneDir == null ) {
			ret = true;
		} else {
			File[] list = getZoneFiles();
			if( list == null || list.length != zones.size()) {
				ret = true;
			} else {
				//  put them in a map;
				Map<String,File> map = new HashMap<>();
				for(File file : list) {
					map.put(file.getName(), file);					
				}
				for(Zone z : zones.values()) {
					File f = z.getMasterFile();
					File f2 = map.get(f.getName());
					if( f== null || f2 == null ) {
						ret = true;
						break;
					} else {
						if(f2.lastModified() != z.getLastModified() ) {
							ret = true;
							break;							
						}
					}					
				}			
			}
		}
		return ret;
	}

	/**
	 * Initialize the server from properties
	 */

	private void loadZones() throws IOException {

		String dirName = getProperty(PROP_ZONE_DIR,"zones");


		log("Loading zonez "+PROP_ZONE_DIR+"= "+dirName);

		zoneDir = new File(dirName).getCanonicalFile();


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

		zones = new HashMap<String, Zone>();
		for( int i=0; i< list.length; i++ ) {
			try {
				Zone z = new Zone(list[i]);
				addZone(z);
				log("Adding Zone "+z.getName());
			} catch (Throwable e) {
				logError("Error loading zone from "+list[i],e);
			}
		}
		if( (defaultZone=getZone(defaultZoneName)) == null ) {
			logError("Can't find default zone '"+defaultZoneName+"'! Must have at lease a default.  seraching in ("+zoneDir+")");
			throw new IOException("use '"+PROP_ZONE_DIR+"' or '"+PROP_DEFAULT_ZONE+"' to set correctly");			
		}
	}

	public Zone getDefaultZone() {
		return defaultZone;
	}

	/**
	 * 
	 * Creation date: (8/26/2001 12:39:33 PM)
	 * @param args java.lang.String[]
	 */
	public static void main(String[] args) {
		us.bringardner.net.dns.server.DnsServer svr = new DnsServer();


		svr.start(true);

		while(!svr.running) {
			Thread.yield();
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
				ret.add(retMsg);
			}			
		}
		return ret;
	}


	/**
	 * Delete a domain from our domain list
	 **/
	public synchronized Object removeDomain(String domain) {
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
			svrSock = getServerSocketFactory().createServerSocket(port);
			svrSock.setSoTimeout((int)acceptTimeout);
			log("Started dnsAdmin on port "+port);
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
					DnsAdminProcessor admin = new DnsAdminProcessor(this,clientSocket);
					admin.start();
					setState("Processing conneciton");
				}

			} catch (OutOfMemoryError ex) {
				System.out.println("Out of memory");
				ex.printStackTrace();
				System.exit(1);
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
				zone = defaultZone;
			}
		}

		if( zone != null ) {
			ret.setAuthorityAnswerOn();
			ret = step3(query,ret,zone);

		} else {
			if( !recursionAvailable ) {
				ret.setResponseCodeNameError();
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

	/* RFC 1034

   3. Start matching down, label by label, in the zone.  The
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
			//  Since we found a zone, if no matches are found, its an error.
			//ret.setResponseCodeNameError();
			ret.addAuthority(zone.getSoa());
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
							//  Need to add more stuff
							query.setQuestion(new Section(((Cname)realrr).getCname(),type,question.getDnsClass()));
							step2(query,ret);
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



		if( doNs && ret.getNSCount() == 0 ) {
			if( ret.isResponseCodeNameError() ) {
				ret.addAuthority(zone.getSoa());
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


		//  if the port == -1 then this is a TCP request and we won't support recursion
		if( question.getPort() == -1 ) {
			ret.setRecursiveAvailableOff();		
		} else 	if( recursionAvailable && question.getMessage().isRecursiveDesired() ) {
			//  The resolver has the cache.  So it takes care of 4 & 5
			question.getMessage().setAuthorityAnswerOff();
			us.bringardner.net.dns.resolve.ResolverThread.addQuery(question);
			ret = null;
		} else {
			ret.setID(msg.getID());
		}

		if( ret != null ) {
			ret.setID(msg.getID());
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

	public Map<String, List<A>> getDynamic() {
		Map<String, List<A>> ret = new HashMap<String, List<A>>();
		for(String name: dynamic.keySet()) {
			ret.put(name, dynamic.get(name));
		}
		return ret;
	}

	public List<A> getDynamic(String name) {
		List<A> ret = dynamic.get(name);
		return ret;
	}

	/**
	 * Add a dynamic entry and set teh TTY from the correct zone
	 * 
	 * @param name, fully qualified dns name
	 * @param addr, ip address 
	 * @return the A entry created or null if the domain is not valid
	 */
	public A addDynamic(String name, String addr) {
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
			List<A> list = new ArrayList<A>();
			list.add(ret);
			dynamic.put(name, list);
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
		thread.interrupt();
		Resolver.shutDown();
	}

	public void removeDynamic(String name) throws IOException  {
		List<A> list = dynamic.remove(name);

		if( list != null) {
			A a = list.get(0);
			try {
				saveDynamic(name,a.getAddressString(),STATUS_DELETED);
			} catch (ClassNotFoundException | SQLException e) {
				throw new IOException(e);
			}
		}

	}
}
