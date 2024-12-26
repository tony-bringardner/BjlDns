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
 * ~version~V000.00.05-V000.00.00-
 */
package us.bringardner.net.dns.dynamic;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;

import us.bringardner.net.dns.A;
import us.bringardner.net.dns.DnsBaseClass;

public class DynamicDns extends DnsBaseClass {

	private static final String PROP_DYNAMIC_DRIVER = "DnsDriver";
	private static final String PROP_DYNAMIC_URL = "DynUrl";
	private static final String PROP_DYNAMIC_USER = "DynUser";
	private static final String PROP_DYNAMIC_PASSWORD = "DynPassword";

	public static final String STATUS_ACTIVE = "active";
	public static final String STATUS_DELETED = "deleted";

	//private static final String SQL_SELECT_ALL = "select name,ip,lastUpdate dynamic_dns   where status = '"+STATUS_ACTIVE+"'";
	private static final String SQL_CREATE_DYN_DNS = "insert into dynamic_dns (ip,lastUpdate,status,name ) values(?,?,?,?)";
	private static final String SQL_UPDATE_DYN_DNS = "update dynamic_dns set ip=? ,lastUpdate=?,status=? where name=?";

	private static final int POS_IP = 1;
	private static final int POS_LAST_UPDATE = 2;
	private static final int POS_STATUS = 3;
	private static final int POS_NAME = 4;
	
	private String name;
	private String ip;
	private long lastUpdate;
	private String status=STATUS_ACTIVE;
	private A a;
	
	public DynamicDns(String name, String ip) {
		setName(name);
		setIp(ip);
	}
	
	
	public A getA() {
		return a;
	}


	public void setA(A a) {
		this.a = a;
	}


	public String getIp() {
		return ip;
	}

	public void setIp(String ip) {
		this.ip = ip;
	}


	public long getLastUpdate() {
		return lastUpdate;
	}

	public void setLastUpdate(long lastUpdate) {
		this.lastUpdate = lastUpdate;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	private Connection getDynDnsConnection() throws ClassNotFoundException, SQLException {
		String driver = System.getProperty(PROP_DYNAMIC_DRIVER,"org.gjt.mm.mysql.Driver");
		String url = System.getProperty(PROP_DYNAMIC_URL,"jdbc:mysql://mail.bringardner.us:3306/email");
		String user = System.getProperty(PROP_DYNAMIC_USER,"tony");
		String password = System.getProperty(PROP_DYNAMIC_PASSWORD,"0000");
		Connection con = null;
		Class.forName(driver);
		con = DriverManager.getConnection(url, user, password);
		return con;
	}


	public void create() throws ClassNotFoundException, SQLException {
		if( isValid() ) {
			doJdbc(SQL_CREATE_DYN_DNS);
		}
	}
	
	public void update() throws ClassNotFoundException, SQLException {
		if( isValid() ) {
			doJdbc(SQL_UPDATE_DYN_DNS);
		}
	}

	public void doJdbc(String sql) throws ClassNotFoundException, SQLException {
		if( isValid() ) {
			Connection con = null;
			PreparedStatement stmt = null;

			try {
				con = getDynDnsConnection();
				stmt = con.prepareStatement(sql);
				stmt.setString(POS_NAME, name);
				stmt.setString(POS_IP, ip);
				stmt.setString(POS_STATUS, status);
				lastUpdate=System.currentTimeMillis();
				stmt.setTimestamp(POS_LAST_UPDATE, new Timestamp(lastUpdate));
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

	private boolean isValid(String val) {
		return !( name == null || name.length() == 0 );
	}
	
	private boolean isValid() {
		boolean ret = isValid(name)
						&& isValid(ip)
						&& isValid(status)
						;
		return ret;
	}
	
	public static void main(String [] args) {
		
	}
}
