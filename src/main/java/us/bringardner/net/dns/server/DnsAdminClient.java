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
 * ~version~V000.01.02-V000.00.05-V000.00.00-
 */
package us.bringardner.net.dns.server;

import java.io.IOException;
import java.net.Socket;
import java.util.Scanner;

import javax.net.SocketFactory;

import us.bringardner.io.CRLFLineReader;
import us.bringardner.io.CRLFLineWriter;
import us.bringardner.net.dns.util.NsLookup;

/**
 * 
 * Creation date: (6/16/2003 10:53:15 AM)
 * @author: Tony Bringardner
 */
public class DnsAdminClient implements DnsAdminConstants {
	private static SocketFactory socketFactory = SocketFactory.getDefault();
	private Socket sock;
	private CRLFLineReader in;
	private CRLFLineWriter out;
	private String adminHost;
	private int adminPort;
	private int timeout = 2000;

	/**
	 * AdminClient constructor comment.
	 */
	public DnsAdminClient() {
		super();
	}

	public static void main(String args[]) throws IOException  {

		String name = System.getProperty("name");
		if( args.length>0) {
			name = args[0];
		}
		if( name == null ) {
			name = NsLookup.getDnsServer();
			if( name == null ) {
				name = "localhost";
			}
		}

		int port = DnsServer.getAdminPort();
		String tmp = System.getProperty("port");
		if( tmp == null && args.length>1) {
			tmp = args[1];
		}
		if( tmp != null ) {
			try {
				port = Integer.parseInt(tmp);
			} catch (Exception e) {
			}
		}

		DnsAdminClient client = new DnsAdminClient(name,port);
		if( client.connect()) {
			try (Scanner in = new Scanner(System.in)) {
				System.out.print("DNS Admin>");
				while(in.hasNext()) {
					String cmd = in.nextLine();
					if( cmd == null ) {
						client.close();
						return;
					}
					if( cmd.isEmpty()) {
						try {
							String res = client.sendCommand(cmd);
							System.out.println(res);
							if( QUIT.equals(cmd)) {
								return;
							}
						} catch (Exception e) {
							e.printStackTrace();
							return;
						}
						System.out.print("DNS Admin>");
					}
				}
			}
		} else {
			System.out.println("Could not connecct to "+name+":"+port);
		}


	}

	/**
	 * AdminClient constructor comment.
	 */
	public DnsAdminClient(String host, int port) throws IOException{
		this.adminHost = host;
		this.adminPort = port;
	}


	public String getAdminHost() {
		return adminHost;
	}

	public void setAdminHost(String adminHost) {
		this.adminHost = adminHost;
	}

	public int getAdminPort() {
		return adminPort;
	}

	public void setAdminPort(int adminPort) {
		this.adminPort = adminPort;
	}

	public int getTimeout() {
		return timeout;
	}

	public void setTimeout(int timeout) {
		this.timeout = timeout;
	}

	public boolean connect()  {
		boolean ret = false;
		try {
			sock = getSocketFactory().createSocket(adminHost,adminPort);
			sock.setSoTimeout(getTimeout());
			in = new CRLFLineReader(sock.getInputStream());
			out = new CRLFLineWriter(sock.getOutputStream());
			String tmp = in.readLine();
			if( tmp.startsWith("+")) {
				ret = true;
			} else {
				System.out.println("Connected but invalid prompt from server="+tmp);
			}
		} catch (Exception e) {
			System.out.println(e);
		}
		return  ret;
	}

	public void close() {
		if( out != null ) {
			try {
				sendCommand(QUIT);
			} catch(Exception ex){}
		}

		if( in != null ) { try { in.close(); } catch(Exception ex) {} }
		if( out != null ) { try { out.close(); } catch(Exception ex) {} }
		if( sock != null ) { try { sock.close(); } catch(Exception ex) {} }
		in = null;
		out = null;
		sock = null;

	}


	private String executePreDefined(String cmd,String ... args ) throws IOException {
		if( args == null || args.length == 0 ) {
			return("Usage:"+cmd+" name [name...]");			
		}

		// concat all args
		
		StringBuilder buf = new StringBuilder(cmd);
		for(String d : args) {
			buf.append(" "+d);
		}
		String ret = sendCommand(buf.toString());
		
	
		return ret;
	}

	public String memory() throws IOException {
		return sendCommand(MEM);
	}

	public String list() throws IOException {
		return sendCommand(LIST);
	}

	public String reset() throws IOException {
		return sendCommand(RESET);
	}

	public String statusALL() throws IOException {
		return sendCommand(STATUS+" "+ALL);
	}

	public String statusUDP() throws IOException {
		return sendCommand(STATUS+" "+UDP);
	}

	public String statusTCP() throws IOException {
		return sendCommand(STATUS+" "+TCP);
	}

	public String statusResolver() throws IOException {
		return sendCommand(STATUS+" "+RESOLVER);
	}

	public String debug(String ... args) throws IOException {
		return executePreDefined(DEBUG, args);
	}

	public void addDomain(String ... domains ) throws IOException {
		executePreDefined(ADD_DOMAIN, domains);
	}

	public void removeDomain(String ... domains ) throws IOException {
		executePreDefined(DEL_DOMAIN, domains);
	}


	public void addDynamic(String ... args ) throws IOException {
		executePreDefined(ADD_DYNAMIC, args);
	}

	public void removeDynamic(String ... args ) throws IOException {
		executePreDefined(DEL_DYNAMIC, args);
	}



	/**
	 * 
	 * Creation date: (6/16/2003 10:58:49 AM)
	 * @return javax.net.SocketFactory
	 */
	public static javax.net.SocketFactory getSocketFactory() {
		return socketFactory;
	}


	private String sendCommand(String cmd) throws IOException {

		StringBuffer ret = new StringBuffer();
		out.writeLine(cmd);
		out.flush();

		String tmp = null;
		boolean done = false;

		while ( !done && (tmp=in.readLine())!=null) {
			ret.append(tmp+"\n");
			if( tmp.startsWith("+") || tmp.startsWith("-") ) {
				done = true;
			} 
		}
		
		return ret.toString();


	}

	/**
	 * 
	 * Creation date: (6/16/2003 10:58:49 AM)
	 * @param newSocketFactory javax.net.SocketFactory
	 */
	public static void setSocketFactory(javax.net.SocketFactory newSocketFactory) {
		socketFactory = newSocketFactory;
	}


}
