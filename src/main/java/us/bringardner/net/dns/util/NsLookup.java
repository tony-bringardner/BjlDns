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
 * ~version~V000.01.02-V000.00.05-V000.00.04-V000.00.00-
 */
package us.bringardner.net.dns.util;

/**
	Copyright Tony Bringarder 1999, 2025
 */
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.InterruptedIOException;
import java.io.PrintStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import us.bringardner.core.BjlLogger;
import us.bringardner.core.ILogger;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.Ns;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.Utility;

/** 
	Test the DNS Code.  This class is intended to give a close emulation of the UNIX nslookup program.  


<pre>
~Commands:       (identifiers are shown in uppercase, [] means optional)
~NAME            - print info about the host/domain NAME using default server
~NAME1 NAME2     - as above, but use NAME2 as server
~help or ?       - print info on common commands; see nslookup(1) for details
~set OPTION      - set an option
~   all         - print options, current server and host
~   debug=(y|n)   - print debugging information
~   *d2      (y|n) - print exhaustive debugging information
~   *defname (y|n) - append domain name to each query 
~   recurse (y|n) - ask for recursive answer to query
~   udp     (y|n) - always use a UDP or virtual circuit
~   domain=NAME - set default domain name to NAME
~   *srchlist=N1[/N2/.../N6] - set domain to N1 and search list to N1,N2, etc.
~   *root=NAME   - set root server to NAME
~   retry=X     - set number of retries to X
~   timeout=X   - set initial time-out interval to X seconds
~   querytype=X - set query type, e.g., A,ANY,CNAME,HINFO,MX,PX,NS,PTR,SOA,TXT,WKS,SRV,NAPTR
~   port=X      - set port number to send query on
~   type=X      - synonym for querytype
~   class=X     - set query class to one of IN (Internet), CHAOS, HESIOD or ANY
~server NAME     - set default server to NAME, using current default server
~*lserver NAME    - set default server to NAME, using initial server
~*root            - set current default server to the root
~exit            - exit the program, quit, ^C also exits
~quit            - exit the program, exit, ^C also exits
~
~* Not Implemented

<b><em>Default Server</em></b>
The server default is dns.minEmall.com.  
You can change this from the command line (server new.server.com) 
or create a file called JDns.prop in the current directory and add the
following line;
JDns.server=new.server.com

</pre>
 */
public class NsLookup extends Utility {

	static class ExitException extends Exception {

		private static final long serialVersionUID = 1L;

	}

	static Message msg = new Message();
	static PrintStream out = System.out;
	// this is for testing
	static boolean echoCommand = false;
	static BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
	static int qtype = A;
	static int dnsClass = IN;
	static String domain = "";
	static String lastName="";


	public static Message getMsg() {
		return msg;
	}

	public static void setMsg(Message msg) {
		NsLookup.msg = msg;
	}

	public static PrintStream getOut() {
		return out;
	}

	public static void setOut(PrintStream out) {
		NsLookup.out = out;		
		if( msg != null ) {
			ILogger logger = msg.getLogger();
			if (logger instanceof BjlLogger	) {
				BjlLogger l = (BjlLogger) logger;
				l.setOut(out);
			}
		}
	}

	public static BufferedReader getIn() {
		return in;
	}

	public static void setIn(BufferedReader in) {
		NsLookup.in = in;
	}

	public static int getQtype() {
		return qtype;
	}

	public static void setQtype(int qtype) {
		NsLookup.qtype = qtype;
	}

	public static int getDnsClass() {
		return dnsClass;
	}

	public static void setDnsClass(int dnsClass) {
		NsLookup.dnsClass = dnsClass;
	}

	public static String getHelp() {
		return help;
	}
	static final String help = 
			"Commands:       (identifiers are shown in uppercase, [] means optional)\n"+
					"NAME            - print info about the host/domain NAME using default server\n"+
					"NAME1 NAME2     - as above, but use NAME2 as server\n"+
					"help or ?       - print info on common commands; see nslookup(1) for details\n"+
					"set OPTION      - set an option\n"+
					"    all         - print options, current server and host\n"+
					"    debug=(y|n)   - print debugging information\n"+
					"    recurse (y|n) - ask for recursive answer to query\n"+
					"    udp     (y|n) - always use a UDP or virtual circuit\n"+
					"    domain=NAME - set default domain name to NAME\n"+
					"    retry=X     - set number of retries to X\n"+
					"    timeout=X   - set initial time-out interval to X seconds\n"+
					"    querytype=X - set query type, e.g., A,ANY,CNAME,HINFO,MX,PX,NS,PTR,SOA,TXT,WKS,SRV,NAPTR\n"+
					"    port=X      - set port number to send query on\n"+
					"    type=X      - synonym for querytype\n"+
					"    class=X     - set query class to one of IN (Internet), CHAOS, HESIOD or ANY\n"+
					"server NAME     - set default server to NAME, using current default server\n"+
					"exit            - exit the program, ^C also exits\n";

	public NsLookup() {
		super();
	}

	public static String getAuthority(String name, String nsServer) throws IOException {
		String ret = null;
		Message msg = new Message();
		msg.setServer(nsServer);
		Message ans = null;
		try {
			//  Otherwise, ask for the requested type
			if( (ans = query(msg,name,NS,dnsClass)) == null ) {
				return null;
			}
		} catch(Throwable ex) {
			out.println("No reply from server");
			return null;
		}

		int rcode = ans.getResponseCode();
		if( rcode != NOERROR ) {
			out.println(ERRORNAMES[rcode]);
			return null;
		}

		if( ans.isAuthority() ) {
			out.println("Authoritative answer svr=:"+msg.getServer());
			return nsServer;
		} else {
			out.println("Non-authoritative answer:");
			for(RR rr : ans.getAuthority() ) {
				if (rr instanceof Ns) {
					Ns ns = (Ns) rr;
					String nm = ns.getNs();
					Message m2 = new Message();
					us.bringardner.net.dns.A arec = ans.getAddress(nm);
					if( arec !=null ) {
						String svr = arec.getAddressString();

						try {
							m2.setServer(svr);
						} catch (UnknownHostException e) {
							e.printStackTrace();
							return null;
						}
						ret = getAuthority(name,svr);
					}
				}
			}				
		}

		return ret;
	}

	public static Message query(Message msg,String name, int type, int dnsClass2) throws IOException {
		Message ret = null;

		if( name.length() > 0 && Character.isDigit(name.charAt(0)) ) {
			//If an ip address lookup is request, ask for PTR records recursion 
			ret = msg.query(name,PTR,dnsClass);
		} else {
			if ( !domain.isEmpty()) {
				name = name+"."+domain;
			}
			//  Otherwise, ask for the requested type				
			ret = msg.query(name,type,dnsClass);
			if(msg.isResponseCodeNoError() && msg.isRecursive()) {
				if(!ret.isAuthority()) {
					Message tmp = doRecursion(msg,ret);
					if( tmp !=null && tmp.isResponseCodeNoError()) {
						ret = tmp;
					}

				}
			}
			lastName = name;
		}
		return ret;
	}

	private static Message doRecursion(Message msg2, Message ret1) throws IOException {
		Message ret2 = ret1;
		if(msg2.isResponseCodeNoError() && msg2.isRecursive()) {
			if(!ret1.isAuthority()) {
				for(Iterator<RR> e1=ret1.authority(); e1.hasNext(); ) {
					RR rr = e1.next();
					if (rr instanceof Ns) {
						Ns ns = (Ns) rr;
						String svr = ns.getNs();
						us.bringardner.net.dns.A arec = ret1.getAddress(svr);
						Message m2 = msg2.copy();
						if( arec != null ) {
							byte[] addr = arec.getAddress();
							InetAddress ip = InetAddress.getByAddress(addr);
							m2.setServer(ip);
						} else {
							m2.setServer(svr);
						}
						Message tmp  = m2.query();
						if( tmp != null && tmp.isResponseCodeNoError() ) {
							ret2 = doRecursion(msg2, tmp);
							break;
						}
					}
				}
			}				

		}	
		return ret2;
	}

	public static List<InetAddress> getHostAddresses() {
		List<InetAddress> hostAddresses = new ArrayList<InetAddress>();
		try {
			for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
				if (!ni.isLoopback() && ni.isUp() && ni.getHardwareAddress() != null) {
					for (InterfaceAddress ia : ni.getInterfaceAddresses()) {
						InetAddress ip = ia.getAddress();
						if (ip instanceof Inet4Address) {
							Inet4Address ip4 = (Inet4Address) ip;
							hostAddresses.add(ip4);	
						}

					}
				}
			}
		} catch (SocketException e) { }

		return hostAddresses;
	}

	public static void main(String[] args) throws Exception {
		lastName = "";
		domain = "";
		dnsClass = IN;
		qtype = A;
		
		echoCommand = System.getProperty("echoCommand", "false").equals("true");

		try {


			int startArg = 0;			
			msg.setServer(getDnsServer());
			msg.recursiveDesiredOn();
			msg.setRecursiveAvailable(true);
			msg.debugOff();
			
			if( args.length>1) {
				if( args[0].equals("-s")) {
					msg.setServer(args[1]);
					startArg = 2;
				}
			}
			if( args.length > startArg) {
				for (int idx = 0; idx < args.length; idx++) {
					processCmd(args[idx]);
				}

			} else {
				String cmd = "";

				if( args.length > 0 ) {
					for(int i=0; i< args.length; i++ ) {
						processCmd(args[i]);
					}
				} else {
					//out.print("Server "+msg.getServer()+" ready\n\n> ");
					out.print("\n> ");

					while( (cmd=in.readLine()) != null) {
						if( cmd != null && !cmd.isEmpty()) {
							if( echoCommand) {
								out.println(cmd);
							}
							try {
								processCmd(cmd);									
							} catch (ExitException e) {
								out.println("NsLookup done");
								return;
							}							
						}
						//out.print("\nServer "+msg.getServer()+" ready\n\n> ");
						out.print("\n> ");
					}
				}
			}
		} catch(Exception ex) {
			ex.printStackTrace(out);
		}
		out.println("NsLookup exit main");
	}// End of main

	/*
	 * This is the list as of the time of this writing
	 * 
a.root-servers.net	198.41.0.4, 2001:503:ba3e::2:30	Verisign, Inc.
b.root-servers.net	170.247.170.2, 2801:1b8:10::b	University of Southern California,
Information Sciences Institute
c.root-servers.net	192.33.4.12, 2001:500:2::c	Cogent Communications
d.root-servers.net	199.7.91.13, 2001:500:2d::d	University of Maryland
e.root-servers.net	192.203.230.10, 2001:500:a8::e	NASA (Ames Research Center)
f.root-servers.net	192.5.5.241, 2001:500:2f::f	Internet Systems Consortium, Inc.
g.root-servers.net	192.112.36.4, 2001:500:12::d0d	US Department of Defense (NIC)
h.root-servers.net	198.97.190.53, 2001:500:1::53	US Army (Research Lab)
i.root-servers.net	192.36.148.17, 2001:7fe::53	Netnod
j.root-servers.net	192.58.128.30, 2001:503:c27::2:30	Verisign, Inc.
k.root-servers.net	193.0.14.129, 2001:7fd::1	RIPE NCC
l.root-servers.net	199.7.83.42, 2001:500:9f::42	ICANN
m.root-servers.net	202.12.27.33, 2001:dc3::35	WIDE Project
	 */
	public static String getDnsServer() throws IOException {
		String ret = null;
		for(int ch='a'; ch <= 'm'; ch++ ) {
			String tmp  = (char)ch+".root-servers.net";
			Message msg= new Message();
			msg.setServer(tmp);
			Message a = msg.query(tmp);
			if( a.getResponseCode() == DNS.NOERROR) {
				ret = tmp;
				break;
			}
		}

		return ret;  
	}


	/**
	 * Just validate I can witch root servers are currently responding
	 * @return
	 * @throws IOException
	 */
	public static List<String> getAllRootServers() throws IOException {
		List<String> ret = new ArrayList<String>();

		for(int ch='a'; ch <= 'm'; ch++ ) {
			String tmp  = (char)ch+".root-servers.net";
			String a = getAuthority(tmp, tmp);
			if( a != null && !a.isEmpty()) {
				ret.add(a);
			}
		}

		return ret;  
	}

	public static String parseArg(String cmd) throws IOException {
		String arg = null;

		int idx = cmd.indexOf('=');
		if( idx == -1 && (idx=cmd.indexOf(' '))==-1 ) {
			out.print("Enter "+cmd+": ");
			arg = in.readLine();
		} else {
			arg = cmd.substring(++idx);
		}
		return arg;
	}

	public static void processCmd(String cmd1) throws Exception {
		String [] parts = cmd1.split(" ");

		for (int idx = 0; idx < parts.length; idx++) {
			String cmd = parts[idx];
			if( cmd.equals("exit") || cmd.equals("quit") ) {
				throw new ExitException();
			} else if( cmd.equals("?") ) {
				showHelp();
			} else if( cmd.equals("help") ) {
				showHelp();
			} else if( cmd.startsWith("set") ) {
				setOption(parts[++idx]);
			} else if( cmd.startsWith("server") ) {
				String srv = (parts[++idx]);
				if( srv!= null && srv.length() > 0 ) {
					msg.setServer(srv);
				}
			}  else 	if( cmd.equals("all"))  {
				out.println(
						"debug="+msg.isDebug()+"\tdefname="+msg.isDefname()+
						"\nrecuse="+msg.isRecursiveDesired()+"\tudp="+msg.isUDP()+
						"\ndomain="+domain+"\tretry="+msg.getRetry()+
						"\nquerytype="+TYPENAMES[qtype]+"\tclass="+CLASSNAMES[dnsClass]+
						"\nserver="+msg.getServerName()+"\tport="+msg.getPort());
				return;

			} else {
				displayResults(cmd);
			}
		}
	}

	public static void setOption(String cmd) throws Exception {
		// all takes no parameters
		if( cmd.equals("all"))  {
			out.println(
					"debug="+msg.isDebug()+"\tdefname="+msg.isDefname()+
					"\nrecuse="+msg.isRecursive()+"\tudp="+msg.isUDP()+
					"\ndomain="+domain+"\tretry="+msg.getRetry()+
					"\nquerytype="+TYPENAMES[qtype]+"\tclass="+CLASSNAMES[dnsClass]+
					"\nserver="+msg.getServerName()+"\tport="+msg.getPort());

			return;
		}

		String val = parseArg(cmd);

		if( val == null || val.isEmpty()) {
			return;
		}

		if( cmd.startsWith("timeout")) {
			msg.setTimeOut(Integer.parseInt(val));
		} else if( cmd.startsWith("retry")) {
			msg.setRetry(Integer.parseInt(val));
		} else if( cmd.startsWith("udp")) {
			String yn = val;
			if( yn.charAt(0) == 'y' || yn.charAt(0) == 'Y' ) {
				msg.UDPOn();
			} else {
				msg.UDPOff();
			}
		} else if( cmd.startsWith("debug") || cmd.startsWith("d2")) {
			String  yn = val;
			if( yn.charAt(0) == 'y' || yn.charAt(0) == 'Y' ) {
				msg.debugOn();
			} else {
				msg.debugOff();
			}
		} else if( cmd.startsWith("recurse")) {
			String yn = val;
			if( yn.charAt(0) == 'y' || yn.charAt(0) == 'Y' ) {
				msg.recursiveDesiredOn();
				msg.setRecursiveAvailable(true);
			} else {
				msg.recursiveDesiredOff();
				msg.setRecursiveAvailable(false);
			}
		} else if( cmd.startsWith("domain")) {
			domain = (val);
		} else if( cmd.startsWith("port")) {
			msg.setPort(Integer.parseInt(val));
		} else if( cmd.startsWith("type")) {
			qtype = typeOf(val);
			out.println("Type = "+qtype);
		} else if( cmd.startsWith("querytype")) {
			qtype = typeOf(val);
		} else if( cmd.startsWith("class")) {
			dnsClass = classOf(val);
		} else {
			//  Bad set option
			out.println("Invalid Option:");
			out.println(help);
		}
	}
	public static void showHelp() {
		out.println(help);
	}
	/**
	Execute a DNS request and dsiplay the results.
	 */
	public static void displayResults(String cmd) throws Exception {
		String oldSvr = null;
		Message ans = null;
		int idx = cmd.indexOf(' ');

		/*
		cmd should be in one of the following formats
			NAME
			SERVER NAME
			ipaddress (999.999.999.999)
		 */
		if( idx > 0 ) {
			/*
		SERVER NAME format.  Save the current server and set server with this one.
			 */
			oldSvr = msg.getServerName();
			String ns = cmd.substring(idx+1);
			cmd = cmd.substring(0,idx);
			msg.setServer(ns);
		}

		try {
			/*
			Reverse lookup is not recommended.  This code manages a domain
			request for ip addresses in the manner described by RFC 1034.
			 */
			if( cmd.length() > 0 && Character.isDigit(cmd.charAt(0)) ) {
				//If an ip address lookup is request, ask for PTR records
				ans = query(msg,cmd,PTR,dnsClass);
			} else {
				//  Otherwise, ask for the requested type
				ans = query(msg,cmd,qtype,dnsClass);
			}
		} catch(InterruptedIOException ex) {
			out.println("No reply from server");
			if( oldSvr != null ) {
				msg.setServer(oldSvr);
			}
			return;
		}
		if( oldSvr != null ) {
			msg.setServer(oldSvr);
		}

		int rcode = ans.getResponseCode();
		if( rcode != NOERROR ) {
			out.println(ERRORNAMES[rcode]);
			return;
		}

		out.println("Answer for "+lastName+" "+msg.getAddress(lastName));
		if( ans.isAuthority() ) {
			out.println("Authoritative answer:");
		} else {
			out.println("Non-authoritative answer:");
		}
		out.println("Answer count = "+ans.getAnswerCount());
		for(Iterator<RR> e=ans.answer(); e.hasNext(); ) {
			out.println(e.next().toString());
		}
		if( !ans.isAuthority() ) {
			out.println("\nAuthoritative answer can be found at:");
		}
		out.println("Auth count = "+ans.getAuthority().size());
		for(Iterator<RR> e=ans.authority(); e.hasNext(); ) {
			out.println(e.next().toString());
		}
		out.println("Additional count = "+ans.getAdditionalCount());
		for(Iterator<RR> e=ans.additional(); e.hasNext(); ) {
			out.println(e.next().toString());
		}
	}
}
