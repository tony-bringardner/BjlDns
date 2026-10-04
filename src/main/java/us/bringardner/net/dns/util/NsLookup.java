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

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.Reader;
import java.io.StringReader;
import java.net.ConnectException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.PortUnreachableException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import us.bringardner.core.BjlLogger;
import us.bringardner.core.ILogger;
import us.bringardner.net.dns.A;
import us.bringardner.net.dns.ByteBuffer;
import us.bringardner.net.dns.Cname;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.Mx;
import us.bringardner.net.dns.Ns;
import us.bringardner.net.dns.Ptr;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.Rp;
import us.bringardner.net.dns.Section;
import us.bringardner.net.dns.Soa;
import us.bringardner.net.dns.Srv;
import us.bringardner.net.dns.Utility;
import us.bringardner.core.util.Hex;

/**
 * A work-alike of the Linux (ISC BIND 9) nslookup: the same command line,
 * interactive commands, options, output and exit status.
 *
 * <pre>
 * nslookup [-option ...]              interactive, using the default server
 * nslookup [-option ...] - server     interactive, using 'server'
 * nslookup [-option ...] host         look up 'host' using the default server
 * nslookup [-option ...] host server  look up 'host' using 'server'
 * </pre>
 *
 * The default servers, search list, ndots, timeout and attempts come from
 * resolv.conf ({@value #DEFAULT_RESOLV_CONF}, or the file named by the
 * {@value #PROP_RESOLV_CONF} property); without one, the servers Java
 * finds for the platform are used, and as a last resort a root server.
 * <p>
 * Interactive commands: {@code host [server]}, {@code server name},
 * {@code lserver name}, {@code set option}, {@code help} or {@code ?},
 * {@code exit} (or {@code quit}). Options (also as {@code -option} on the
 * command line; a unique prefix is enough, as in nslookup):
 * {@code all}, {@code class=}, {@code type=} / {@code querytype=},
 * {@code domain=}, {@code srchlist=a/b/c}, {@code port=}, {@code timeout=},
 * {@code retry=}, {@code ndots=}, {@code [no]debug}, {@code [no]d2},
 * {@code [no]recurse}, {@code [no]search} ({@code [no]defname}),
 * {@code [no]vc}, {@code [no]fail}.
 * <p>
 * Exit status 1 if a lookup failed (an error answer such as NXDOMAIN, or no
 * server could be reached), else 0.
 */
public class NsLookup extends Utility {

	/** resolv.conf to read the default servers and search list from. */
	public static final String PROP_RESOLV_CONF = "JDns.resolvConf";
	public static final String DEFAULT_RESOLV_CONF = "/etc/resolv.conf";

	/** Seconds per try when no timeout is set (as dig/nslookup). */
	static final int UDP_TIMEOUT = 5;
	static final int TCP_TIMEOUT = 10;

	static final String VERSION = "nslookup BjlDns";

	/** Text before the rdata, per type (BIND nslookup, types 0-41). */
	private static final String [] RTYPETEXT = {
			"rtype_0 = ", "internet address = ", "nameserver = ", "md = ", "mf = ",
			"canonical name = ", "soa = ", "mb = ", "mg = ", "mr = ",
			"rtype_10 = ", "protocol = ", "name = ", "hinfo = ", "minfo = ",
			"mail exchanger = ", "text = ", "rp = ", "afsdb = ", "x25 address = ",
			"isdn address = ", "rt = ", "nsap = ", "nsap_ptr = ", "signature = ",
			"key = ", "px = ", "gpos = ", "has AAAA address ", "loc = ",
			"next = ", "rtype_31 = ", "rtype_32 = ", "service = ", "rtype_34 = ",
			"naptr = ", "kx = ", "cert = ", "v6 address = ", "dname = ",
			"rtype_40 = ", "optional = "
	};

	private static final String [] RCODETEXT = {
			"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED",
			"YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE", "RESERVED11",
			"RESERVED12", "RESERVED13", "RESERVED14", "RESERVED15", "BADVERS"
	};

	static final String help =
			"Commands:       (identifiers are shown in uppercase, [] means optional)\n"+
			"NAME            - print info about the host/domain NAME using default server\n"+
			"NAME1 NAME2     - as above, but use NAME2 as server\n"+
			"help or ?       - print info on common commands\n"+
			"set OPTION      - set an option\n"+
			"    all                 - print options, current server and host\n"+
			"    [no]debug           - print debugging information\n"+
			"    [no]d2              - print exhaustive debugging information\n"+
			"    [no]recurse         - ask for recursive answer to query\n"+
			"    [no]search          - use domain search list\n"+
			"    [no]defname         - synonym for [no]search\n"+
			"    [no]vc              - always use a virtual circuit (TCP)\n"+
			"    [no]fail            - [do not] try the next server on SERVFAIL\n"+
			"    domain=NAME         - set default domain name to NAME\n"+
			"    srchlist=N1[/N2/...] - set the search list to N1, N2, ...\n"+
			"    ndots=X             - names with fewer dots use the search list first\n"+
			"    retry=X             - set number of retries to X\n"+
			"    timeout=X           - set initial time-out interval to X seconds\n"+
			"    type=X              - set query type, e.g., A,AAAA,ANY,CNAME,MX,NS,PTR,SOA,SRV,TXT\n"+
			"    querytype=X         - same as type\n"+
			"    class=X             - set query class to one of IN (Internet), CH (Chaos), HS (Hesiod) or ANY\n"+
			"    port=X              - set port number to send query on\n"+
			"server NAME     - set default server to NAME\n"+
			"lserver NAME    - set default server to NAME\n"+
			"exit            - exit the program\n";

	/** A server: the name as given, and one of its addresses. */
	static class Server {
		final String userarg;
		final InetAddress address;

		Server(String userarg, InetAddress address) {
			this.userarg = userarg;
			this.address = address;
		}
	}

	/** A response and the server it came from. */
	static class Response {
		final Message msg;
		final Server server;

		Response(Message msg, Server server) {
			this.msg = msg;
			this.server = server;
		}
	}

	/** Why a query got no answer: not reachable. */
	private static class CommunicationsError extends IOException {
		private static final long serialVersionUID = 1L;
		/** A TCP connection could not be made (nslookup reports it differently). */
		final boolean connect;

		CommunicationsError(String why) {
			this(why, false);
		}

		CommunicationsError(String why, boolean connect) {
			super(why);
			this.connect = connect;
		}
	}

	private static final SecureRandom ID_RANDOM = new SecureRandom();

	//  I/O (settable for tests and embedding)
	static Message msg = new Message();
	static PrintStream out = System.out;
	static PrintStream err = System.err;
	static BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
	/** Print the prompt: null = only when stdin is a terminal. */
	static Boolean interactive = null;
	/** Echo each command after the prompt (for tests: the output reads like a session). */
	static boolean echoCommand = false;

	//  Settings (reset by run())
	static List<Server> servers = new ArrayList<Server>();
	static List<Server> initialServers = new ArrayList<Server>();
	/** The servers are the system's (not given): try the next one if recursion is not available. */
	static boolean checkRa = true;
	static int port = DNSPORT;
	static int timeout = 0;
	static int tries = 3;
	static int ndots = 1;
	static boolean vc = false;
	static boolean vcSet = false;
	static boolean debug = false;
	static boolean d2 = false;
	static boolean search = true;
	static boolean recurse = true;
	static boolean fail = true;
	static String deftype = "A";
	static boolean defaultLookups = true;
	static String defclass = "IN";
	static List<String> searchList = new ArrayList<String>();

	//  Status
	static boolean queryError = true;
	static boolean printError = false;
	static boolean aNoAnswer = false;

	public NsLookup() {
		super();
	}

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

	public static void setErr(PrintStream err) {
		NsLookup.err = err;
	}

	public static BufferedReader getIn() {
		return in;
	}

	public static void setIn(BufferedReader in) {
		NsLookup.in = in;
	}

	/** Show the "> " prompt (null: only when stdin is a terminal). */
	public static void setInteractive(Boolean interactive) {
		NsLookup.interactive = interactive;
	}

	public static void setEchoCommand(boolean echo) {
		NsLookup.echoCommand = echo;
	}

	public static int getQtype() {
		return typeCode(deftype);
	}

	public static void setQtype(int qtype) {
		deftype = typeName(qtype);
		defaultLookups = false;
	}

	public static int getDnsClass() {
		return classCode(defclass);
	}

	public static void setDnsClass(int dnsClass) {
		defclass = className(dnsClass);
	}

	public static String getHelp() {
		return help;
	}

	public static void showHelp() {
		out.print(help);
	}

	public static void main(String[] args) {
		System.exit(run(args));
	}

	/**
	 * Run nslookup (main() without System.exit()).
	 * @return the exit status: 1 if a lookup failed, else 0
	 */
	public static int run(String[] args) {
		reset();
		echoCommand = echoCommand || Boolean.getBoolean("echoCommand");
		loadResolvConf();

		String lookup = null;
		boolean haveLookup = false;
		for(int idx=0; idx < args.length; idx++ ) {
			String a = args[idx];
			if( a.startsWith("-") ) {
				if( a.regionMatches(true, 0, "-ver", 0, 4) ) {
					err.println(VERSION);
					return 0;
				} else if( a.length() > 1 ) {
					setOption(a.substring(1));
				} else {
					haveLookup = true;
				}
			} else if( !haveLookup ) {
				haveLookup = true;
				lookup = a;
			} else {
				if( idx+1 < args.length ) {
					usage();
					return 1;
				}
				List<Server> list = resolveServer(a);
				if( list == null ) {
					err.println("nslookup: couldn't get address for '"+a+"': not found");
					return 1;
				}
				servers = list;
				checkRa = false;
			}
		}
		if( servers.isEmpty() ) {
			servers = platformServers();
		}
		initialServers = servers;

		if( lookup != null ) {
			lookup(lookup, null);
		} else {
			interactiveLoop();
		}
		out.println();
		out.flush();
		return (queryError ? 1 : 0) | (printError ? 1 : 0);
	}

	private static void usage() {
		err.println("Usage:");
		err.println("   nslookup [-opt ...]             # interactive mode using default server");
		err.println("   nslookup [-opt ...] - server    # interactive mode using 'server'");
		err.println("   nslookup [-opt ...] host        # just look up 'host' using default server");
		err.println("   nslookup [-opt ...] host server # just look up 'host' using 'server'");
	}

	/** Back to the defaults (the state is static, and tests run several sessions). */
	static void reset() {
		servers = new ArrayList<Server>();
		initialServers = servers;
		checkRa = true;
		port = DNSPORT;
		timeout = 0;
		tries = 3;
		ndots = 1;
		vc = false;
		vcSet = false;
		debug = false;
		d2 = false;
		search = true;
		recurse = true;
		fail = true;
		deftype = "A";
		defaultLookups = true;
		defclass = "IN";
		searchList = new ArrayList<String>();
		queryError = true;
		printError = false;
		aNoAnswer = false;
		msg.debugOff();
	}

	private static void interactiveLoop() {
		boolean prompt = interactive != null ? interactive : System.console() != null;
		try {
			while( true ) {
				if( prompt ) {
					out.print("> ");
					out.flush();
				}
				String line = in.readLine();
				if( line == null ) {
					break;
				}
				if( echoCommand ) {
					out.println(line);
				}
				if( !command(line) ) {
					break;
				}
			}
		} catch(IOException ex) {
			out.println(";; "+ex.getMessage());
		}
	}

	/**
	 * Run one interactive command.
	 * @return false to exit
	 */
	public static boolean command(String line) {
		String [] tok = line.trim().split("\\s+");
		if( tok.length == 0 || tok[0].isEmpty() ) {
			return true;
		}
		String cmd = tok[0];
		String arg = tok.length > 1 ? tok[1] : null;
		if( cmd.equalsIgnoreCase("set") && arg != null ) {
			setOption(arg);
		} else if( cmd.equalsIgnoreCase("server") || cmd.equalsIgnoreCase("lserver") ) {
			if( arg != null ) {
				List<Server> list = resolveServer(arg);
				if( list == null ) {
					out.println("nslookup: couldn't get address for '"+arg+"': not found");
					return true;
				}
				servers = list;
				checkRa = false;
			}
			showSettings(true, true);
		} else if( cmd.equalsIgnoreCase("exit") || cmd.equalsIgnoreCase("quit") ) {
			return false;
		} else if( cmd.equalsIgnoreCase("help") || cmd.equals("?") ) {
			showHelp();
		} else if( cmd.equalsIgnoreCase("finger") || cmd.equalsIgnoreCase("root")
				|| cmd.equalsIgnoreCase("ls") || cmd.equalsIgnoreCase("view") ) {
			out.println("The '"+cmd+"' command is not implemented.");
		} else {
			lookup(cmd, arg);
		}
		return true;
	}

	/** Is 'opt' an abbreviation (at least min characters) of 'full'? */
	private static boolean abbrev(String opt, String full, int min) {
		return opt.length() >= min && opt.length() <= full.length() && full.regionMatches(true, 0, opt, 0, opt.length());
	}

	/** The value of "name=value" if opt starts with one of the prefixes (e.g. "type=", "ty="). */
	private static String value(String opt, String ... prefixes) {
		for(String p : prefixes) {
			if( opt.regionMatches(true, 0, p, 0, p.length()) ) {
				return opt.substring(p.length());
			}
		}
		return null;
	}

	/** A "set" option (or a -option on the command line). */
	public static void setOption(String opt) {
		String v;
		if( abbrev(opt, "all", 3) ) {
			showSettings(true, false);
		} else if( (v=value(opt, "class=", "cl=")) != null ) {
			if( classCode(v) < 0 ) {
				out.println("unknown query class: "+v);
			} else {
				defclass = v;
			}
		} else if( (v=value(opt, "type=", "ty=", "querytype=", "query=", "qu=", "q=")) != null ) {
			if( typeCode(v) < 0 ) {
				out.println("unknown query type: "+v);
			} else {
				deftype = v;
				defaultLookups = false;
			}
		} else if( (v=value(opt, "domain=", "do=")) != null ) {
			searchList = new ArrayList<String>();
			if( !v.isEmpty() ) {
				searchList.add(stripDot(v));
			}
			search = true;
		} else if( (v=value(opt, "srchlist=", "srch=")) != null ) {
			searchList = new ArrayList<String>();
			for(String s : v.split("/")) {
				if( !s.isEmpty() ) {
					searchList.add(stripDot(s));
				}
			}
			search = true;
		} else if( (v=value(opt, "port=", "po=")) != null ) {
			Integer n = number(v, 65535, "port");
			if( n != null ) {
				port = n;
			}
		} else if( (v=value(opt, "timeout=", "t=")) != null ) {
			Integer n = number(v, Integer.MAX_VALUE, "timeout");
			if( n != null ) {
				timeout = n;
			}
		} else if( abbrev(opt, "recurse", 3) ) {
			recurse = true;
		} else if( abbrev(opt, "norecurse", 5) ) {
			recurse = false;
		} else if( (v=value(opt, "retry=", "ret=")) != null ) {
			Integer n = number(v, Integer.MAX_VALUE, "tries");
			if( n != null ) {
				tries = n;
			}
		} else if( abbrev(opt, "defname", 3) ) {
			search = true;
		} else if( abbrev(opt, "nodefname", 5) ) {
			search = false;
		} else if( abbrev(opt, "vc", 2) ) {
			vc = true;
			vcSet = true;
		} else if( abbrev(opt, "novc", 4) ) {
			vc = false;
			vcSet = true;
		} else if( abbrev(opt, "debug", 3) ) {
			debug = true;
		} else if( abbrev(opt, "nodebug", 5) ) {
			debug = false;
		} else if( abbrev(opt, "d2", 2) ) {
			d2 = true;
			msg.debugOn();
		} else if( abbrev(opt, "nod2", 4) ) {
			d2 = false;
			msg.debugOff();
		} else if( abbrev(opt, "search", 3) ) {
			search = true;
		} else if( abbrev(opt, "nosearch", 5) ) {
			search = false;
		} else if( abbrev(opt, "sil", 3) ) {
			//  (silence the deprecation message: there is none)
		} else if( abbrev(opt, "fail", 3) ) {
			fail = true;
		} else if( abbrev(opt, "nofail", 5) ) {
			fail = false;
		} else if( (v=value(opt, "ndots=")) != null ) {
			Integer n = number(v, 128, "ndots");
			if( n != null ) {
				ndots = n;
			}
		} else {
			out.println("*** Invalid option: "+opt);
		}
	}

	private static Integer number(String v, int max, String what) {
		try {
			long n = Long.parseLong(v.trim());
			if( n >= 0 && n <= max ) {
				return (int)n;
			}
			out.println("value out of range: "+what+"="+v);
		} catch(NumberFormatException ex) {
			out.println("invalid "+what+": "+v);
		}
		return null;
	}

	/** "set all", and the server lines after "server". */
	static void showSettings(boolean full, boolean serverOnly) {
		for(Server s : servers) {
			out.println("Default server: "+s.userarg);
			out.println("Address: "+sockaddr(s.address, port));
			if( !full ) {
				return;
			}
		}
		if( serverOnly ) {
			return;
		}
		out.println();
		out.println("Set options:");
		out.println("  "+(vc ? "vc" : "novc")+"\t\t\t"+(debug ? "debug" : "nodebug")+"\t\t"+(d2 ? "d2" : "nod2"));
		out.println("  "+(search ? "search" : "nosearch")+"\t\t"+(recurse ? "recurse" : "norecurse"));
		out.println("  timeout = "+timeout+"\t\tretry = "+tries+"\tport = "+port+"\tndots = "+ndots);
		out.println("  querytype = "+String.format("%-8s", deftype)+"\tclass = "+defclass);
		out.println("  srchlist = "+String.join("/", searchList));
	}

	//  ------------------------------------------------------------------
	//  Servers

	/** The addresses of a server given by name or address, or null. */
	static List<Server> resolveServer(String name) {
		try {
			List<Server> ret = new ArrayList<Server>();
			for(InetAddress a : InetAddress.getAllByName(name)) {
				ret.add(new Server(name, a));
			}
			return ret.isEmpty() ? null : ret;
		} catch(UnknownHostException | SecurityException ex) {
			return null;
		}
	}

	/** resolv.conf: servers, search list, ndots, timeout and attempts. */
	static void loadResolvConf() {
		String path = System.getProperty(PROP_RESOLV_CONF, DEFAULT_RESOLV_CONF);
		File f = new File(path);
		if( !f.canRead() ) {
			return;
		}
		try(Reader r = new FileReader(f)) {
			applyResolvConf(r);
		} catch(IOException ex) {
			err.println("nslookup: can't read "+path+": "+ex.getMessage());
		}
	}

	/** Apply the settings of a resolv.conf (see resolv.conf(5)). */
	static void applyResolvConf(Reader r) throws IOException {
		BufferedReader br = new BufferedReader(r);
		String line;
		List<Server> list = new ArrayList<Server>();
		while( (line=br.readLine()) != null ) {
			int hash = line.indexOf('#');
			if( hash >= 0 ) {
				line = line.substring(0, hash);
			}
			int semi = line.indexOf(';');
			if( semi >= 0 ) {
				line = line.substring(0, semi);
			}
			String [] tok = line.trim().split("\\s+");
			if( tok.length < 2 ) {
				continue;
			}
			String key = tok[0].toLowerCase(Locale.ROOT);
			if( key.equals("nameserver") ) {
				String a = tok[1];
				//  An address only, so this never waits for a name lookup
				if( isAddressLiteral(a) ) {
					try {
						list.add(new Server(a, InetAddress.getByName(a)));
					} catch(UnknownHostException ex) {
						//  (skip it)
					}
				}
			} else if( key.equals("domain") ) {
				searchList = new ArrayList<String>();
				searchList.add(stripDot(tok[1]));
			} else if( key.equals("search") ) {
				searchList = new ArrayList<String>();
				for(int i=1; i < tok.length; i++ ) {
					searchList.add(stripDot(tok[i]));
				}
			} else if( key.equals("options") ) {
				for(int i=1; i < tok.length; i++ ) {
					String [] kv = tok[i].split(":", 2);
					if( kv.length != 2 ) {
						continue;
					}
					try {
						int n = Integer.parseInt(kv[1]);
						if( kv[0].equals("ndots") ) {
							ndots = Math.min(n, 15);
						} else if( kv[0].equals("timeout") ) {
							timeout = n;
						} else if( kv[0].equals("attempts") ) {
							tries = n == 0 ? 3 : n;
						}
					} catch(NumberFormatException ex) {
						//  (ignore it)
					}
				}
			}
		}
		if( list.isEmpty() ) {
			//  resolv.conf without a name server means this host (resolv.conf(5))
			list.add(new Server("127.0.0.1", InetAddress.getByName("127.0.0.1")));
		}
		servers = list;
	}

	/** Test hook: apply resolv.conf text. */
	static void applyResolvConf(String text) throws IOException {
		applyResolvConf(new StringReader(text));
	}

	private static boolean isAddressLiteral(String a) {
		return a.matches("[0-9]{1,3}(\\.[0-9]{1,3}){3}") || (a.indexOf(':') >= 0 && a.matches("[0-9A-Fa-f:.]+(%[0-9A-Za-z_.-]+)?"));
	}

	/** Without resolv.conf: the servers Java finds (Windows), else a root server. */
	static List<Server> platformServers() {
		List<Server> ret = new ArrayList<Server>();
		try {
			Hashtable<String,String> env = new Hashtable<String,String>();
			env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
			javax.naming.directory.DirContext ctx = new javax.naming.directory.InitialDirContext(env);
			Object url = ctx.getEnvironment().get("java.naming.provider.url");
			ctx.close();
			if( url != null ) {
				for(String u : url.toString().split("\\s+")) {
					Matcher m = Pattern.compile("dns://\\[?([^\\]/]+?)\\]?(?::\\d+)?(/.*)?").matcher(u);
					if( m.matches() && isAddressLiteral(m.group(1)) ) {
						ret.add(new Server(m.group(1), InetAddress.getByName(m.group(1))));
					}
				}
			}
		} catch(Exception | LinkageError ex) {
			//  (no JNDI DNS provider)
		}
		if( ret.isEmpty() ) {
			try {
				String root = getDnsServer();
				if( root != null ) {
					ret.add(new Server(root, InetAddress.getByName(root)));
				}
			} catch(IOException ex) {
				//  (nothing reachable)
			}
		}
		return ret;
	}

	/**
	 * The first root server that answers (a-m.root-servers.net), or null.
	 * (Used when there is no other name server.)
	 */
	public static String getDnsServer() throws IOException {
		String ret = null;
		for(int ch='a'; ch <= 'm'; ch++ ) {
			String tmp  = (char)ch+".root-servers.net";
			try {
				Message m = new Message();
				m.setServer(tmp);
				Message a = m.query(tmp);
				if( a != null && a.getResponseCode() == DNS.NOERROR) {
					ret = tmp;
					break;
				}
			} catch(IOException ex) {
				//  (try the next one)
			}
		}
		return ret;
	}

	//  ------------------------------------------------------------------
	//  Lookups

	/**
	 * Look up a name (or the PTR record of an address), as nslookup does:
	 * with the search list, then A and AAAA unless a type is set.
	 * @param serverName a server for this lookup only, or null
	 */
	public static void lookup(String name, String serverName) {
		List<Server> list = servers;
		if( serverName != null ) {
			list = resolveServer(serverName);
			if( list == null ) {
				out.println("nslookup: couldn't get address for '"+serverName+"': not found");
				return;
			}
		}
		if( list.isEmpty() ) {
			out.println(";; no servers could be reached");
			return;
		}
		boolean check = checkRa && serverName == null;
		aNoAnswer = false;

		int type;
		int cls = classCode(defclass);
		List<String> candidates = new ArrayList<String>();
		String reverse = reverseName(name);
		if( reverse != null ) {
			type = PTR;
			candidates.add(reverse);
		} else {
			type = typeCode(deftype);
			candidates.addAll(searchNames(name));
		}

		Response r = null;
		String qname = null;
		for(int i=0; i < candidates.size(); i++ ) {
			qname = candidates.get(i);
			r = send(qname, type, cls, list, check);
			if( r == null ) {
				return;
			}
			if( r.msg.getResponseCode() == NAME_ERROR && i+1 < candidates.size() ) {
				if( debug ) {
					printMessage(r, qname, name, type);
				}
				continue;
			}
			break;
		}
		String next = printMessage(r, qname, name, type);
		if( next != null ) {
			//  The AAAA half of a default lookup (for the name the CNAMEs lead to)
			Response r2 = send(next, AAAA, cls, list, check);
			if( r2 != null ) {
				printMessage(r2, next, next, AAAA);
			}
		}
	}

	/** The names to try for 'name', in order (resolv.conf rules, as dig). */
	static List<String> searchNames(String name) {
		List<String> ret = new ArrayList<String>();
		if( name.endsWith(".") ) {
			ret.add(name.length() > 1 ? name.substring(0, name.length()-1) : ".");
			return ret;
		}
		int dots = 0;
		for(char c : name.toCharArray()) {
			if( c == '.' ) {
				dots++;
			}
		}
		if( dots >= ndots || !search ) {
			ret.add(name);
		} else {
			for(String s : searchList) {
				ret.add(name+"."+s);
			}
			ret.add(name);
		}
		return ret;
	}

	/** in-addr.arpa / ip6.arpa name for an IPv4 or IPv6 address, else null. */
	static String reverseName(String text) {
		return us.bringardner.net.dns.ReverseName.of(text);
	}

	/**
	 * Print a response as nslookup does.
	 * @param qname the name asked
	 * @param textname the name as typed (for "Can't find")
	 * @return the name for the AAAA half of a default lookup, or null
	 */
	static String printMessage(Response r, String qname, String textname, int type) {
		Message m = r.msg;
		queryError = false;
		if( !defaultLookups || type == A ) {
			out.println("Server:\t\t"+r.server.userarg);
			out.println("Address:\t"+sockaddr(r.server.address, port));
			out.println();
		}
		if( debug ) {
			out.println("------------");
			detailSection("QUESTIONS:", m, null);
			detailSection("ANSWERS:", m, m.getAnswer());
			detailSection("AUTHORITY RECORDS:", m, m.getAuthority());
			detailSection("ADDITIONAL RECORDS:", m, m.getAdditional());
			out.println("------------");
		}
		int rcode = m.getResponseCode();
		if( rcode != NOERROR ) {
			out.println("** server can't find "+qname+": "+rcodeText(rcode));
			printError = true;
			return null;
		}
		String next = null;
		if( defaultLookups && type == A ) {
			next = chaseCnames(m, qname);
		}
		boolean aa = m.isAuthority();
		if( !aa && (!defaultLookups || type == A) ) {
			out.println("Non-authoritative answer:");
		}
		if( !m.getAnswer().isEmpty() ) {
			printSection(m.getAnswer(), true);
		} else if( defaultLookups && type == A ) {
			aNoAnswer = true;
		} else if( !defaultLookups || (type == AAAA && aNoAnswer) ) {
			out.println("*** Can't find "+textname+": No answer");
		}
		if( !aa && type != A && type != AAAA ) {
			out.println();
			out.println("Authoritative answers can be found from:");
			printSection(m.getAuthority(), false);
			printSection(m.getAdditional(), false);
		}
		return next;
	}

	/** Follow the CNAMEs from 'name' in the answer. */
	private static String chaseCnames(Message m, String name) {
		String cur = name;
		for(int i=0; i < m.getAnswer().size(); i++ ) {
			String next = null;
			for(RR rr : m.getAnswer()) {
				if( rr.getType() == CNAME && sameName(rr.getName(), cur) ) {
					next = stripDot(rdataText(rr));
					break;
				}
			}
			if( next == null ) {
				break;
			}
			cur = next;
		}
		return cur;
	}

	private static boolean sameName(String a, String b) {
		return stripDot(a).equalsIgnoreCase(stripDot(b));
	}

	/** A section, grouped by owner name and type (as BIND prints a message). */
	private static void printSection(List<RR> section, boolean answer) {
		for(RR rr : grouped(section)) {
			String owner = ownerText(rr.getName());
			int t = rr.getType();
			if( (t == A || t == AAAA) && answer ) {
				out.println("Name:\t"+owner);
				out.println("Address: "+rdataText(rr));
			} else if( t == SOA ) {
				out.println(owner);
				printSoa(rr);
			} else {
				out.println(owner+"\t"+rtypeText(t)+rdataText(rr));
			}
		}
	}

	private static void detailSection(String header, Message m, List<RR> section) {
		out.println("    "+header);
		if( section == null ) {
			for(Section q : m.getQuestion()) {
				out.println("\t"+ownerText(q.getName())+", type = "+typeName(q.getType())+", class = "+className(q.getDnsClass()));
			}
			return;
		}
		for(RR rr : grouped(section)) {
			out.println("    ->  "+ownerText(rr.getName()));
			if( rr.getType() == SOA ) {
				printSoa(rr);
			} else {
				out.println("\t"+rtypeText(rr.getType())+rdataText(rr));
			}
			out.println("\tttl = "+Integer.toUnsignedString(rr.getTTL()));
		}
	}

	private static void printSoa(RR rr) {
		if( rr instanceof Soa ) {
			Soa s = (Soa) rr;
			out.println("\torigin = "+ownerText(s.getMname()));
			out.println("\tmail addr = "+ownerText(s.getRname()));
			out.println("\tserial = "+Integer.toUnsignedString(s.getSerial()));
			out.println("\trefresh = "+Integer.toUnsignedString(s.getRefreash()));
			out.println("\tretry = "+Integer.toUnsignedString(s.getRetry()));
			out.println("\texpire = "+Integer.toUnsignedString(s.getExpire()));
			out.println("\tminimum = "+Integer.toUnsignedString(s.getMinimum()));
		} else {
			out.println("\t"+rtypeText(SOA)+rdataText(rr));
		}
	}

	/** Records in BIND's order: by owner name (first seen), then type (first seen); OPT and TSIG left out. */
	private static List<RR> grouped(List<RR> section) {
		Map<String,Map<Integer,List<RR>>> byName = new LinkedHashMap<String,Map<Integer,List<RR>>>();
		for(RR rr : section) {
			if( rr.getType() == OPT || rr.getType() == 250 ) {
				continue;
			}
			String key = stripDot(rr.getName()).toLowerCase(Locale.ROOT);
			Map<Integer,List<RR>> byType = byName.get(key);
			if( byType == null ) {
				byType = new LinkedHashMap<Integer,List<RR>>();
				byName.put(key, byType);
			}
			Integer t = rr.getType()*65536 + rr.getDnsClass();
			List<RR> set = byType.get(t);
			if( set == null ) {
				set = new ArrayList<RR>();
				byType.put(t, set);
			}
			set.add(rr);
		}
		List<RR> ret = new ArrayList<RR>();
		for(Map<Integer,List<RR>> byType : byName.values()) {
			for(List<RR> set : byType.values()) {
				ret.addAll(set);
			}
		}
		return ret;
	}

	//  ------------------------------------------------------------------
	//  Presentation format (as BIND prints it)

	static String rtypeText(int type) {
		return type >= 0 && type < RTYPETEXT.length ? RTYPETEXT[type] : "rdata_"+type+" = ";
	}

	static String rcodeText(int rcode) {
		return rcode < RCODETEXT.length ? RCODETEXT[rcode] : "?"+rcode;
	}

	/** An owner name: no trailing dot, "." for the root. */
	static String ownerText(String name) {
		String n = stripDot(name);
		return n.isEmpty() ? "." : n;
	}

	/** A name in rdata: absolute (trailing dot). */
	static String absolute(String name) {
		if( name == null || name.isEmpty() || name.equals(".") ) {
			return ".";
		}
		return name.endsWith(".") ? name : name+".";
	}

	static String stripDot(String name) {
		if( name == null ) {
			return "";
		}
		return name.length() > 1 && name.endsWith(".") ? name.substring(0, name.length()-1) : name;
	}

	/** The rdata of a record in presentation format. */
	static String rdataText(RR rr) {
		switch(rr.getType()) {
		case A:
			if( rr instanceof A ) {
				return ((A)rr).getAddressString();
			}
			break;
		case AAAA:
			if( rr.getRdata() != null && rr.getRdata().length == 16 ) {
				return ipv6Text(rr.getRdata());
			}
			break;
		case NS:
			if( rr instanceof Ns ) {
				return absolute(((Ns)rr).getNs());
			}
			break;
		case CNAME:
			if( rr instanceof Cname ) {
				return absolute(((Cname)rr).getCname());
			}
			break;
		case PTR:
			if( rr instanceof Ptr ) {
				return absolute(((Ptr)rr).getPtr());
			}
			break;
		case MX:
			if( rr instanceof Mx ) {
				Mx mx = (Mx) rr;
				return mx.getPref()+" "+absolute(mx.getExchange());
			}
			break;
		case SRV:
			if( rr instanceof Srv ) {
				Srv s = (Srv) rr;
				return s.getPriority()+" "+s.getWeight()+" "+s.getPort()+" "+absolute(s.getTarget());
			}
			break;
		case RP:
			if( rr instanceof Rp ) {
				Rp rp = (Rp) rr;
				return absolute(rp.getMboxDname())+" "+absolute(rp.getTxtDname());
			}
			break;
		case SOA:
			if( rr instanceof Soa ) {
				Soa s = (Soa) rr;
				return absolute(s.getMname())+" "+absolute(s.getRname())+" "+Integer.toUnsignedString(s.getSerial())
				+" "+Integer.toUnsignedString(s.getRefreash())+" "+Integer.toUnsignedString(s.getRetry())
				+" "+Integer.toUnsignedString(s.getExpire())+" "+Integer.toUnsignedString(s.getMinimum());
			}
			break;
		case HINFO:
		case TXT:
		case 99:	//  SPF
			if( rr.getRdata() != null ) {
				String s = characterStrings(rr.getRdata());
				if( s != null ) {
					return s;
				}
			}
			break;
		default:
			break;
		}
		if( rr.getClass() != RR.class ) {
			try {
				return rr.getRdataAsString();
			} catch(RuntimeException ex) {
				//  (fall back to the generic form)
			}
		}
		return generic(rr.getRdata());
	}

	/** RFC 3597 form: \# length hex. */
	static String generic(byte [] rdata) {
		if( rdata == null ) {
			rdata = new byte[0];
		}
		StringBuilder sb = new StringBuilder("\\# ").append(rdata.length);
		if( rdata.length > 0 ) {
			sb.append(' ');
			sb.append(Hex.encodeUpper(rdata));
		}
		return sb.toString();
	}

	/** One or more <character-string>s, quoted, separated by spaces; null if malformed. */
	static String characterStrings(byte [] rdata) {
		StringBuilder sb = new StringBuilder();
		int pos = 0;
		while( pos < rdata.length ) {
			int len = rdata[pos++] & 0xff;
			if( pos+len > rdata.length ) {
				return null;
			}
			if( sb.length() > 0 ) {
				sb.append(' ');
			}
			sb.append('"');
			for(int i=0; i < len; i++ ) {
				int c = rdata[pos+i] & 0xff;
				if( c == '"' || c == '\\' ) {
					sb.append('\\').append((char)c);
				} else if( c < 0x20 || c >= 0x7f ) {
					sb.append('\\').append(String.format("%03d", c));
				} else {
					sb.append((char)c);
				}
			}
			sb.append('"');
			pos += len;
		}
		return sb.toString();
	}

	/** RFC 5952 text of an IPv6 address (as inet_ntop). */
	static String ipv6Text(byte [] a) {
		int [] g = new int[8];
		for(int i=0; i < 8; i++ ) {
			g[i] = ((a[2*i] & 0xff) << 8) | (a[2*i+1] & 0xff);
		}
		//  IPv4-mapped and IPv4-compatible forms as inet_ntop prints them
		if( g[0]==0 && g[1]==0 && g[2]==0 && g[3]==0 && g[4]==0 && (g[5]==0xffff || (g[5]==0 && g[6]!=0)) ) {
			String v4 = (a[12]&0xff)+"."+(a[13]&0xff)+"."+(a[14]&0xff)+"."+(a[15]&0xff);
			return g[5]==0xffff ? "::ffff:"+v4 : "::"+v4;
		}
		int bestStart = -1, bestLen = 0;
		for(int i=0; i < 8; ) {
			if( g[i] == 0 ) {
				int j = i;
				while( j < 8 && g[j] == 0 ) {
					j++;
				}
				if( j-i > bestLen && j-i >= 2 ) {
					bestStart = i;
					bestLen = j-i;
				}
				i = j;
			} else {
				i++;
			}
		}
		StringBuilder sb = new StringBuilder();
		for(int i=0; i < 8; i++ ) {
			if( i == bestStart ) {
				sb.append("::");
				i += bestLen-1;
				continue;
			}
			if( sb.length() > 0 && sb.charAt(sb.length()-1) != ':' ) {
				sb.append(':');
			}
			sb.append(Integer.toHexString(g[i]));
		}
		return sb.toString();
	}

	/** address#port, as nslookup prints a server. */
	static String sockaddr(InetAddress a, int port) {
		String text;
		if( a instanceof Inet6Address ) {
			text = ipv6Text(a.getAddress());
			Inet6Address a6 = (Inet6Address) a;
			if( a6.getScopedInterface() != null ) {
				text += "%"+a6.getScopedInterface().getName();
			} else if( a6.getScopeId() != 0 ) {
				text += "%"+a6.getScopeId();
			}
		} else {
			text = a.getHostAddress();
		}
		return text+"#"+port;
	}

	//  ------------------------------------------------------------------
	//  Types and classes

	/** The code of a type name (A, MX, ANY, TYPE65534, ...), or -1. */
	static int typeCode(String name) {
		if( name == null || name.isEmpty() ) {
			return -1;
		}
		if( name.equalsIgnoreCase("ANY") || name.equals("*") ) {
			return QTYPE_ALL;
		}
		if( name.regionMatches(true, 0, "TYPE", 0, 4) && name.length() > 4 ) {
			try {
				int n = Integer.parseInt(name.substring(4));
				return n >= 0 && n <= 65535 ? n : -1;
			} catch(NumberFormatException ex) {
				return -1;
			}
		}
		for(int i=1; i < TYPENAMES.length; i++ ) {
			String t = TYPENAMES[i];
			if( !Character.isDigit(t.charAt(0)) && !t.equals("*") && t.equalsIgnoreCase(name) ) {
				return i;
			}
		}
		return -1;
	}

	/** The name of a type (TYPEnnn for one without a name). */
	static String typeName(int type) {
		if( type == QTYPE_ALL ) {
			return "ANY";
		}
		if( type > 0 && type < TYPENAMES.length && !Character.isDigit(TYPENAMES[type].charAt(0)) && !TYPENAMES[type].equals("*") ) {
			return TYPENAMES[type];
		}
		return "TYPE"+type;
	}

	/** The code of a class name (IN, CH/CHAOS, HS/HESIOD, NONE, ANY, CLASSnnn), or -1. */
	static int classCode(String name) {
		if( name == null ) {
			return -1;
		}
		String n = name.toUpperCase(Locale.ROOT);
		switch(n) {
		case "IN": return IN;
		case "CH": case "CHAOS": return 3;
		case "HS": case "HESIOD": return 4;
		case "NONE": return 254;
		case "ANY": return 255;
		default: break;
		}
		if( n.startsWith("CLASS") && n.length() > 5 ) {
			try {
				int c = Integer.parseInt(n.substring(5));
				return c >= 0 && c <= 65535 ? c : -1;
			} catch(NumberFormatException ex) {
				return -1;
			}
		}
		return -1;
	}

	static String className(int cls) {
		switch(cls) {
		case 1: return "IN";
		case 3: return "CH";
		case 4: return "HS";
		case 254: return "NONE";
		case 255: return "ANY";
		default: return "CLASS"+cls;
		}
	}

	//  ------------------------------------------------------------------
	//  Transport

	/**
	 * Send a query to the servers in turn ('tries' times each), printing a
	 * line for each failure.
	 * @return the response, or null (after ";; no servers could be reached")
	 */
	static Response send(String qname, int type, int cls, List<Server> list, boolean check) {
		boolean tcp = vc || (type == QTYPE_ALL && !vcSet);
		boolean reported = false;
		for(int s=0; s < list.size(); s++ ) {
			Server server = list.get(s);
			boolean last = s+1 == list.size();
			for(int t=0; t < Math.max(tries, 1); t++ ) {
				try {
					Message resp = exchange(qname, type, cls, server.address, tcp);
					if( resp.isTruncated() && !tcp ) {
						out.println(";; Truncated, retrying in TCP mode.");
						resp = exchange(qname, type, cls, server.address, true);
					}
					boolean servfail = resp.getResponseCode() == SERVER_ERROR && !fail;
					if( servfail || (check && recurse && !resp.isRecursiveAvailable()) ) {
						String why = servfail ? "SERVFAIL reply" : "recursion not available";
						if( !last ) {
							out.println(";; Got "+why+" from "+server.userarg+", trying next server");
							break;
						}
						out.println(";; Got "+why+" from "+server.userarg);
					}
					return new Response(resp, server);
				} catch(CommunicationsError ex) {
					if( ex.connect ) {
						//  (as nslookup: this pair of lines for every failed TCP connection)
						out.println(";; Connection to "+sockaddr(server.address, port)+"("+server.userarg+") for "+qname+" failed: "+ex.getMessage()+".");
						out.println(";; no servers could be reached");
						reported = true;
					} else {
						out.println(";; communications error to "+sockaddr(server.address, port)+": "+ex.getMessage());
						reported = false;
					}
				}
			}
		}
		if( !reported ) {
			out.println(";; no servers could be reached");
		}
		return null;
	}

	/** One query and its response. */
	static Message exchange(String qname, int type, int cls, InetAddress server, boolean tcp) throws CommunicationsError {
		Message q = new Message();
		q.setQuestion(qname.equals(".") ? "" : qname, type, cls);
		q.recursiveDesired(recurse);
		int id = ID_RANDOM.nextInt(0x10000);
		q.setID(id);
		byte [] data = q.toByteArray();
		int ms = 1000 * (timeout > 0 ? timeout : (tcp ? TCP_TIMEOUT : UDP_TIMEOUT));
		if( d2 ) {
			out.println(";; sending "+(tcp ? "TCP" : "UDP")+" query "+id+" for "+qname+" "+typeName(type)+" to "+sockaddr(server, port));
		}
		try {
			return tcp || data.length > MAX_UDP_PAYLOAD ? tcpExchange(q, id, data, server, ms) : udpExchange(q, id, data, server, ms);
		} catch(SocketTimeoutException ex) {
			throw new CommunicationsError("timed out");
		} catch(ConnectException ex) {
			throw new CommunicationsError("connection refused", true);
		} catch(PortUnreachableException ex) {
			throw new CommunicationsError("connection refused");
		} catch(IOException | RuntimeException ex) {
			//  (e.g. an IPv6 server without IPv6 networking)
			Throwable t = ex.getCause() != null && ex instanceof java.io.UncheckedIOException ? ex.getCause() : ex;
			throw new CommunicationsError(t.getMessage() == null ? t.toString() : t.getMessage());
		}
	}

	private static Message udpExchange(Message q, int id, byte [] data, InetAddress server, int ms) throws IOException {
		try(DatagramSocket sock = new DatagramSocket()) {
			//  Connected, so an ICMP port unreachable is reported (connection refused)
			sock.connect(server, port);
			sock.send(new DatagramPacket(data, data.length));
			long deadline = System.currentTimeMillis()+ms;
			byte [] buf = new byte[65535];
			while( true ) {
				long remaining = deadline-System.currentTimeMillis();
				if( remaining <= 0 ) {
					throw new SocketTimeoutException();
				}
				sock.setSoTimeout((int)remaining);
				DatagramPacket p = new DatagramPacket(buf, buf.length);
				sock.receive(p);
				Message m;
				try {
					m = new Message(new ByteBuffer(Arrays.copyOf(buf, p.getLength())));
				} catch(RuntimeException ex) {
					continue;
				}
				if( q.isResponseTo(m, id) ) {
					return m;
				}
			}
		}
	}

	private static Message tcpExchange(Message q, int id, byte [] data, InetAddress server, int ms) throws IOException {
		try(Socket sock = new Socket()) {
			sock.connect(new InetSocketAddress(server, port), ms);
			sock.setSoTimeout(ms);
			OutputStream os = sock.getOutputStream();
			ByteArrayOutputStream bo = new ByteArrayOutputStream();
			bo.write(data.length >> 8);
			bo.write(data.length);
			bo.write(data);
			os.write(bo.toByteArray());
			os.flush();
			InputStream is = sock.getInputStream();
			DataInputStream din = new DataInputStream(is);
			int len = din.readUnsignedShort();
			byte [] resp = new byte[len];
			din.readFully(resp);
			Message m;
			try {
				m = new Message(new ByteBuffer(resp));
			} catch(RuntimeException ex) {
				throw new IOException("malformed response");
			}
			if( !q.isResponseTo(m, id) ) {
				throw new IOException("response does not match the query");
			}
			return m;
		}
	}
}
