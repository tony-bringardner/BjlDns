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
package us.bringardner.net.dns.util;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.ConnectException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.PortUnreachableException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
import us.bringardner.net.dns.Tsig;
import us.bringardner.net.dns.Utility;
import us.bringardner.net.dns.server.Zone;

/**
 * A work-alike of the ISC BIND 9 nsupdate (RFC 2136 dynamic update): the
 * same command line, commands, output and exit status.
 *
 * <pre>
 * nsupdate [-dDi] [-L level] [-l] [-y [hmac:]keyname:secret | -k keyfile]
 *          [-p port] [-t timeout] [-u udptimeout] [-r udpretries] [-v]
 *          [-C resolv.conf] [-V] [-4 | -6] [filename]
 * </pre>
 *
 * Commands: {@code server}, {@code local}, {@code zone}, {@code class},
 * {@code ttl}, {@code key}, {@code check-names}, {@code [prereq] nxdomain |
 * yxdomain | nxrrset | yxrrset}, {@code [update] add | del[ete]},
 * {@code show}, {@code send} (or a blank line), {@code answer},
 * {@code debug}, {@code version}, {@code help}, {@code quit}.
 * <p>
 * Without {@code server} and {@code zone} the zone and its primary server
 * are found with an SOA query to the servers in resolv.conf, as nsupdate
 * does. Requests are signed with TSIG when a key is given (-y, -k, or the
 * key command). Exit status: 0, 1 for a syntax or setup error, 2 when an
 * update failed.
 */
public class NsUpdate extends Utility {

	public static final String VERSION = "BjlDns";
	/** The session key named writes for "nsupdate -l". */
	public static final String SESSION_KEYFILE = "/var/run/named/session.key";

	static final int STATUS_MORE = 0;
	static final int STATUS_SEND = 1;
	static final int STATUS_QUIT = 2;
	static final int STATUS_SYNTAX = 3;

	static final long TTL_MAX = 2147483647L;
	static final int CLASS_NONE = 254;
	static final int CLASS_ANY = 255;
	static final int OPCODE_UPDATE = 5;
	static final int MAX_SERVERADDRS = 4;

	/** Thrown to end the program with a status (fatal errors, as _exit). */
	static class Exit extends RuntimeException {
		private static final long serialVersionUID = 1L;
		final int status;

		Exit(int status) {
			super(null, null, false, false);
			this.status = status;
		}
	}

	/** A request that got no answer. */
	static class CommunicationsError extends IOException {
		private static final long serialVersionUID = 1L;

		CommunicationsError(String why) {
			super(why);
		}
	}

	/** An answer and its wire form. */
	static class Reply {
		final Message msg;
		final byte [] wire;

		Reply(Message msg, byte [] wire) {
			this.msg = msg;
			this.wire = wire;
		}
	}

	private static final SecureRandom ID_RANDOM = new SecureRandom();

	//  I/O
	static PrintStream out = System.out;
	static PrintStream err = System.err;
	static BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
	/** Prompt with "> ": null = when stdin is a terminal. */
	static Boolean interactiveDefault = null;

	//  Settings
	static int dnsport = DNSPORT;
	static boolean debugging;
	static boolean ddebugging;
	static boolean usevc;
	static boolean localOnly;
	static boolean interactive;
	static boolean seenError;
	static int timeout = 300;
	static int udpTimeout = 3;
	static int udpRetries = 3;
	static int defaultClass = IN;
	/** -1 until a class is used ("none") */
	static int zoneClass = -1;
	static long defaultTtl;
	static boolean defaultTtlSet;
	static boolean checkNames = true;
	static String resolvConf = "/etc/resolv.conf";
	static List<InetSocketAddress> servers = new ArrayList<InetSocketAddress>();
	static boolean defaultServers = true;
	static int nsInUse;
	static List<InetSocketAddress> primaryServers = new ArrayList<InetSocketAddress>();
	static int primaryInUse;
	static String userZone;
	static Tsig.Key tsigKey;
	static String keyFile;
	static String keyStr;
	static InetAddress localAddr4;
	static int localPort4;
	static InetAddress localAddr6;
	static int localPort6;
	static boolean haveIpv4 = true;
	static boolean haveIpv6;

	//  The update being built
	static List<RR> prereqs = new ArrayList<RR>();
	static List<RR> updates = new ArrayList<RR>();
	/** The last answer to an update (for "answer") */
	static Reply answer;

	public static void setOut(PrintStream out) {
		NsUpdate.out = out;
	}

	public static void setErr(PrintStream err) {
		NsUpdate.err = err;
	}

	public static void setIn(BufferedReader in) {
		NsUpdate.in = in;
	}

	/** Show the "> " prompt (null: only when stdin is a terminal). */
	public static void setInteractive(Boolean interactive) {
		NsUpdate.interactiveDefault = interactive;
	}

	public static void main(String[] args) {
		System.exit(run(args));
	}

	/**
	 * Run nsupdate (main() without System.exit()).
	 * @return the exit status: 0, 1 (syntax or setup error) or 2 (an update failed)
	 */
	public static int run(String[] args) {
		reset();
		try {
			preParseArgs(args);
			parseArgs(args);
			setupSystem();
			while( true ) {
				resetMessage();
				if( !userInteraction() ) {
					break;
				}
				startUpdate();
			}
			return seenError ? 2 : 0;
		} catch(Exit e) {
			return e.status;
		} finally {
			out.flush();
			err.flush();
		}
	}

	static void reset() {
		dnsport = DNSPORT;
		debugging = false;
		ddebugging = false;
		usevc = false;
		localOnly = false;
		interactive = interactiveDefault != null ? interactiveDefault : System.console() != null;
		seenError = false;
		timeout = 300;
		udpTimeout = 3;
		udpRetries = 3;
		defaultClass = IN;
		zoneClass = -1;
		defaultTtl = 0;
		defaultTtlSet = false;
		checkNames = true;
		resolvConf = "/etc/resolv.conf";
		servers = new ArrayList<InetSocketAddress>();
		defaultServers = true;
		nsInUse = 0;
		primaryServers = new ArrayList<InetSocketAddress>();
		primaryInUse = 0;
		userZone = null;
		tsigKey = null;
		keyFile = null;
		keyStr = null;
		localAddr4 = null;
		localAddr6 = null;
		answer = null;
		haveIpv4 = true;
		haveIpv6 = probeIpv6();
		resetMessage();
	}

	private static boolean probeIpv6() {
		try(DatagramSocket s = new DatagramSocket(new InetSocketAddress(InetAddress.getByName("::1"), 0))) {
			return true;
		} catch(Exception ex) {
			return false;
		}
	}

	static void resetMessage() {
		prereqs = new ArrayList<RR>();
		updates = new ArrayList<RR>();
	}

	static void fatal(String text) {
		err.println(text);
		throw new Exit(1);
	}

	static void error(String text) {
		err.println(text);
	}

	static void debug(String text) {
		if( debugging ) {
			err.println(text);
		}
	}

	static void ddebug(String text) {
		if( ddebugging ) {
			err.println(text);
		}
	}

	//  ------------------------------------------------------------------
	//  Command line

	private static final String OPTIONS = "46C:dDghilL:Mok:p:Pr:R:t:Tu:vVy:";

	/** A getopt(3) parse: the options in order, then the remaining arguments. */
	static class Opt {
		final char ch;
		final String arg;

		Opt(char ch, String arg) {
			this.ch = ch;
			this.arg = arg;
		}
	}

	static int argIndex;

	static List<Opt> getopt(String [] args) {
		List<Opt> ret = new ArrayList<Opt>();
		int i = 0;
		for(; i < args.length; i++ ) {
			String a = args[i];
			if( !a.startsWith("-") || a.equals("-") ) {
				break;
			}
			if( a.equals("--") ) {
				i++;
				break;
			}
			for(int j=1; j < a.length(); j++ ) {
				char c = a.charAt(j);
				int pos = OPTIONS.indexOf(c);
				if( pos < 0 || c == ':' ) {
					ret.add(new Opt('?', String.valueOf(c)));
					continue;
				}
				if( pos+1 < OPTIONS.length() && OPTIONS.charAt(pos+1) == ':' ) {
					String arg;
					if( j+1 < a.length() ) {
						arg = a.substring(j+1);
					} else if( i+1 < args.length ) {
						arg = args[++i];
					} else {
						ret.add(new Opt(':', String.valueOf(c)));
						break;
					}
					ret.add(new Opt(c, arg));
					break;
				}
				ret.add(new Opt(c, null));
			}
		}
		argIndex = i;
		return ret;
	}

	private static void usage() {
		err.println("usage: nsupdate [-CdDi] [-L level] [-l] [-g | -o | -y keyname:secret | -k keyfile] [-p port] [-v] [-V] [-P] [-T] [-4 | -6] [filename]");
	}

	static void preParseArgs(String [] args) {
		boolean doexit = false;
		boolean ipv4only = false;
		boolean ipv6only = false;
		for(Opt o : getopt(args)) {
			switch(o.ch) {
			case 'M':
				debugging = true;
				ddebugging = true;
				break;
			case '4':
				if( ipv6only ) {
					fatal("only one of -4 and -6 allowed");
				}
				ipv4only = true;
				break;
			case '6':
				if( ipv4only ) {
					fatal("only one of -4 and -6 allowed");
				}
				ipv6only = true;
				break;
			case '?':
			case ':':
			case 'h':
				if( o.ch == '?' ) {
					err.println("nsupdate: illegal option -- "+o.arg);
				} else if( o.ch == ':' ) {
					err.println("nsupdate: option requires an argument -- "+o.arg);
				}
				err.println("nsupdate: invalid argument -"+(o.ch == 'h' ? "h" : o.arg));
				usage();
				throw new Exit(1);
			case 'P':
				//  (no private types)
				doexit = true;
				break;
			case 'T':
				for(int t=1; t < TYPENAMES.length; t++ ) {
					String n = TYPENAMES[t];
					if( !Character.isDigit(n.charAt(0)) && !n.equals("*") && !n.equals("OPT") && !n.equals("TSIG")
							&& !n.equals("TKEY") && !n.equals("IXFR") && !n.equals("AXFR") && !n.equals("MAILA") && !n.equals("MAILB") ) {
						out.println(n);
					}
				}
				doexit = true;
				break;
			case 'V':
				version(err);
				doexit = true;
				break;
			default:
				break;
			}
		}
		if( doexit ) {
			throw new Exit(0);
		}
	}

	private static void version(PrintStream s) {
		s.println("nsupdate "+VERSION);
	}

	static void parseArgs(String [] args) {
		boolean forceInteractive = false;
		debug("parse_args");
		for(Opt o : getopt(args)) {
			switch(o.ch) {
			case '4':
				haveIpv6 = false;
				break;
			case '6':
				if( !haveIpv6 ) {
					fatal("can't find IPv6 networking");
				}
				haveIpv4 = false;
				break;
			case 'C':
				resolvConf = o.arg;
				break;
			case 'd':
				debugging = true;
				break;
			case 'D':
				debugging = true;
				ddebugging = true;
				break;
			case 'M':
				break;
			case 'i':
				forceInteractive = true;
				interactive = true;
				break;
			case 'l':
				localOnly = true;
				break;
			case 'L':
				if( !o.arg.matches("[0-9]+") ) {
					err.println("bad library debug value '"+o.arg+"'");
					throw new Exit(1);
				}
				break;
			case 'y':
				keyStr = o.arg;
				break;
			case 'v':
				usevc = true;
				break;
			case 'k':
				keyFile = o.arg;
				break;
			case 'g':
			case 'o':
				err.println("nsupdate: cannot specify -g	or -o, program not linked with GSS API Library");
				throw new Exit(1);
			case 'p': {
				Long n = parseUint(o.arg, 65535);
				if( n == null ) {
					err.println("bad port number '"+o.arg+"'");
					throw new Exit(1);
				}
				dnsport = n.intValue();
				break;
			}
			case 't': {
				Long n = parseUint(o.arg, 0xffffffffL);
				if( n == null ) {
					err.println("bad timeout '"+o.arg+"'");
					throw new Exit(1);
				}
				timeout = n == 0 || n > Integer.MAX_VALUE ? Integer.MAX_VALUE : n.intValue();
				break;
			}
			case 'u': {
				Long n = parseUint(o.arg, 0xffffffffL);
				if( n == null ) {
					err.println("bad udp timeout '"+o.arg+"'");
					throw new Exit(1);
				}
				udpTimeout = (int)Math.min(n, Integer.MAX_VALUE);
				break;
			}
			case 'r': {
				Long n = parseUint(o.arg, 0xffffffffL);
				if( n == null ) {
					err.println("bad udp retries '"+o.arg+"'");
					throw new Exit(1);
				}
				udpRetries = (int)Math.min(n, 1000);
				break;
			}
			case 'R':
				fatal("The -R option has been deprecated.");
				break;
			default:
				break;
			}
		}
		if( keyFile != null && keyStr != null ) {
			err.println("nsupdate: cannot specify both -k and -y");
			throw new Exit(1);
		}
		if( argIndex < args.length ) {
			String f = args[argIndex];
			if( !f.equals("-") ) {
				try {
					in = new BufferedReader(new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8));
				} catch(IOException ex) {
					err.println("could not open '"+f+"': file not found");
					throw new Exit(1);
				}
			}
			if( !forceInteractive ) {
				interactive = false;
			}
		}
	}

	/** A decimal number 0..max, or null. */
	static Long parseUint(String s, long max) {
		if( s == null || !s.matches("[0-9]+") || s.length() > 12 ) {
			return null;
		}
		long n = Long.parseLong(s);
		return n > max ? null : n;
	}

	static void setupSystem() {
		ddebug("setup_system()");
		List<InetAddress> ns = new ArrayList<InetAddress>();
		File rc = new File(resolvConf);
		if( rc.exists() ) {
			try {
				for(String line : Files.readAllLines(rc.toPath(), StandardCharsets.UTF_8)) {
					String [] tok = line.trim().split("\\s+");
					if( tok.length >= 2 && tok[0].equals("nameserver") ) {
						String a = tok[1];
						if( a.matches("[0-9.]+") || (a.indexOf(':') >= 0 && a.matches("[0-9A-Fa-f:.]+(%.+)?")) ) {
							ns.add(InetAddress.getByName(a));
						}
					}
				}
			} catch(IOException ex) {
				fatal("parse of "+resolvConf+" failed");
			}
		}
		servers = new ArrayList<InetSocketAddress>();
		nsInUse = 0;
		if( localOnly || ns.isEmpty() ) {
			if( localOnly && keyFile == null ) {
				keyFile = SESSION_KEYFILE;
			}
			defaultServers = !localOnly;
			try {
				if( haveIpv6 ) {
					servers.add(new InetSocketAddress(InetAddress.getByName("::1"), dnsport));
				}
				if( haveIpv4 ) {
					servers.add(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), dnsport));
				}
			} catch(UnknownHostException ex) {
				//  (literals)
			}
		} else {
			for(InetAddress a : ns) {
				if( (a instanceof Inet4Address && haveIpv4) || (a instanceof Inet6Address && haveIpv6) ) {
					servers.add(new InetSocketAddress(a, dnsport));
				}
			}
		}
		if( keyStr != null ) {
			setupKeyStr(keyStr);
		} else if( localOnly ) {
			if( !readSessionKey(keyFile) ) {
				fatal("can't read key from "+keyFile+": file not found\n");
			}
		} else if( keyFile != null ) {
			setupKeyFile(keyFile);
		}
	}

	//  ------------------------------------------------------------------
	//  Keys

	/** An HMAC algorithm name (hmac-sha256, ...), or null after an error message. */
	static String parseHmac(String text) {
		String t = text.toLowerCase(Locale.ROOT);
		for(String alg : new String[] {"hmac-md5", "hmac-sha1", "hmac-sha224", "hmac-sha256", "hmac-sha384", "hmac-sha512"}) {
			if( t.equals(alg) ) {
				return alg;
			}
			if( t.startsWith(alg+"-") ) {
				error("truncated TSIG ('"+text+"') is not supported");
				return null;
			}
		}
		error("unknown key type '"+text+"'");
		return null;
	}

	/** -y [hmac:]keyname:secret */
	static void setupKeyStr(String keystr) {
		debug("Creating key...");
		int s = keystr.indexOf(':');
		if( s <= 0 || s+1 >= keystr.length() ) {
			fatal("key option must specify [hmac:]keyname:secret");
		}
		String secretstr = keystr.substring(s+1);
		String name;
		String alg;
		int n = secretstr.indexOf(':');
		if( n >= 0 ) {
			if( n == 0 || n+1 >= secretstr.length() ) {
				fatal("key option must specify [hmac:]keyname:secret");
			}
			name = secretstr.substring(0, n);
			secretstr = secretstr.substring(n+1);
			alg = parseHmac(keystr.substring(0, s));
			if( alg == null ) {
				throw new Exit(1);
			}
		} else {
			alg = "hmac-md5";
			name = keystr.substring(0, s);
		}
		debug("namefromtext");
		byte [] secret;
		try {
			secret = Base64.getDecoder().decode(secretstr.trim());
		} catch(IllegalArgumentException ex) {
			err.println("could not create key from "+keystr+": bad base64 encoding");
			return;
		}
		debug("keycreate");
		try {
			tsigKey = new Tsig.Key(absolute(name), alg, secret);
		} catch(IllegalArgumentException ex) {
			err.println("could not create key from "+keystr+": "+ex.getMessage());
		}
	}

	/** named.conf key clause: key "name" { algorithm hmac-sha256; secret "..."; }; */
	static boolean readSessionKey(String file) {
		File f = new File(file);
		if( !f.exists() ) {
			return false;
		}
		String text;
		try {
			text = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
		} catch(IOException ex) {
			return false;
		}
		//  Comments: # //, and /* */
		text = text.replaceAll("(?s)/\\*.*?\\*/", " ").replaceAll("(?m)(#|//).*$", " ");
		Matcher m = Pattern.compile("key\\s+\"?([^\"\\s{]+)\"?\\s*\\{(.*?)\\}\\s*;", Pattern.DOTALL | Pattern.CASE_INSENSITIVE).matcher(text);
		if( !m.find() ) {
			return false;
		}
		String name = m.group(1);
		Matcher a = Pattern.compile("algorithm\\s+\"?([^\";\\s]+)\"?\\s*;", Pattern.CASE_INSENSITIVE).matcher(m.group(2));
		Matcher s = Pattern.compile("secret\\s+\"([^\"]+)\"\\s*;", Pattern.CASE_INSENSITIVE).matcher(m.group(2));
		if( !a.find() || !s.find() ) {
			fatal("key must have algorithm and secret");
		}
		setupKeyStr(a.group(1)+":"+name+":"+s.group(1));
		return true;
	}

	private static final Map<Integer,String> KEY_ALGORITHMS = new LinkedHashMap<Integer,String>();
	static {
		KEY_ALGORITHMS.put(157, "hmac-md5");
		KEY_ALGORITHMS.put(161, "hmac-sha1");
		KEY_ALGORITHMS.put(162, "hmac-sha224");
		KEY_ALGORITHMS.put(163, "hmac-sha256");
		KEY_ALGORITHMS.put(164, "hmac-sha384");
		KEY_ALGORITHMS.put(165, "hmac-sha512");
	}

	/** -k: a K<name>+<alg>+<id> .key/.private pair, or a named.conf key file. */
	static void setupKeyFile(String file) {
		debug("Creating key...");
		String base = file;
		if( base.length() > 1 && base.endsWith(".") ) {
			base = base.substring(0, base.length()-1);
		} else if( base.length() > 8 && base.endsWith(".private") ) {
			base = base.substring(0, base.length()-8);
		} else if( base.length() > 4 && base.endsWith(".key") ) {
			base = base.substring(0, base.length()-4);
		}
		File priv = new File(base+".private");
		File pub = new File(base+".key");
		if( priv.exists() && pub.exists() ) {
			try {
				String p = new String(Files.readAllBytes(priv.toPath()), StandardCharsets.UTF_8);
				Matcher alg = Pattern.compile("(?m)^Algorithm:\\s*(\\d+)").matcher(p);
				Matcher key = Pattern.compile("(?m)^Key:\\s*(\\S+)").matcher(p);
				String name = null;
				for(String line : Files.readAllLines(pub.toPath(), StandardCharsets.UTF_8)) {
					line = line.trim();
					if( !line.isEmpty() && !line.startsWith(";") ) {
						name = line.split("\\s+")[0];
						break;
					}
				}
				if( alg.find() && key.find() && name != null ) {
					err.println(new java.text.SimpleDateFormat("dd-MMM-yyyy HH:mm:ss.SSS", Locale.ENGLISH).format(new java.util.Date())
							+" "+priv.getPath()+": Use of K* file pairs for HMAC is deprecated");
					err.println();
					String a = KEY_ALGORITHMS.get(Integer.parseInt(alg.group(1)));
					if( a == null ) {
						err.println("could not create key from "+file+": SIG(0) keys are not supported");
						return;
					}
					setupKeyStr(a+":"+name+":"+key.group(1));
					return;
				}
			} catch(IOException | RuntimeException ex) {
				//  (try the other format)
			}
		}
		if( readSessionKey(file) ) {
			return;
		}
		err.println("could not read key from "+base+".{private,key}: file not found");
	}

	//  ------------------------------------------------------------------
	//  Commands

	/** nsu_strsep: the next word (delimiters skipped first); the rest stays in rest[0] (null at the end). */
	static String strsep(String [] rest, String delims) {
		String s = rest[0];
		rest[0] = null;
		if( s == null ) {
			return null;
		}
		int i = 0;
		while( i < s.length() && delims.indexOf(s.charAt(i)) >= 0 ) {
			i++;
		}
		int j = i;
		while( j < s.length() ) {
			if( delims.indexOf(s.charAt(j)) >= 0 ) {
				rest[0] = s.substring(j+1);
				return s.substring(i, j);
			}
			j++;
		}
		return s.substring(i);
	}

	private static final String WS = " \t\r\n";

	/** Read commands until send (true) or quit / end of input (false). */
	static boolean userInteraction() {
		ddebug("user_interaction()");
		int result = STATUS_MORE;
		while( result == STATUS_MORE || result == STATUS_SYNTAX ) {
			result = nextCommand();
			if( !interactive && result == STATUS_SYNTAX ) {
				fatal("syntax error");
			}
		}
		return result == STATUS_SEND;
	}

	static int nextCommand() {
		String line;
		try {
			//  (the prompt goes to a terminal only, as readline's)
			if( interactive && (interactiveDefault != null ? interactiveDefault : System.console() != null) ) {
				out.print("> ");
				out.flush();
			}
			line = in.readLine();
		} catch(IOException ex) {
			line = null;
		}
		if( line == null ) {
			return STATUS_QUIT;
		}
		return command(line);
	}

	/** One command (a line of input). */
	public static int command(String cmdline) {
		ddebug("do_next_command()");
		String [] rest = {cmdline};
		String word = strsep(rest, WS);
		if( word == null || word.isEmpty() ) {
			return STATUS_SEND;
		}
		if( word.charAt(0) == ';' ) {
			return STATUS_MORE;
		}
		switch(word.toLowerCase(Locale.ROOT)) {
		case "quit": return STATUS_QUIT;
		case "prereq": return evaluatePrereq(rest);
		case "nxdomain": return makePrereq(rest, false, false);
		case "yxdomain": return makePrereq(rest, true, false);
		case "nxrrset": return makePrereq(rest, false, true);
		case "yxrrset": return makePrereq(rest, true, true);
		case "update": return evaluateUpdate(rest);
		case "delete":
		case "del": return updateAddOrDelete(rest, true);
		case "add": return updateAddOrDelete(rest, false);
		case "server": return evaluateServer(rest);
		case "local": return evaluateLocal(rest);
		case "zone": return evaluateZone(rest);
		case "class": return evaluateClass(rest);
		case "send": return STATUS_SEND;
		case "debug":
			if( debugging ) {
				ddebugging = true;
			} else {
				debugging = true;
			}
			return STATUS_MORE;
		case "ttl": return evaluateTtl(rest);
		case "show":
			showOutgoing(out, false, 0);
			return STATUS_MORE;
		case "answer":
			if( answer != null ) {
				showReply(out, answer, "Answer:");
			}
			return STATUS_MORE;
		case "key": return evaluateKey(rest);
		case "realm": return STATUS_SYNTAX;
		case "check-names":
		case "checknames": return evaluateCheckNames(rest);
		case "gsstsig":
		case "oldgsstsig":
			err.println("gsstsig not supported");
			return STATUS_MORE;
		case "help":
			out.print("nsupdate "+VERSION+":\n"
					+"local address [port]      (set local resolver)\n"
					+"server address [port]     (set primary server for zone)\n"
					+"send                      (send the update request)\n"
					+"show                      (show the update request)\n"
					+"answer                    (show the answer to the last request)\n"
					+"quit                      (quit, any pending update is not sent)\n"
					+"help                      (display this message)\n"
					+"key [hmac:]keyname secret (use TSIG to sign the request)\n"
					+"gsstsig                   (use GSS_TSIG to sign the request)\n"
					+"oldgsstsig                (use Microsoft's GSS_TSIG to sign the request)\n"
					+"zone name                 (set the zone to be updated)\n"
					+"class CLASS               (set the zone's DNS class, e.g. IN (default), CH)\n"
					+"check-names { on | off }  (enable / disable check-names)\n"
					+"[prereq] nxdomain name    (require that this name does not exist)\n"
					+"[prereq] yxdomain name    (require that this name exists)\n"
					+"[prereq] nxrrset ....     (require that this RRset does not exist)\n"
					+"[prereq] yxrrset ....     (require that this RRset exists)\n"
					+"[update] add ....         (add the given record to the zone)\n"
					+"[update] del[ete] ....    (remove the given record(s) from the zone)\n");
			return STATUS_MORE;
		case "version":
			version(out);
			return STATUS_MORE;
		default:
			err.println("incorrect section name: "+word);
			return STATUS_SYNTAX;
		}
	}

	/** An owner name, or null after an error message. */
	static String parseName(String [] rest) {
		String word = strsep(rest, WS);
		if( word == null || word.isEmpty() ) {
			err.println("could not read owner name");
			return null;
		}
		String n = checkName(word);
		if( n == null ) {
			return null;
		}
		return n;
	}

	/** A name as typed, absolute (a trailing dot is added), or null after "invalid owner name". */
	static String checkName(String word) {
		String n = word.endsWith(".") ? word : word+".";
		if( n.length() > 255 || n.startsWith(".") && n.length() > 1 || n.contains("..") ) {
			error("invalid owner name: "+(n.contains("..") || n.startsWith(".") ? "empty label" : "name too long"));
			return null;
		}
		for(String label : n.substring(0, n.length()-1).split("\\.")) {
			if( label.length() > 63 ) {
				error("invalid owner name: label too long");
				return null;
			}
		}
		return n;
	}

	static String absolute(String name) {
		return name.endsWith(".") ? name : name+".";
	}

	static String stripDot(String name) {
		return name.length() > 1 && name.endsWith(".") ? name.substring(0, name.length()-1) : name;
	}

	/** The zone's class (the default class until one is used) */
	static int getZoneClass() {
		if( zoneClass == -1 ) {
			zoneClass = defaultClass;
		}
		return zoneClass;
	}

	static boolean setZoneClass(int cls) {
		if( zoneClass == -1 || cls == -1 ) {
			zoneClass = cls;
		}
		return zoneClass == cls;
	}

	static int evaluatePrereq(String [] rest) {
		ddebug("evaluate_prereq()");
		String word = strsep(rest, WS);
		if( word == null || word.isEmpty() ) {
			err.println("could not read operation code");
			return STATUS_SYNTAX;
		}
		switch(word.toLowerCase(Locale.ROOT)) {
		case "nxdomain": return makePrereq(rest, false, false);
		case "yxdomain": return makePrereq(rest, true, false);
		case "nxrrset": return makePrereq(rest, false, true);
		case "yxrrset": return makePrereq(rest, true, true);
		default:
			err.println("incorrect operation code: "+word);
			return STATUS_SYNTAX;
		}
	}

	static int makePrereq(String [] rest, boolean positive, boolean rrset) {
		ddebug("make_prereq()");
		String name = parseName(rest);
		if( name == null ) {
			return STATUS_SYNTAX;
		}
		int cls = -1;
		int type;
		if( rrset ) {
			String word = strsep(rest, WS);
			if( word == null || word.isEmpty() ) {
				err.println("could not read class or type");
				return STATUS_SYNTAX;
			}
			int c = classCode(word);
			if( c >= 0 ) {
				if( !setZoneClass(c) ) {
					err.println("class mismatch: "+word);
					return STATUS_SYNTAX;
				}
				cls = c;
				word = strsep(rest, WS);
				if( word == null || word.isEmpty() ) {
					err.println("could not read type");
					return STATUS_SYNTAX;
				}
			} else {
				cls = getZoneClass();
			}
			type = typeCode(word);
			if( type < 0 ) {
				err.println("invalid type: "+word);
				return STATUS_SYNTAX;
			}
		} else {
			type = QTYPE_ALL;
		}
		RR rr = null;
		if( rrset && positive ) {
			Object data = parseRdata(rest, cls, type, name, 0);
			if( data == SYNTAX ) {
				return STATUS_SYNTAX;
			}
			rr = (RR) data;
		}
		if( rr == null ) {
			rr = empty(name, type, positive ? CLASS_ANY : CLASS_NONE, 0);
		}
		prereqs.add(rr);
		return STATUS_MORE;
	}

	private static final Object SYNTAX = new Object();

	/** A record without data (class ANY or NONE). */
	static RR empty(String name, int type, int cls, long ttl) {
		RR rr = new RR(name, type, cls);
		rr.setRdata(new byte[0]);
		rr.setTTL((int)ttl);
		return rr;
	}

	/**
	 * The rest of the line as the data of a record: the record, null when
	 * there is no data, or SYNTAX after an error message.
	 */
	static Object parseRdata(String [] rest, int cls, int type, String name, long ttl) {
		String text = rest[0];
		if( text == null || text.trim().isEmpty() ) {
			return null;
		}
		text = text.trim();
		try {
			return makeRecord(name, ttl, cls, type, text);
		} catch(IllegalArgumentException ex) {
			err.println("invalid rdata format: "+reason(ex));
			return SYNTAX;
		}
	}

	private static String reason(IllegalArgumentException ex) {
		String m = ex.getMessage();
		if( ex instanceof NumberFormatException || m == null ) {
			return "not a valid number";
		}
		if( m.startsWith("Invalid or unsupported type") || m.equals("not implemented") ) {
			return "not implemented";
		}
		if( m.toLowerCase(Locale.ROOT).contains("address") ) {
			return "bad dotted quad";
		}
		if( m.contains("unexpected end") || m.startsWith("no text") || m.contains("needs") ) {
			return "unexpected end of input";
		}
		return m;
	}

	/** A record from the text of its data (with the RFC 3597 \# form). */
	static RR makeRecord(String name, long ttl, int cls, int type, String text) {
		if( text.startsWith("\\#") ) {
			String [] tok = text.substring(2).trim().split("\\s+");
			if( tok.length < 1 || !tok[0].matches("[0-9]+") ) {
				throw new IllegalArgumentException("unexpected end of input");
			}
			int len = Integer.parseInt(tok[0]);
			String hex = String.join("", Arrays.asList(tok).subList(1, tok.length));
			if( hex.length() != 2*len || !hex.matches("[0-9A-Fa-f]*") ) {
				throw new IllegalArgumentException(hex.length() < 2*len ? "unexpected end of input" : "bad hex encoding");
			}
			byte [] data = new byte[len];
			for(int i=0; i < len; i++ ) {
				data[i] = (byte)Integer.parseInt(hex.substring(2*i, 2*i+2), 16);
			}
			return fromWire(name, type, cls, ttl, data);
		}
		if( cls != IN && IN_ONLY.contains(type) ) {
			if( type == A && cls == 4 ) {
				//  HS A is as IN A
				RR rr = Zone.parseRecord(stripDot(name), ttl, IN, type, text);
				rr.setDnsClass(cls);
				rr.setName(stripDot(name));
				return rr;
			}
			if( type == A && cls == 3 ) {
				//  CH A: a domain and a 16 bit octal address (RFC 1035 3.4.1 / Chaosnet)
				String [] tok = text.trim().split("\\s+");
				if( tok.length < 2 ) {
					throw new IllegalArgumentException("unexpected end of input");
				}
				int addr;
				try {
					addr = Integer.parseInt(tok[1], 8);
				} catch(NumberFormatException ex) {
					throw new IllegalArgumentException("bad number");
				}
				if( addr > 0xffff ) {
					throw new IllegalArgumentException("out of range");
				}
				ByteArrayOutputStream b = new ByteArrayOutputStream();
				writeName(b, absolute(tok[0]));
				b.write(addr >> 8);
				b.write(addr);
				return fromWire(name, type, cls, ttl, b.toByteArray());
			}
			throw new IllegalArgumentException("unknown class/type");
		}
		RR rr = Zone.parseRecord(stripDot(name), ttl, cls, type, text);
		//  Keep the owner as typed (case)
		rr.setName(stripDot(name));
		return rr;
	}

	/** Types whose data format is defined for class IN only (in BIND: and CH / HS A) */
	static final java.util.Set<Integer> IN_ONLY = new java.util.HashSet<Integer>(Arrays.asList(
			A, 11, 22, 23, 26, AAAA, SRV, 35, 36, 38, 42, 34, 49, 31, 32, 64, 65));

	/** A record from its data in wire form (a typed record when this library knows the type). */
	static RR fromWire(String name, int type, int cls, long ttl, byte [] rdata) {
		ByteArrayOutputStream b = new ByteArrayOutputStream();
		//  A response with this one record in the answer section
		b.write(0); b.write(0); b.write(0x80); b.write(0);
		b.write(0); b.write(0); b.write(0); b.write(1); b.write(0); b.write(0); b.write(0); b.write(0);
		writeName(b, name);
		b.write(type >> 8); b.write(type);
		b.write(cls >> 8); b.write(cls);
		b.write((int)(ttl >> 24)); b.write((int)(ttl >> 16)); b.write((int)(ttl >> 8)); b.write((int)ttl);
		b.write(rdata.length >> 8); b.write(rdata.length);
		b.write(rdata, 0, rdata.length);
		try {
			Message m = new Message(new ByteBuffer(b.toByteArray()));
			RR rr = m.getAnswer().get(0);
			if( rr.getClass() != RR.class && rr.getRdata() == null ) {
				rr.setRdata(rdata);
			}
			return rr;
		} catch(RuntimeException ex) {
			throw new IllegalArgumentException("bad rdata");
		}
	}

	private static void writeName(ByteArrayOutputStream b, String name) {
		String n = stripDot(name);
		if( !n.equals(".") && !n.isEmpty() ) {
			for(String label : n.split("\\.")) {
				byte [] l = label.getBytes(StandardCharsets.ISO_8859_1);
				b.write(l.length);
				b.write(l, 0, l.length);
			}
		}
		b.write(0);
	}

	static int evaluateServer(String [] rest) {
		if( localOnly ) {
			err.println("cannot reset server in localhost-only mode");
			return STATUS_SYNTAX;
		}
		String server = strsep(rest, WS);
		if( server == null || server.isEmpty() ) {
			err.println("could not read server name");
			return STATUS_SYNTAX;
		}
		int port = dnsport;
		String word = strsep(rest, WS);
		if( word != null && !word.isEmpty() ) {
			Integer p = port(word);
			if( p == null ) {
				return STATUS_SYNTAX;
			}
			port = p;
		}
		defaultServers = false;
		nsInUse = 0;
		servers = getAddresses(server, port);
		if( servers.isEmpty() ) {
			return STATUS_SYNTAX;
		}
		return STATUS_MORE;
	}

	/** A port 1-65535, or null after an error message. */
	private static Integer port(String word) {
		long p;
		try {
			p = Long.parseLong(word);
		} catch(NumberFormatException ex) {
			err.println("port '"+word+"' is not numeric");
			return null;
		}
		if( p < 1 || p > 65535 ) {
			err.println("port '"+word+"' is out of range (1 to 65535)");
			return null;
		}
		return (int)p;
	}

	/** Up to 4 addresses of a host (as getaddrinfo), or none after "couldn't get address". */
	static List<InetSocketAddress> getAddresses(String host, int port) {
		List<InetSocketAddress> ret = new ArrayList<InetSocketAddress>();
		try {
			for(InetAddress a : InetAddress.getAllByName(host)) {
				if( (a instanceof Inet4Address && haveIpv4) || (a instanceof Inet6Address && haveIpv6) ) {
					ret.add(new InetSocketAddress(a, port));
				}
				if( ret.size() == MAX_SERVERADDRS ) {
					break;
				}
			}
		} catch(UnknownHostException ex) {
			//  (none)
		}
		if( ret.isEmpty() ) {
			error("couldn't get address for '"+host+"': not found");
		}
		return ret;
	}

	static int evaluateLocal(String [] rest) {
		String local = strsep(rest, WS);
		if( local == null || local.isEmpty() ) {
			err.println("could not read server name");
			return STATUS_SYNTAX;
		}
		int port = 0;
		String word = strsep(rest, WS);
		if( word != null && !word.isEmpty() ) {
			Integer p = port(word);
			if( p == null ) {
				return STATUS_SYNTAX;
			}
			port = p;
		}
		try {
			if( haveIpv6 && local.indexOf(':') >= 0 && local.matches("[0-9A-Fa-f:.]+") ) {
				localAddr6 = InetAddress.getByName(local);
				localPort6 = port;
				return STATUS_MORE;
			}
			if( haveIpv4 && local.matches("[0-9]{1,3}(\\.[0-9]{1,3}){3}") ) {
				localAddr4 = InetAddress.getByName(local);
				localPort4 = port;
				return STATUS_MORE;
			}
		} catch(UnknownHostException ex) {
			//  (bad literal)
		}
		err.print("invalid address "+local);
		return STATUS_SYNTAX;
	}

	static int evaluateKey(String [] rest) {
		String namestr = strsep(rest, WS);
		if( namestr == null || namestr.isEmpty() ) {
			err.println("could not read key name");
			return STATUS_SYNTAX;
		}
		String alg = "hmac-md5";
		int n = namestr.indexOf(':');
		if( n >= 0 ) {
			alg = parseHmac(namestr.substring(0, n));
			if( alg == null ) {
				return STATUS_SYNTAX;
			}
			namestr = namestr.substring(n+1);
		}
		if( namestr.isEmpty() ) {
			err.println("could not parse key name");
			return STATUS_SYNTAX;
		}
		String secretstr = strsep(rest, "\r\n");
		if( secretstr == null || secretstr.isEmpty() ) {
			err.println("could not read key secret");
			return STATUS_SYNTAX;
		}
		byte [] secret;
		try {
			secret = Base64.getDecoder().decode(secretstr.trim());
		} catch(IllegalArgumentException ex) {
			err.println("could not create key from "+secretstr+": bad base64 encoding");
			return STATUS_SYNTAX;
		}
		try {
			tsigKey = new Tsig.Key(absolute(namestr), alg, secret);
		} catch(IllegalArgumentException ex) {
			err.println("could not create key from "+namestr+" "+secretstr+": "+ex.getMessage());
			return STATUS_SYNTAX;
		}
		return STATUS_MORE;
	}

	static int evaluateZone(String [] rest) {
		String word = strsep(rest, WS);
		if( word == null || word.isEmpty() ) {
			err.println("could not read zone name");
			return STATUS_SYNTAX;
		}
		String n = word.endsWith(".") ? word : word+".";
		if( n.contains("..") || (n.startsWith(".") && n.length() > 1) ) {
			userZone = null;
			err.println("could not parse zone name");
			return STATUS_SYNTAX;
		}
		userZone = n;
		return STATUS_MORE;
	}

	static int evaluateTtl(String [] rest) {
		String word = strsep(rest, WS);
		if( word == null || word.isEmpty() ) {
			err.println("could not read ttl");
			return STATUS_SYNTAX;
		}
		if( word.equalsIgnoreCase("none") ) {
			defaultTtl = 0;
			defaultTtlSet = false;
			return STATUS_MORE;
		}
		Long ttl = parseUint(word, 0xffffffffL);
		if( ttl == null ) {
			return STATUS_SYNTAX;
		}
		if( ttl > TTL_MAX ) {
			err.println("ttl '"+word+"' is out of range (0 to "+TTL_MAX+")");
			return STATUS_SYNTAX;
		}
		defaultTtl = ttl;
		defaultTtlSet = true;
		return STATUS_MORE;
	}

	static int evaluateClass(String [] rest) {
		String word = strsep(rest, WS);
		if( word == null || word.isEmpty() ) {
			err.println("could not read class name");
			return STATUS_SYNTAX;
		}
		int c = classCode(word);
		if( c < 0 ) {
			err.println("could not parse class name: "+word);
			return STATUS_SYNTAX;
		}
		if( c == CLASS_NONE || c == CLASS_ANY || c == 0 ) {
			err.println("bad default class: "+word);
			return STATUS_SYNTAX;
		}
		defaultClass = c;
		return STATUS_MORE;
	}

	static int evaluateCheckNames(String [] rest) {
		ddebug("evaluate_checknames()");
		String word = strsep(rest, WS);
		if( word == null || word.isEmpty() ) {
			err.println("could not read check-names directive");
			return STATUS_SYNTAX;
		}
		String w = word.toLowerCase(Locale.ROOT);
		if( w.equals("yes") || w.equals("true") || w.equals("on") ) {
			checkNames = true;
		} else if( w.equals("no") || w.equals("false") || w.equals("off") ) {
			checkNames = false;
		} else {
			err.println("incorrect check-names directive: "+word);
			return STATUS_SYNTAX;
		}
		return STATUS_MORE;
	}

	static int evaluateUpdate(String [] rest) {
		ddebug("evaluate_update()");
		String word = strsep(rest, WS);
		if( word == null || word.isEmpty() ) {
			err.println("could not read operation code");
			return STATUS_SYNTAX;
		}
		switch(word.toLowerCase(Locale.ROOT)) {
		case "delete":
		case "del": return updateAddOrDelete(rest, true);
		case "add": return updateAddOrDelete(rest, false);
		default:
			err.println("incorrect operation code: "+word);
			return STATUS_SYNTAX;
		}
	}

	static int updateAddOrDelete(String [] rest, boolean isDelete) {
		ddebug("update_addordelete()");
		String name = parseName(rest);
		if( name == null ) {
			return STATUS_SYNTAX;
		}
		long ttl;
		int cls;
		int type;
		String word = strsep(rest, WS);
		if( word == null || word.isEmpty() ) {
			if( !isDelete ) {
				err.println("could not read owner ttl");
				return STATUS_SYNTAX;
			}
			updates.add(empty(name, QTYPE_ALL, CLASS_ANY, 0));
			return STATUS_MORE;
		}
		Long t = parseUint(word, 0xffffffffL);
		boolean haveWord = false;
		if( t == null ) {
			if( isDelete ) {
				ttl = 0;
				haveWord = true;
			} else if( defaultTtlSet ) {
				ttl = defaultTtl;
				haveWord = true;
			} else {
				err.println("ttl '"+word+"': "+(word.matches("[0-9]+") ? "out of range" : "not a valid number"));
				return STATUS_SYNTAX;
			}
		} else {
			if( isDelete ) {
				ttl = 0;
			} else if( t > TTL_MAX ) {
				err.println("ttl '"+word+"' is out of range (0 to "+TTL_MAX+")");
				return STATUS_SYNTAX;
			} else {
				ttl = t;
			}
		}
		if( !haveWord ) {
			word = strsep(rest, WS);
		}
		if( word == null || word.isEmpty() ) {
			if( isDelete ) {
				updates.add(empty(name, QTYPE_ALL, CLASS_ANY, 0));
				return STATUS_MORE;
			}
			err.println("could not read class or type");
			return STATUS_SYNTAX;
		}
		int c = classCode(word);
		if( c >= 0 && c != CLASS_ANY ) {
			if( !setZoneClass(c) ) {
				err.println("class mismatch: "+word);
				return STATUS_SYNTAX;
			}
			cls = c;
			word = strsep(rest, WS);
			if( word == null || word.isEmpty() ) {
				if( isDelete ) {
					updates.add(empty(name, QTYPE_ALL, CLASS_ANY, 0));
					return STATUS_MORE;
				}
				err.println("could not read type");
				return STATUS_SYNTAX;
			}
			type = typeCode(word);
			if( type < 0 ) {
				err.println("'"+word+"' is not a valid type: unknown class/type");
				return STATUS_SYNTAX;
			}
		} else {
			cls = getZoneClass();
			type = typeCode(word);
			if( type < 0 ) {
				err.println("'"+word+"' is not a valid class or type: unknown class/type");
				return STATUS_SYNTAX;
			}
		}
		Object data = parseRdata(rest, cls, type, name, ttl);
		if( data == SYNTAX ) {
			return STATUS_SYNTAX;
		}
		RR rr = (RR) data;
		if( isDelete ) {
			if( rr == null ) {
				rr = empty(name, type, CLASS_ANY, 0);
			} else {
				rr.setDnsClass(CLASS_NONE);
				rr.setTTL(0);
			}
		} else {
			if( rr == null ) {
				err.println("could not read rdata");
				return STATUS_SYNTAX;
			}
			if( checkNames ) {
				String bad = checkOwner(name, type);
				if( bad != null ) {
					err.println("check-names failed: bad owner '"+stripDot(bad)+"'");
					return STATUS_SYNTAX;
				}
				bad = checkRdataNames(rr, name, cls);
				if( bad != null ) {
					err.println("check-names failed: bad name '"+stripDot(bad)+"'");
					return STATUS_SYNTAX;
				}
			}
			if( type == NSEC3PARAM ) {
				byte [] d = rdataOf(rr);
				if( d != null && d.length >= 4 && (((d[2] & 0xff) << 8) | (d[3] & 0xff)) > 150 ) {
					err.println("NSEC3PARAM has excessive iterations (> 150)");
					return STATUS_SYNTAX;
				}
			}
		}
		updates.add(rr);
		return STATUS_MORE;
	}

	//  ------------------------------------------------------------------
	//  check-names (RFC 952 / RFC 1123 host names, as BIND checks them)

	static boolean isHostname(String name, boolean wildcard) {
		String n = stripDot(name);
		if( n.equals(".") || n.isEmpty() ) {
			return true;
		}
		String [] labels = n.split("\\.");
		int start = 0;
		if( wildcard && labels.length > 0 && labels[0].equals("*") ) {
			start = 1;
		}
		for(int i=start; i < labels.length; i++ ) {
			String l = labels[i];
			for(int j=0; j < l.length(); j++ ) {
				char c = l.charAt(j);
				boolean border = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
				if( j == 0 || j == l.length()-1 ) {
					if( !border ) {
						return false;
					}
				} else if( !border && c != '-' ) {
					return false;
				}
			}
		}
		return true;
	}

	static boolean isMailbox(String name) {
		String n = stripDot(name);
		if( n.equals(".") || n.isEmpty() ) {
			return true;
		}
		int dot = n.indexOf('.');
		if( dot < 0 ) {
			//  (only the local part: fine)
			for(char c : n.toCharArray()) {
				if( c <= 0x20 || c >= 0x7f ) {
					return false;
				}
			}
			return true;
		}
		for(char c : n.substring(0, dot).toCharArray()) {
			if( c <= 0x20 || c >= 0x7f ) {
				return false;
			}
		}
		return isHostname(n.substring(dot+1), false);
	}

	/** The owner if it is not a valid owner for the type (A, AAAA, MX), else null. */
	static String checkOwner(String name, int type) {
		String n = stripDot(name);
		String [] labels = n.split("\\.");
		if( type == A || type == AAAA ) {
			if( labels.length > 2 && labels[0].equalsIgnoreCase("gc") && labels[1].equalsIgnoreCase("_msdcs")
					&& isHostname(n.substring(labels[0].length()+labels[1].length()+2), false) ) {
				return null;
			}
			if( type == A ) {
				for(int i=0; i < labels.length-1; i++ ) {
					String l = labels[i].toLowerCase(Locale.ROOT);
					if( l.equals("_spf") || l.equals("_spf_verify") || l.equals("_spf_rate") ) {
						return null;
					}
				}
			}
			return isHostname(name, true) ? null : name;
		}
		if( type == MX || type == 38 ) {
			return isHostname(name, true) ? null : name;
		}
		return null;
	}

	/** A name in the data that is not a valid host name / mailbox for the type, else null. */
	static String checkRdataNames(RR rr, String owner, int cls) {
		switch(rr.getType()) {
		case MX:
			if( rr instanceof Mx ) {
				String x = absolute(((Mx)rr).getExchange());
				return isHostname(x, false) ? null : x;
			}
			break;
		case NS:
			if( rr instanceof Ns ) {
				String x = absolute(((Ns)rr).getNs());
				return isHostname(x, false) ? null : x;
			}
			break;
		case SRV:
			if( rr instanceof Srv ) {
				String x = absolute(((Srv)rr).getTarget());
				return isHostname(x, false) ? null : x;
			}
			break;
		case PTR:
			if( cls == IN && rr instanceof Ptr ) {
				String o = stripDot(owner).toLowerCase(Locale.ROOT);
				if( o.endsWith("in-addr.arpa") || o.endsWith("ip6.arpa") || o.endsWith("ip6.int") ) {
					String x = absolute(((Ptr)rr).getPtr());
					return isHostname(x, false) ? null : x;
				}
			}
			break;
		case SOA:
			if( rr instanceof Soa ) {
				String m = absolute(((Soa)rr).getMname());
				if( !isHostname(m, false) ) {
					return m;
				}
				String r = absolute(((Soa)rr).getRname());
				return isMailbox(r) ? null : r;
			}
			break;
		case RP:
			if( rr instanceof Rp ) {
				String m = absolute(((Rp)rr).getMboxDname());
				return isMailbox(m) ? null : m;
			}
			break;
		default:
			break;
		}
		return null;
	}

	//  ------------------------------------------------------------------
	//  Sending

	/** The first name of the update section (or the prerequisite section), with its record. */
	static RR firstRecord() {
		if( !updates.isEmpty() ) {
			return updates.get(0);
		}
		if( !prereqs.isEmpty() ) {
			return prereqs.get(0);
		}
		return null;
	}

	static void startUpdate() {
		ddebug("start_update()");
		answer = null;
		if( userZone != null && !defaultServers ) {
			primaryServers = servers;
			primaryInUse = nsInUse;
			sendUpdate(userZone);
			setZoneClass(-1);
			return;
		}
		String qname;
		if( userZone != null ) {
			qname = userZone;
		} else {
			RR first = firstRecord();
			if( first == null ) {
				return;
			}
			qname = absolute(first.getName());
			if( !updates.isEmpty() && first.getType() == DS && !stripDot(qname).equals(".") ) {
				qname = parent(qname);
			}
		}
		nsInUse = 0;
		findZone(qname);
	}

	static String parent(String name) {
		String n = stripDot(name);
		int dot = n.indexOf('.');
		return dot < 0 ? "." : n.substring(dot+1)+".";
	}

	/** Look for the zone of qname with SOA queries, then send the update to its primary. */
	static void findZone(String qname) {
		int cls = getZoneClass();
		while( true ) {
			Reply r = null;
			while( r == null ) {
				if( nsInUse >= servers.size() ) {
					fatal("could not reach any name server");
				}
				InetSocketAddress server = servers.get(nsInUse);
				try {
					Message q = new Message();
					q.setQuestion(stripDot(qname).equals(".") ? "" : stripDot(qname), SOA, cls);
					q.recursiveDesired(defaultServers);
					r = exchange(q, server, !defaultServers && usevc, defaultServers ? null : tsigKey, false);
					if( r.msg.getResponseCode() == REFUSED ) {
						nextServer(server, "REFUSED");
						r = null;
					}
				} catch(CommunicationsError ex) {
					nextServer(server, ex.getMessage());
				}
			}
			if( debugging ) {
				showReply(err, r, "Reply from SOA query:");
			}
			int opcode = (r.wire[2] >> 3) & 0xf;
			if( opcode != 0 ) {
				fatal("invalid OPCODE in response to SOA query");
			}
			int rcode = r.msg.getResponseCode();
			if( rcode != NOERROR && rcode != NAME_ERROR ) {
				fatal("response to SOA query was unsuccessful");
			}
			if( userZone != null && rcode == NAME_ERROR ) {
				error("specified zone '"+stripDot(userZone)+"' does not exist (NXDOMAIN)");
				seenError = true;
				return;
			}
			Soa soa = null;
			boolean seenCname = false;
			for(RR rr : r.msg.getAnswer()) {
				if( rr instanceof Soa ) {
					soa = (Soa) rr;
					break;
				}
				if( rr.getType() == CNAME || rr.getType() == 39 ) {
					seenCname = true;
					break;
				}
			}
			if( soa == null && !seenCname ) {
				for(RR rr : r.msg.getAuthority()) {
					if( rr instanceof Soa ) {
						soa = (Soa) rr;
						break;
					}
				}
			}
			if( soa == null || seenCname ) {
				//  Drop a label and ask again
				if( stripDot(qname).equals(".") ) {
					fatal("could not find enclosing zone");
				}
				qname = parent(qname);
				continue;
			}
			debug("Found zone name: "+nameText(soa.getName(), true));
			String zname = userZone != null ? userZone : absolute(soa.getName().isEmpty() ? "." : soa.getName());
			String primary = soa.getMname();
			debug("The primary is: "+nameText(primary, true));
			if( defaultServers ) {
				primaryServers = getAddresses(stripDot(primary), dnsport);
				if( primaryServers.isEmpty() ) {
					seenError = true;
					return;
				}
				primaryInUse = 0;
			} else {
				primaryServers = servers;
				primaryInUse = nsInUse;
			}
			sendUpdate(zname);
			setZoneClass(-1);
			return;
		}
	}

	static void nextServer(InetSocketAddress addr, String why) {
		err.println("; Communication with "+sockaddr(addr)+" failed: "+why);
		if( ++nsInUse >= servers.size() ) {
			fatal("could not reach any name server");
		}
		ddebug("recvsoa: trying next server");
	}

	/** Build the update message for a zone. */
	static Message updateMessage(String zone) {
		Message m = new Message();
		m.setOpCode(OPCODE_UPDATE);
		m.recursiveDesired(false);
		m.addQuestion(new Section(stripDot(zone).equals(".") ? "" : stripDot(zone), SOA, getZoneClass()));
		for(RR rr : prereqs) {
			m.addAnswer(rr);
		}
		for(RR rr : updates) {
			m.addAuthority(rr);
		}
		return m;
	}

	static void sendUpdate(String zone) {
		ddebug("send_update()");
		while( primaryInUse < primaryServers.size() ) {
			InetSocketAddress primary = primaryServers.get(primaryInUse);
			debug("Sending update to "+sockaddr(primary));
			Message m = updateMessage(zone);
			try {
				Reply r = exchange(m, primary, usevc, tsigKey, true);
				updateCompleted(r);
				return;
			} catch(CommunicationsError ex) {
				err.println("; Communication with "+sockaddr(primary)+" failed: "+ex.getMessage());
				if( ++primaryInUse >= primaryServers.size() ) {
					seenError = true;
					return;
				}
				ddebug("update_completed: trying next server");
			}
		}
	}

	static void updateCompleted(Reply r) {
		ddebug("update_completed()");
		answer = r;
		int opcode = (r.wire[2] >> 3) & 0xf;
		if( opcode != OPCODE_UPDATE ) {
			fatal("invalid OPCODE in response to UPDATE request");
		}
		int rcode = r.msg.getResponseCode();
		if( rcode != NOERROR ) {
			seenError = true;
			if( !debugging ) {
				String text = rcodeText(rcode);
				Tsig.Record t = Tsig.find(r.wire);
				if( t != null && t.error != 0 ) {
					text += "("+tsigErrorText(t.error)+")";
				}
				err.println("update failed: "+text);
			}
		}
		if( debugging ) {
			showReply(err, r, "\nReply from update query:");
		}
	}

	/**
	 * Send a message and wait for its answer: UDP (udpRetries+1 tries of
	 * udpTimeout seconds; a truncated answer is asked again over TCP) or TCP.
	 * @param show print the outgoing message (debug)
	 */
	static Reply exchange(Message m, InetSocketAddress server, boolean tcp, Tsig.Key key, boolean show) throws CommunicationsError {
		int id = ID_RANDOM.nextInt(0x10000);
		m.setID(id);
		byte [] data = m.toByteArray();
		Tsig.Session session = null;
		if( key != null ) {
			session = Tsig.Session.client(key);
			data = session.signRequest(data);
		}
		if( show && debugging ) {
			showOutgoing(out, true, id, data);
		}
		byte [] resp;
		if( tcp || data.length > 512 ) {
			resp = tcpExchange(data, server);
		} else {
			resp = udpExchange(data, id, server);
			if( resp != null && (resp[2] & 0x02) != 0 ) {
				resp = tcpExchange(data, server);
			}
		}
		Message r;
		try {
			r = new Message(new ByteBuffer(resp));
		} catch(RuntimeException ex) {
			throw new CommunicationsError("unexpected end of input");
		}
		if( session != null ) {
			String problem = null;
			Tsig.Record t = Tsig.find(resp);
			if( t == null ) {
				problem = "expected a TSIG or SIG(0)";
			} else if( t.error != 0 ) {
				problem = "tsig indicates error";
			} else {
				try {
					session.verifyResponse(resp);
				} catch(Tsig.TsigException ex) {
					problem = ex.error == Tsig.BADTIME ? "clock skew" : "tsig verify failure";
				}
			}
			if( problem != null ) {
				err.println("; TSIG error with server: "+problem);
				seenError = true;
			}
		}
		return new Reply(r, resp);
	}

	private static byte [] udpExchange(byte [] data, int id, InetSocketAddress server) throws CommunicationsError {
		InetAddress local = server.getAddress() instanceof Inet6Address ? localAddr6 : localAddr4;
		int localPort = server.getAddress() instanceof Inet6Address ? localPort6 : localPort4;
		long overall = System.currentTimeMillis() + 1000L*Math.min(timeout, 1000000);
		try(DatagramSocket sock = local != null ? new DatagramSocket(new InetSocketAddress(local, localPort)) : new DatagramSocket()) {
			sock.connect(server);
			byte [] buf = new byte[65535];
			for(int attempt=0; attempt <= udpRetries; attempt++ ) {
				sock.send(new DatagramPacket(data, data.length));
				long deadline = Math.min(overall, System.currentTimeMillis() + 1000L*Math.max(udpTimeout, 1));
				while( true ) {
					long remaining = deadline - System.currentTimeMillis();
					if( remaining <= 0 ) {
						break;
					}
					sock.setSoTimeout((int)remaining);
					DatagramPacket p = new DatagramPacket(buf, buf.length);
					try {
						sock.receive(p);
					} catch(SocketTimeoutException ex) {
						break;
					}
					if( p.getLength() >= 12 && (((buf[0] & 0xff) << 8) | (buf[1] & 0xff)) == id && (buf[2] & 0x80) != 0 ) {
						return Arrays.copyOf(buf, p.getLength());
					}
				}
				if( System.currentTimeMillis() >= overall ) {
					break;
				}
			}
			throw new CommunicationsError("timed out");
		} catch(PortUnreachableException ex) {
			throw new CommunicationsError("connection refused");
		} catch(CommunicationsError ex) {
			throw ex;
		} catch(IOException | RuntimeException ex) {
			throw new CommunicationsError(ex.getMessage() == null ? ex.toString() : ex.getMessage());
		}
	}

	private static byte [] tcpExchange(byte [] data, InetSocketAddress server) throws CommunicationsError {
		InetAddress local = server.getAddress() instanceof Inet6Address ? localAddr6 : localAddr4;
		int localPort = server.getAddress() instanceof Inet6Address ? localPort6 : localPort4;
		int ms = (int)Math.min(1000L*timeout, Integer.MAX_VALUE);
		try(Socket sock = new Socket()) {
			if( local != null ) {
				sock.bind(new InetSocketAddress(local, localPort));
			}
			try {
				sock.connect(server, ms);
			} catch(ConnectException ex) {
				//  (as nsupdate reports a refused TCP connection)
				throw new CommunicationsError("operation canceled");
			}
			sock.setSoTimeout(ms);
			OutputStream os = sock.getOutputStream();
			ByteArrayOutputStream b = new ByteArrayOutputStream();
			b.write(data.length >> 8);
			b.write(data.length);
			b.write(data);
			os.write(b.toByteArray());
			os.flush();
			DataInputStream din = new DataInputStream(sock.getInputStream());
			int len = din.readUnsignedShort();
			byte [] resp = new byte[len];
			din.readFully(resp);
			return resp;
		} catch(SocketTimeoutException ex) {
			throw new CommunicationsError("timed out");
		} catch(CommunicationsError ex) {
			throw ex;
		} catch(IOException | RuntimeException ex) {
			throw new CommunicationsError("operation canceled");
		}
	}

	//  ------------------------------------------------------------------
	//  Messages as text (BIND's debug style, as nsupdate prints them)

	static final String [] OPCODES = {"QUERY", "IQUERY", "STATUS", "RESERVED3", "NOTIFY", "UPDATE",
			"RESERVED6", "RESERVED7", "RESERVED8", "RESERVED9", "RESERVED10", "RESERVED11",
			"RESERVED12", "RESERVED13", "RESERVED14", "RESERVED15"};

	/** "show": the update being built (not sent yet: id 0, no counts), or as sent (debug). */
	static void showOutgoing(PrintStream s, boolean rendered, int id, byte [] ... wire) {
		ddebug("show_message()");
		StringBuilder sb = new StringBuilder("Outgoing update query:\n");
		int [] counts = new int[4];
		if( rendered && wire.length > 0 ) {
			byte [] w = wire[0];
			for(int i=0; i < 4; i++ ) {
				counts[i] = ((w[4+2*i] & 0xff) << 8) | (w[5+2*i] & 0xff);
			}
		}
		header(sb, OPCODE_UPDATE, 0, rendered ? id : 0, "", counts);
		//  (nsupdate shows the zone it was given, even after sending to a zone it found)
		if( userZone != null ) {
			sb.append(";; ZONE SECTION:\n");
			sb.append(questionLine(userZone, getZoneClass(), SOA));
			sb.append('\n');
		}
		section(sb, "PREREQUISITE", prereqs, false);
		section(sb, "UPDATE", updates, false);
		if( rendered && wire.length > 0 ) {
			tsigSection(sb, wire[0]);
		}
		s.print(sb);
		s.flush();
	}

	/** A received message. */
	static void showReply(PrintStream s, Reply r, String description) {
		StringBuilder sb = new StringBuilder(description).append('\n');
		byte [] w = r.wire;
		int opcode = (w[2] >> 3) & 0xf;
		int rcode = w[3] & 0xf;
		int id = ((w[0] & 0xff) << 8) | (w[1] & 0xff);
		StringBuilder flags = new StringBuilder();
		if( (w[2] & 0x80) != 0 ) flags.append(" qr");
		if( (w[2] & 0x04) != 0 ) flags.append(" aa");
		if( (w[2] & 0x02) != 0 ) flags.append(" tc");
		if( (w[2] & 0x01) != 0 ) flags.append(" rd");
		if( (w[3] & 0x80) != 0 ) flags.append(" ra");
		if( (w[3] & 0x20) != 0 ) flags.append(" ad");
		if( (w[3] & 0x10) != 0 ) flags.append(" cd");
		int [] counts = new int[4];
		for(int i=0; i < 4; i++ ) {
			counts[i] = ((w[4+2*i] & 0xff) << 8) | (w[5+2*i] & 0xff);
		}
		RR opt = null;
		List<RR> additional = new ArrayList<RR>();
		for(RR rr : r.msg.getAdditional()) {
			if( rr.getType() == OPT ) {
				opt = rr;
			} else if( rr.getType() != Tsig.TYPE ) {
				additional.add(rr);
			}
		}
		if( opt != null ) {
			//  The extended RCODE is in the OPT record
			rcode |= ((opt.getTTL() >>> 24) & 0xff) << 4;
		}
		header(sb, opcode, rcode, id, flags.toString(), counts);
		if( opt != null ) {
			sb.append(";; OPT PSEUDOSECTION:\n");
			sb.append("; EDNS: version: ").append((opt.getTTL() >> 16) & 0xff).append(", flags:");
			if( (opt.getTTL() & 0x8000) != 0 ) {
				sb.append(" do");
			}
			sb.append("; udp: ").append(opt.getDnsClass()).append('\n');
		}
		boolean update = opcode == OPCODE_UPDATE;
		if( !r.msg.getQuestion().isEmpty() ) {
			sb.append(";; ").append(update ? "ZONE" : "QUESTION").append(" SECTION:\n");
			for(Section q : r.msg.getQuestion()) {
				sb.append(questionLine(absolute(q.getName().isEmpty() ? "." : q.getName()), q.getDnsClass(), q.getType()));
			}
			sb.append('\n');
		}
		section(sb, update ? "PREREQUISITE" : "ANSWER", r.msg.getAnswer(), true);
		section(sb, update ? "UPDATE" : "AUTHORITY", r.msg.getAuthority(), true);
		section(sb, "ADDITIONAL", additional, true);
		tsigSection(sb, w);
		s.print(sb);
		s.flush();
	}

	private static void header(StringBuilder sb, int opcode, int rcode, int id, String flags, int [] counts) {
		boolean update = opcode == OPCODE_UPDATE;
		sb.append(";; ->>HEADER<<- opcode: ").append(OPCODES[opcode & 0xf]).append(", status: ").append(rcodeText(rcode))
		.append(", id: ").append(String.format("%6d", id)).append('\n');
		sb.append(";; flags:").append(flags).append("; ")
		.append(update ? "ZONE: " : "QUESTION: ").append(counts[0]).append(", ")
		.append(update ? "PREREQ: " : "ANSWER: ").append(counts[1]).append(", ")
		.append(update ? "UPDATE: " : "AUTHORITY: ").append(counts[2]).append(", ")
		.append("ADDITIONAL: ").append(counts[3]).append('\n');
	}

	private static void section(StringBuilder sb, String title, List<RR> records, boolean grouped) {
		if( records.isEmpty() ) {
			return;
		}
		sb.append(";; ").append(title).append(" SECTION:\n");
		for(RR rr : grouped ? grouped(records) : records) {
			sb.append(recordLine(rr));
		}
		sb.append('\n');
	}

	private static void tsigSection(StringBuilder sb, byte [] wire) {
		Tsig.Record t = Tsig.find(wire);
		if( t == null ) {
			return;
		}
		sb.append(";; TSIG PSEUDOSECTION:\n");
		StringBuilder data = new StringBuilder();
		data.append(absolute(t.algorithm)).append(' ').append(t.timeSigned).append(' ').append(t.fudge).append(' ').append(t.mac.length);
		if( t.mac.length > 0 ) {
			data.append(' ').append(split(Base64.getEncoder().encodeToString(t.mac)));
		}
		data.append(' ').append(t.originalId).append(' ').append(tsigErrorText(t.error)).append(' ').append(t.other.length).append(' ');
		if( t.other.length > 0 ) {
			data.append(split(Base64.getEncoder().encodeToString(t.other)));
		}
		sb.append(columns(absolute(t.keyName), "0", "ANY", "TSIG", data.toString()));
		sb.append('\n');
	}

	/** The records grouped by owner and type (as BIND keeps a parsed message) */
	private static List<RR> grouped(List<RR> section) {
		Map<String,Map<Integer,List<RR>>> byName = new LinkedHashMap<String,Map<Integer,List<RR>>>();
		for(RR rr : section) {
			String key = stripDot(rr.getName()).toLowerCase(Locale.ROOT);
			Map<Integer,List<RR>> byType = byName.computeIfAbsent(key, k -> new LinkedHashMap<Integer,List<RR>>());
			byType.computeIfAbsent(rr.getType()*65536+rr.getDnsClass(), k -> new ArrayList<RR>()).add(rr);
		}
		List<RR> ret = new ArrayList<RR>();
		for(Map<Integer,List<RR>> byType : byName.values()) {
			for(List<RR> set : byType.values()) {
				ret.addAll(set);
			}
		}
		return ret;
	}

	static String questionLine(String name, int cls, int type) {
		StringBuilder sb = new StringBuilder(";");
		StringBuilder line = new StringBuilder(nameText(name, false));
		int column = line.length();
		column = indent(line, column, 32);
		line.append(className(cls));
		column += className(cls).length();
		indent(line, column, 40);
		line.append(typeName(type));
		return sb.append(line).append('\n').toString();
	}

	static String recordLine(RR rr) {
		String data = rr.getRdata() != null && rr.getRdata().length == 0 && (rr.getDnsClass() == CLASS_ANY || rr.getDnsClass() == CLASS_NONE)
				? "" : rdataText(rr);
		return columns(nameText(rr.getName(), false), Long.toString(rr.getTTL() & 0xffffffffL), className(rr.getDnsClass()), typeName(rr.getType()), data);
	}

	/** Owner, TTL, class, type and data at BIND's columns (24, 32, 40, 48; tabs of 8). */
	static String columns(String owner, String ttl, String cls, String type, String data) {
		StringBuilder sb = new StringBuilder(owner);
		int column = owner.length();
		column = indent(sb, column, 24);
		sb.append(ttl);
		column += ttl.length();
		column = indent(sb, column, 32);
		sb.append(cls);
		column += cls.length();
		column = indent(sb, column, 40);
		sb.append(type);
		column += type.length();
		indent(sb, column, 48);
		sb.append(data).append('\n');
		return sb.toString();
	}

	/** BIND's indent(): tabs (of 8) to the column, at least one space past the current one. */
	private static int indent(StringBuilder sb, int from, int to) {
		if( to < from+1 ) {
			to = from+1;
		}
		int ntabs = to/8 - from/8;
		if( ntabs > 0 ) {
			for(int i=0; i < ntabs; i++ ) {
				sb.append('\t');
			}
			from = (to/8)*8;
		}
		for(int i=from; i < to; i++ ) {
			sb.append(' ');
		}
		return to;
	}

	/** A name as BIND prints it: absolute (or without the final dot) */
	static String nameText(String name, boolean omitFinalDot) {
		String n = name == null ? "" : name;
		if( n.isEmpty() || n.equals(".") ) {
			return ".";
		}
		n = absolute(n);
		return omitFinalDot ? n.substring(0, n.length()-1) : n;
	}

	/** Split base64 or hex into words of 56 characters (as nsupdate prints them). */
	static String split(String s) {
		StringBuilder sb = new StringBuilder();
		for(int i=0; i < s.length(); i += 56 ) {
			if( sb.length() > 0 ) {
				sb.append(' ');
			}
			sb.append(s, i, Math.min(s.length(), i+56));
		}
		return sb.toString();
	}

	/** The data of a record in presentation format (as BIND prints it). */
	static String rdataText(RR rr) {
		int type = rr.getType();
		switch(type) {
		case DS:
		case 59:	//  CDS
			return splitAfter(NsLookup.rdataText(rr), 3);
		case DNSKEY:
		case 60:	//  CDNSKEY
			return splitAfter(NsLookup.rdataText(rr), 3);
		case RRSIG:
			return splitAfter(NsLookup.rdataText(rr), 8);
		case SVCB:
		case HTTPS: {
			//  As BIND: alpn quoted; printable characters not escaped
			String t = NsLookup.rdataText(rr).replaceAll("(^| )alpn=([^\" ]+)", "$1alpn=\"$2\"");
			Matcher m = Pattern.compile("\\\\(\\d{3})").matcher(t);
			StringBuffer sb = new StringBuffer();
			while( m.find() ) {
				int c = Integer.parseInt(m.group(1));
				String rep = c >= 0x20 && c < 0x7f && c != '"' && c != '\\' ? String.valueOf((char)c) : m.group(0);
				m.appendReplacement(sb, Matcher.quoteReplacement(rep));
			}
			m.appendTail(sb);
			return sb.toString();
		}
		case HINFO:
			if( rr instanceof us.bringardner.net.dns.Hinfo && rr.getRdata() == null ) {
				us.bringardner.net.dns.Hinfo h = (us.bringardner.net.dns.Hinfo) rr;
				return NsLookup.characterStrings(characterString(h.getCpu(), h.getOs()));
			}
			break;
		default:
			break;
		}
		if( type == A && rr.getDnsClass() == 3 && rr.getRdata() != null && rr.getRdata().length >= 3 ) {
			//  CH A: domain and octal address
			byte [] d = rr.getRdata();
			StringBuilder n = new StringBuilder();
			int pos = 0;
			while( pos < d.length && d[pos] != 0 ) {
				int len = d[pos++] & 0xff;
				n.append(new String(d, pos, Math.min(len, d.length-pos), StandardCharsets.ISO_8859_1)).append('.');
				pos += len;
			}
			pos++;
			if( pos+2 == d.length ) {
				return (n.length() == 0 ? "." : n.toString())+" "+Integer.toOctalString(((d[pos] & 0xff) << 8) | (d[pos+1] & 0xff));
			}
		}
		if( rr.getClass() == RR.class ) {
			String g = NsLookup.generic(rr.getRdata());
			int sp = g.indexOf(' ', 3);
			return sp < 0 ? g : g.substring(0, sp+1)+split(g.substring(sp+1));
		}
		return NsLookup.rdataText(rr);
	}

	/** Strings as <character-string>s (UTF-8). */
	private static byte [] characterString(String ... strings) {
		ByteArrayOutputStream b = new ByteArrayOutputStream();
		for(String str : strings) {
			byte [] d = (str == null ? "" : str).getBytes(StandardCharsets.UTF_8);
			b.write(Math.min(d.length, 255));
			b.write(d, 0, Math.min(d.length, 255));
		}
		return b.toByteArray();
	}

	/** The fields after the first n joined and split in words of 56 (base64 / hex). */
	private static String splitAfter(String text, int n) {
		String [] tok = text.trim().split("\\s+");
		if( tok.length <= n ) {
			return text;
		}
		StringBuilder sb = new StringBuilder();
		for(int i=0; i < n; i++ ) {
			sb.append(tok[i]).append(' ');
		}
		sb.append(split(String.join("", Arrays.asList(tok).subList(n, tok.length))));
		return sb.toString();
	}

	private static byte [] rdataOf(RR rr) {
		return rr.getRdata();
	}

	static String rcodeText(int rcode) {
		return NsLookup.rcodeText(rcode);
	}

	static String tsigErrorText(int error) {
		switch(error) {
		case 0: return "NOERROR";
		case 16: return "BADSIG";
		case 17: return "BADKEY";
		case 18: return "BADTIME";
		case 19: return "BADMODE";
		case 20: return "BADNAME";
		case 21: return "BADALG";
		case 22: return "BADTRUNC";
		default: return error < 16 ? rcodeText(error) : Integer.toString(error);
		}
	}

	static String sockaddr(InetSocketAddress a) {
		return NsLookup.sockaddr(a.getAddress(), a.getPort());
	}

	/** Type code for a name (A, TYPE65280, ...), or -1. */
	static int typeCode(String name) {
		if( name.equalsIgnoreCase("ANY") ) {
			return QTYPE_ALL;
		}
		return NsLookup.typeCode(name);
	}

	static String typeName(int type) {
		return NsLookup.typeName(type);
	}

	/** Class code for a name (IN, CH, HS, NONE, ANY, CLASSnnn), or -1. */
	static int classCode(String name) {
		return NsLookup.classCode(name);
	}

	static String className(int cls) {
		return NsLookup.className(cls);
	}

	/** Test hook: the records of the update being built. */
	static List<RR> pendingUpdates() {
		return updates;
	}

	static InputStream nullInput() {
		return new java.io.ByteArrayInputStream(new byte[0]);
	}
}
