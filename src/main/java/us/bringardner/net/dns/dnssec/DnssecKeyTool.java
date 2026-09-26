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
 */
package us.bringardner.net.dns.dnssec;

import java.io.File;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import us.bringardner.net.dns.Ds;

/**
 * Command line tool for DNSSEC keys.
 * <pre>
 * keygen [-a ALGORITHM] [-b BITS] [-ksk | -zsk] [-d DIR] ZONE
 *     Make a key and write K&lt;zone&gt;.+&lt;alg&gt;+&lt;tag&gt;.key and .private into DIR
 *     (default: the current directory). Without -ksk or -zsk the key is a
 *     combined signing key (flags 257) that signs everything, which is all a
 *     zone needs. ALGORITHM: ECDSAP256SHA256 (default), ECDSAP384SHA384,
 *     ED25519, RSASHA256, RSASHA512.
 * ds [-d DIR] ZONE
 *     Print the DS records to give the parent zone (for the zone's key
 *     signing keys).
 * </pre>
 * Keys made with BIND's dnssec-keygen can be used too.
 */
public final class DnssecKeyTool {

	private DnssecKeyTool() {
	}

	public static void main(String[] args) {
		System.exit(run(args, System.out, System.err));
	}

	/** @return the exit code */
	public static int run(String[] args, PrintStream out, PrintStream err) {
		if( args.length == 0 ) {
			return usage(err);
		}
		String cmd = args[0];
		String alg = "ECDSAP256SHA256";
		int bits = 0;
		String kind = "csk";
		File dir = new File(".");
		String zone = null;
		try {
			for(int i=1; i < args.length; i++ ) {
				String a = args[i];
				switch(a) {
				case "-a": alg = args[++i]; break;
				case "-b": bits = Integer.parseInt(args[++i]); break;
				case "-ksk": kind = "ksk"; break;
				case "-zsk": kind = "zsk"; break;
				case "-d": dir = new File(args[++i]); break;
				default:
					if( a.startsWith("-") || zone != null ) {
						return usage(err);
					}
					zone = a;
				}
			}
		} catch(ArrayIndexOutOfBoundsException | NumberFormatException ex) {
			return usage(err);
		}
		if( zone == null ) {
			return usage(err);
		}
		try {
			switch(cmd) {
			case "keygen": {
				if( !dir.isDirectory() ) {
					err.println(dir+" is not a directory");
					return 1;
				}
				DnssecKey k = DnssecKey.generate(zone, Algorithm.of(alg), !kind.equals("zsk"), bits);
				File f = k.save(dir);
				out.println("Wrote "+f+" and its .private file ("+k+")");
				if( k.isKsk() ) {
					out.println("DS records for the parent zone of "+k.getZone()+":");
					out.println(dsText(k, Ds.SHA256));
				}
				return 0;
			}
			case "ds": {
				List<String> errors = new ArrayList<String>();
				Map<String, List<DnssecKey>> keys = DnssecKey.loadDir(dir, errors);
				for(String e : errors) {
					err.println(e);
				}
				List<DnssecKey> list = keys.get(Canonical.key(zone));
				if( list == null ) {
					err.println("No keys for "+zone+" in "+dir);
					return 1;
				}
				boolean any = false;
				for(DnssecKey k : list) {
					if( k.isKsk() ) {
						out.println(dsText(k, Ds.SHA256));
						any = true;
					}
				}
				if( !any ) {
					err.println("No key signing key (flags 257) for "+zone+" in "+dir);
					return 1;
				}
				return 0;
			}
			default:
				return usage(err);
			}
		} catch(Exception ex) {
			err.println(ex.getMessage());
			return 1;
		}
	}

	static String dsText(DnssecKey k, int digestType) {
		Ds ds = k.toDs(digestType, 3600);
		return k.getZone()+". IN DS "+ds.getRdataAsString();
	}

	private static int usage(PrintStream err) {
		err.println("usage: DnssecKeyTool keygen [-a ALGORITHM] [-b BITS] [-ksk | -zsk] [-d DIR] ZONE");
		err.println("       DnssecKeyTool ds [-d DIR] ZONE");
		err.println("ALGORITHM: ECDSAP256SHA256 (default), ECDSAP384SHA384, ED25519, RSASHA256, RSASHA512");
		return 2;
	}
}
