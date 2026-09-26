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
package us.bringardner.net.dns.server;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.Section;
import us.bringardner.net.dns.Soa;

/**
 * Applies one RFC 2136 UPDATE message to a copy of a zone: checks the
 * prerequisites, pre-scans the updates, then makes the changes. Nothing is
 * changed unless everything is valid (the caller publishes the new zone and
 * writes the journal lines).
 */
public class ZoneUpdater implements DNS {

	//  RCODEs of RFC 2136 2.2
	public static final int YXDOMAIN = 6;
	public static final int YXRRSET = 7;
	public static final int NXRRSET = 8;
	public static final int NOTAUTH = 9;
	public static final int NOTZONE = 10;

	public static final int CLASS_NONE = 254;
	public static final int CLASS_ANY = 255;
	private static final int TYPE_ANY = 255;

	/** The outcome: an RCODE and, if something changed, the new zone and its journal lines. */
	public static final class Result {
		public final int rcode;
		public final Zone zone;
		public final List<String> journal;

		Result(int rcode, Zone zone, List<String> journal) {
			this.rcode = rcode;
			this.zone = zone;
			this.journal = journal;
		}

		public boolean changed() {
			return zone != null;
		}
	}

	private static Result fail(int rcode) {
		return new Result(rcode, null, null);
	}

	private static boolean isMeta(int type) {
		return type == AXFR || type == IXFR || type == 253 || type == 254 || type == TYPE_ANY || type == OPT;
	}

	/**
	 * @param zone the zone named in the zone section (already checked to be ours)
	 * @param req the UPDATE message
	 */
	public static Result apply(Zone zone, Message req) {
		int zclass = zone.getSoa().getDnsClass();

		// ---- prerequisites (RFC 2136 3.2)
		Map<String, Set<String>> valueDependent = new HashMap<String, Set<String>>();
		for(RR p : req.getAnswer()) {
			String name = p.getName();
			if( p.getTTL() != 0 ) {
				return fail(FORMAT_ERROR);
			}
			if( !zone.contains(name) ) {
				return fail(NOTZONE);
			}
			int cls = p.getDnsClass();
			int type = p.getType();
			List<RR> here = zone.exactRecords(name);
			boolean empty = p.getRdLength() == 0;
			if( cls == CLASS_ANY ) {
				if( !empty ) {
					return fail(FORMAT_ERROR);
				}
				if( type == TYPE_ANY ) {
					if( here.isEmpty() && !zone.isApex(name) ) {
						return fail(NAME_ERROR);
					}
				} else if( !hasType(zone, here, name, type) ) {
					return fail(NXRRSET);
				}
			} else if( cls == CLASS_NONE ) {
				if( !empty ) {
					return fail(FORMAT_ERROR);
				}
				if( type == TYPE_ANY ) {
					if( !here.isEmpty() || zone.isApex(name) ) {
						return fail(YXDOMAIN);
					}
				} else if( hasType(zone, here, name, type) ) {
					return fail(YXRRSET);
				}
			} else if( cls == zclass ) {
				if( isMeta(type) ) {
					return fail(FORMAT_ERROR);
				}
				valueDependent.computeIfAbsent(setKey(name, type), k -> new HashSet<String>()).add(Zone.recordKey(p));
			} else {
				return fail(NOTZONE);
			}
		}
		for(Map.Entry<String, Set<String>> e : valueDependent.entrySet()) {
			String [] nt = e.getKey().split(" ");
			int type = Integer.parseInt(nt[1]);
			Set<String> have = new HashSet<String>();
			for(RR rr : zone.exactRecords(nt[0])) {
				if( rr.getType() == type ) {
					have.add(Zone.recordKey(rr));
				}
			}
			if( type == SOA && zone.isApex(nt[0]) ) {
				have.add(Zone.recordKey(zone.getSoa()));
			}
			if( !have.equals(e.getValue()) ) {
				return fail(NXRRSET);
			}
		}

		// ---- pre-scan the updates (RFC 2136 3.4.1)
		List<RR> updates = req.getAuthority();
		for(RR u : updates) {
			if( !zone.contains(u.getName()) ) {
				return fail(NOTZONE);
			}
			int cls = u.getDnsClass();
			int type = u.getType();
			if( cls == zclass ) {
				if( isMeta(type) ) {
					return fail(FORMAT_ERROR);
				}
				if( type != SOA && !Zone.isUpdatableType(type) ) {
					//  Kept in the journal as zone file text, which the reader must understand
					return fail(REFUSED);
				}
			} else if( cls == CLASS_ANY ) {
				if( u.getTTL() != 0 || u.getRdLength() != 0 || (isMeta(type) && type != TYPE_ANY) ) {
					return fail(FORMAT_ERROR);
				}
			} else if( cls == CLASS_NONE ) {
				if( u.getTTL() != 0 || isMeta(type) ) {
					return fail(FORMAT_ERROR);
				}
			} else {
				return fail(FORMAT_ERROR);
			}
		}

		// ---- make the changes (RFC 2136 3.4.2) on a copy
		Zone z = zone.copyForUpdate();
		List<String> journal = new ArrayList<String>();
		boolean soaSet = false;
		for(RR u : updates) {
			String name = u.getName();
			int cls = u.getDnsClass();
			int type = u.getType();
			boolean apex = z.isApex(name);
			if( cls == zclass ) {
				if( type == SOA ) {
					if( apex && serialNewer(((Soa)u).getSerial(), z.getSoa().getSerial()) ) {
						Soa s = (Soa)z.getSoa().copy();
						s.setSerial(((Soa)u).getSerial());
						z.replaceSoa(s);
						journal.add("serial "+Integer.toUnsignedString(s.getSerial()));
						soaSet = true;
					}
					continue;
				}
				List<RR> here = z.exactRecords(name);
				boolean hasCname = false;
				boolean hasOther = false;
				for(RR r : here) {
					if( r.getType() == CNAME ) {
						hasCname = true;
					} else {
						hasOther = true;
					}
				}
				if( type == CNAME ? hasOther : hasCname ) {
					if( type != CNAME ) {
						//  a name with a CNAME can't have other data: ignored
						continue;
					}
					if( hasOther ) {
						continue;
					}
				}
				String key = Zone.recordKey(u);
				if( type == CNAME && hasCname ) {
					//  replaces the CNAME
					z.removeRecords(name, r -> r.getType() == CNAME);
					journal.add("delset "+absolute(name)+" CNAME");
				} else if( z.removeRecords(name, r -> Zone.recordKey(r).equals(key)) > 0 ) {
					//  the same record again: new TTL
					journal.add("del "+delLine(u));
				}
				z.addRecord(u);
				journal.add("add "+Zone.recordLine(u));
			} else if( cls == CLASS_ANY ) {
				if( type == TYPE_ANY ) {
					java.util.function.Predicate<RR> which = apex ? (r -> r.getType() != NS) : (r -> true);
					if( z.removeRecords(name, which) > 0 ) {
						journal.add(apex ? "delname-keepns "+absolute(name) : "delname "+absolute(name));
					}
				} else {
					if( apex && (type == SOA || type == NS) ) {
						continue;
					}
					if( z.removeRecords(name, r -> r.getType() == type) > 0 ) {
						journal.add("delset "+absolute(name)+" "+DNS.TYPENAMES[type]);
					}
				}
			} else {
				//  CLASS NONE: delete one record
				if( type == SOA ) {
					continue;
				}
				String key = Zone.recordKey(u);
				if( apex && type == NS ) {
					int ns = 0;
					for(RR r : z.exactRecords(name)) {
						if( r.getType() == NS ) {
							ns++;
						}
					}
					if( ns <= 1 ) {
						//  never the last NS of the zone
						continue;
					}
				}
				if( z.removeRecords(name, r -> Zone.recordKey(r).equals(key)) > 0 ) {
					journal.add("del "+delLine(u));
				}
			}
		}
		if( journal.isEmpty() ) {
			//  Nothing changed (e.g. adding a record that is already there)
			return new Result(NOERROR, null, null);
		}
		if( !soaSet ) {
			//  Every change gets a new serial (RFC 2136 3.6), so secondaries see it
			Soa s = (Soa)z.getSoa().copy();
			s.setSerial(s.getSerial()+1);
			z.replaceSoa(s);
			journal.add("serial "+Integer.toUnsignedString(s.getSerial()));
		}
		z.setWildCards(true);
		return new Result(NOERROR, z, journal);
	}

	private static String absolute(String name) {
		return name.endsWith(".") ? name : name+".";
	}

	/** "owner class type rdata" for deleting one record (the request's class is NONE; the zone's is IN). */
	private static String delLine(RR rr) {
		return absolute(rr.getName())+" "+us.bringardner.net.dns.Utility.CLASSNAMES[IN]+" "+DNS.TYPENAMES[rr.getType()]+" "+Zone.rdataText(rr);
	}

	private static String setKey(String name, int type) {
		String n = name.endsWith(".") ? name.substring(0, name.length()-1) : name;
		return n.toLowerCase()+" "+type;
	}

	private static boolean hasType(Zone zone, List<RR> here, String name, int type) {
		if( type == SOA ) {
			return zone.isApex(name);
		}
		for(RR r : here) {
			if( r.getType() == type ) {
				return true;
			}
		}
		return false;
	}

	/** RFC 1982 serial number comparison: a is newer than b. */
	static boolean serialNewer(int a, int b) {
		return a != b && ((a - b) > 0);
	}

	/** The zone section of an UPDATE must name one zone, type SOA. @return null if not */
	public static Section zoneSection(Message req) {
		List<Section> q = req.getQuestion();
		if( q.size() != 1 || q.get(0).getType() != SOA ) {
			return null;
		}
		return q.get(0);
	}
}
