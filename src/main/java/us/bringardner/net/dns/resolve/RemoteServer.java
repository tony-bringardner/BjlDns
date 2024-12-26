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
package us.bringardner.net.dns.resolve;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import us.bringardner.net.dns.A;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.DnsBaseClass;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.Name;
import us.bringardner.net.dns.Ns;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.Section;
import us.bringardner.net.dns.server.DnsServer;


/**
 * RemoteServer represents a foreign DNS server that we may
 * send queries to.  The name is not a server name but the name from
 * the Section part of the NS record.
 **/ 
public class RemoteServer  extends DnsBaseClass {
	private String nameStr;
	private Name name;
	private List<ServerA> addr;
	//private long lastUsed;
	// a stating point for iteration
	private int pos=0; 
	public RemoteServer() {
		addr = new ArrayList<ServerA>();
		//lastUsed = System.currentTimeMillis();
	}

	public RemoteServer(String newName) {
		this(new Name(newName));
	}

	// Construct from a message
	public RemoteServer(Message msg) {
		this(msg.getFirstQuestion().getName());
		Iterator<RR> it = msg.authority();
		RR rr = null;
		RR a = null;
		List<RR> al=null;
		Map<String, List<RR>> addrs = msg.getAll();

		while(it.hasNext() ) {
			rr = (RR)it.next();
			if( rr instanceof Ns ) {
				if( nameStr == null ) {
					nameStr = rr.getName();
					name = new Name(nameStr);
				}

				al = (List<RR>)addrs.get(((Ns)rr).getNs().toLowerCase());
				if( al != null ) {  // Should never happen but, you know it will!
					Iterator<RR> ii = al.iterator();
					while( ii.hasNext() ) {
						a = (RR)ii.next();
						if( a instanceof A ) {
							addAddress((A)a);
						}
					}
				} else {
					//  NS record with no name???  I don't know why anyone would config there server this way??
					//  Th sSereverA should lookup the ip if it's needed
					addAddress(((Ns)rr).getNs(),null);
				}
			}
		}
	}

	public RemoteServer(Name newName) {
		this();
		name = newName;
	}

	public void addAddress(String nm, String ip) {
		addr.add(new ServerA(nm,ip));
	}

	public void addAddress(RR rr) {
		if( rr != null && rr instanceof A ) {
			addr.add(new ServerA((A)rr));
		}
	}

	public String getName() {
		return nameStr;
	}

	public boolean isActive() {
		boolean ret = false;

		Iterator<ServerA> it = addr.iterator();
		while(it.hasNext()) {
			if( (ret=((ServerA)it.next()).isActive())) {
				break;
			}
		}

		return ret;
	}

	public Iterator<ServerA> iterator() {
		if( pos >= addr.size() ) {
			pos = 0;
		}
		return new ServerIterator(addr,pos++);
	}


	public int matchCount(String n) {
		return name.matchCount(n);
	}

	public int matchCount(Name n) {
		return name.matchCount(n);
	}

	public int matchCount(Section n) {
		return name.matchCount(n.getName());
	}

	public Message resolve(Section nm, long maxTime) {
		Message ret = null;
		ServerA svr = null;

		//boolean db = DnsServer.isDebug();
		
		Iterator<ServerA> it = this.iterator();
		while( it.hasNext() && (System.currentTimeMillis() < maxTime || DnsServer.isDebug())) {
			svr = (ServerA)it.next();
			if( (ret=svr.query(nm)) != null ) {
				if( ret.getResponseCode() == DNS.NAME_ERROR ) {
					//lastUsed = System.currentTimeMillis();
					return ret;
				}
				if(ret.getAnswerCount() > 0 || ret.getNSCount() > 0) 
				{
					//lastUsed = System.currentTimeMillis();
					return ret;
				}
			}
		}

		return null;
	}

	public void setName(String newName ) {
		nameStr = newName;
		name = new Name(newName);
	}

	public void setName(Name newName ) {
		name = newName;
		nameStr = name.toString();
	}

	public String toString() {
		return nameStr+"("+addr.toString()+")";
	}

}
