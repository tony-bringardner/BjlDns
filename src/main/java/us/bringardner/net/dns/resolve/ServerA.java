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

import java.net.InetAddress;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import us.bringardner.net.dns.A;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.DnsBaseClass;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.Section;

/**
 * One address of a remote (upstream) name server.
 * <p>
 * Thread-safe: one ServerA is shared by all ResolverThreads (through the
 * Resolver's server map), so every query builds its own Message and all
 * statistics / state are atomic or volatile.
 * <p>
 * After more than MAX_TRIES consecutive failures the server is marked
 * inactive for DEACTIVATE ms. When that time has passed it gets one more
 * try; if that also fails it is deactivated again.
 */
public class ServerA  extends DnsBaseClass
{
	//  One Hour
	public static long DEACTIVATE=(1*60*60*1000);  
	public static int MAX_TRIES=2;
	/** Per-attempt timeout (ms) and attempts per query sent to one upstream address */
	public static int QUERY_TIMEOUT = 2000;
	public static int QUERY_RETRY = 1;

	private final AtomicInteger msgSent = new AtomicInteger();
	private final AtomicInteger msgRec  = new AtomicInteger();
	private final AtomicLong totResp = new AtomicLong();
	private final AtomicInteger consecutiveFailures = new AtomicInteger();
	private volatile long lastReq = 0;
	//  Inactive until this time (ms). 0 == active
	private volatile long inactiveUntil = 0;

	private volatile String name;
	private volatile String addrStr;
	private volatile InetAddress addr;
	private volatile int port = DNS.DNSPORT;

	/**
	 * Constructor for ServerA
	 */
	public ServerA(String n, String addr) {
		setName(n);
		if( addr != null ) {
			setAddress(addr);
		} else {
			log("No address for "+name+", looking up by name");
			setAddress(n);
		}
	}
	
	/**
	 * Constructor for ServerA
	 */
	public ServerA(A rr)  {
		setName( rr.getName());
		setAddress(rr.getAddressString());
	}

	/** Average response time (ms) over all queries sent, 0 if none sent. */
	public int aveResponseTime() { 
		int sent = msgSent.get();
		return sent == 0 ? 0 : (int)(totResp.get()/sent); 
	}
	
	/** Queries sent per response received (1 == every query answered), 0 if none answered. */
	public int battingAve() { 
		int rec = msgRec.get();
		return rec == 0 ? 0 : msgSent.get() / rec; 
	}

	public int getMsgSent() {
		return msgSent.get();
	}

	public int getMsgRec() {
		return msgRec.get();
	}

	public long getLastReq() {
		return lastReq;
	}
	
	/**
	 * @return true if this server may be queried now (never deactivated, or
	 * the deactivation period has passed).
	 */
	public boolean isActive() {
		return System.currentTimeMillis() >= inactiveUntil;
	}

	/**
	 * Send a query to this server.
	 * 
	 * @return the response, or null if the server is inactive, has no
	 * address, or did not answer.
	 */
	public Message query(Section q) {
		if( !isActive() ) {
			return null;
		}

		InetAddress server = addr;
		if ( server == null ) {
			return null;
		}

		//  A new Message for every query. The old code shared one Message per
		//  server between all resolver threads, so one thread could send (and
		//  receive the answer to) another thread's question.
		Message qm = new Message();
		qm.setServer(server);
		qm.setPort(port);
		qm.setQuestion(q);
		qm.setTimeOut(QUERY_TIMEOUT);
		qm.setRetry(QUERY_RETRY);

		long start = System.currentTimeMillis();
		lastReq = start;
		msgSent.incrementAndGet();

		Message ret = null;
		try {
			ret = qm.query();
		} catch(Exception ex) {
			//  Timeout or I/O error, counted as a failure below
		}

		totResp.addAndGet(System.currentTimeMillis()-start);

		if( ret != null ) {
			msgRec.incrementAndGet();
			consecutiveFailures.set(0);
			inactiveUntil = 0;
		} else {
			if( consecutiveFailures.incrementAndGet() > MAX_TRIES ) {
				inactiveUntil = System.currentTimeMillis()+DEACTIVATE;
			}
		}

		return ret;
	}

	/**
	 * Force this server active (clears the failure count) or inactive for DEACTIVATE ms.
	 */
	public void setActive(boolean newActive) {
		if( newActive ) {
			consecutiveFailures.set(0);
			inactiveUntil = 0;
		} else {
			inactiveUntil = System.currentTimeMillis()+DEACTIVATE;
		}
	}

	public final void setAddress(String ip) {
		try {
			addrStr = ip;
			addr = InetAddress.getByName(ip);
		} catch(Exception ex) {
			//  This should never throw an exception since we're using the IP address			
			//  So I'll just assume for the moment that there is nothing to do here
			log("Error setting addr in SearverA ip = "+ip,ex);
		}
	}

	public InetAddress getAddress() {
		return addr;
	}

	/** UDP/TCP port of this server (default 53). */
	public int getPort() {
		return port;
	}

	public void setPort(int port) {
		this.port = port;
	}
	
	public final void setName(String n) { 
		name = n; 
	}
	
	public String toString() {
		return (name == null ? "" : name)+"("+addrStr+(port == DNS.DNSPORT ? "" : ":"+port)+") ";
	}
	
}
