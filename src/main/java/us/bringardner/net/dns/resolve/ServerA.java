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
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.Section;

/**
 * One address of a remote (upstream) name server.
 * <p>
 * Thread-safe: one ServerA is shared by all ResolverThreads (through the
 * Resolver's server map), so every query builds its own Message and all
 * statistics / state are atomic or volatile.
 * <p>
 * After more than MAX_TRIES consecutive failures the server is marked
 * inactive for a hold-off that starts at HOLD_OFF_MIN ms and doubles with
 * every further failure, up to DEACTIVATE ms. When the hold-off has passed
 * it gets one more try. Any answer makes it active again.
 * <p>
 * It used to be inactive for a whole hour after 3 failures: a short network
 * outage (a router restart) turned off every root server address and all
 * recursion failed for the next hour.
 */
public class ServerA  extends DnsBaseClass
{
	/** Longest hold-off (ms) for a server that keeps failing (default 10 minutes, JDns.upstreamHoldOffMax). */
	public static volatile long DEACTIVATE=10*60*1000L;
	/** First hold-off (ms) after MAX_TRIES+1 failures in a row (default 5 s, JDns.upstreamHoldOffMin). */
	public static volatile long HOLD_OFF_MIN=5*1000L;
	/** A server that is held off is probed at most this often (ms) when no server of its zone is available. */
	public static volatile long PROBE_INTERVAL=1000L;
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
	//  No probe (query while inactive) before this time (ms)
	private final AtomicLong nextProbe = new AtomicLong();

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
		}
		//  else: a name server without glue. Its address is looked up through
		//  our own resolver when it is first queried (lookupAddress). It used
		//  to be InetAddress.getByName(name) right here: a blocking OS lookup
		//  in the resolver thread that could even query this server.
	}

	/** Most glueless name server lookups nested inside each other (per thread). */
	static final int MAX_GLUE_DEPTH = 3;
	//  Names whose address this thread is looking up (loop guard)
	private static final ThreadLocal<java.util.Set<String>> lookingUp =
			ThreadLocal.withInitial(java.util.HashSet::new);

	/**
	 * Find the address of a name server that came without glue, through the
	 * Resolver (cache, validated upstream queries). A lookup that needs itself
	 * (e.g. ns.example.com for example.com with no glue) or is nested deeper
	 * than MAX_GLUE_DEPTH gives up instead of recursing.
	 * 
	 * @return the address, or null if it can't be found
	 */
	private InetAddress lookupAddress() {
		String n = name;
		if( n == null ) {
			return null;
		}
		java.util.Set<String> busy = lookingUp.get();
		String key = n.toLowerCase();
		if( busy.contains(key) || busy.size() >= MAX_GLUE_DEPTH ) {
			return null;
		}
		busy.add(key);
		try {
			Message m = Resolver.resolve(new Section(n, DNS.A, DNS.IN));
			if( m != null ) {
				for(RR rr : m.getAnswer()) {
					if( rr instanceof A ) {
						//  From the address bytes: no DNS lookup
						InetAddress a = InetAddress.getByAddress(n, ((A)rr).getAddress());
						addrStr = a.getHostAddress();
						addr = a;
						return a;
					}
				}
			}
		} catch(Exception ex) {
			log(() -> "Could not look up name server "+n+": "+ex);
		} finally {
			busy.remove(key);
		}
		return null;
	}

	public String getName() {
		return name;
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
	/** Shortest timeout used for a server whose response time is known (ms). */
	public static int MIN_QUERY_TIMEOUT = 300;
	/** Smoothed response time in ms (EWMA, 1/8 weight), 0 if never answered. */
	private volatile double srtt = 0;

	/** Smoothed response time (ms); 0 if this server has never answered. */
	public long getSrtt() {
		return Math.round(srtt);
	}

	/** Record a response time (or a failure penalty) in the smoothed average. */
	private synchronized void recordRtt(long ms) {
		srtt = srtt == 0 ? ms : (7*srtt + ms) / 8;
	}

	/**
	 * Timeout for the next query: about twice the smoothed response time
	 * (MIN_QUERY_TIMEOUT..QUERY_TIMEOUT) once it is known, QUERY_TIMEOUT
	 * before that, never more than 'remaining'.
	 */
	public int timeoutFor(long remaining) {
		long t = srtt > 0 ? Math.max(MIN_QUERY_TIMEOUT, Math.min(QUERY_TIMEOUT, Math.round(srtt*2)+100)) : QUERY_TIMEOUT;
		return (int)Math.max(1, Math.min(t, remaining));
	}

	public Message query(Section q) {
		return query(q, QUERY_TIMEOUT);
	}

	/**
	 * Send a query to this server, waiting at most timeoutMs per attempt.
	 * @return the response, or null (inactive, no address, no answer)
	 */
	public Message query(Section q, int timeoutMs) {
		return query(q, timeoutMs, 0, false);
	}

	/**
	 * Send a query to this server.
	 * 
	 * @param timeoutMs longest wait per attempt
	 * @param deadline absolute time (ms) after which the query gives up,
	 *  including a TCP retry after a truncated answer; 0 for none
	 * @param probe query even if the server is inactive, when tryProbe()
	 *  allows it (no other server of the zone is available)
	 * @return the response, or null (inactive, no address, no answer)
	 */
	public Message query(Section q, int timeoutMs, long deadline, boolean probe) {
		if( !isActive() && !(probe && tryProbe()) ) {
			return null;
		}

		InetAddress server = addr;
		if ( server == null ) {
			server = lookupAddress();
		}
		if ( server == null ) {
			//  Unknown address counts as a failure (deactivates after MAX_TRIES)
			failed();
			return null;
		}

		//  A new Message for every query. The old code shared one Message per
		//  server between all resolver threads, so one thread could send (and
		//  receive the answer to) another thread's question.
		Message qm = new Message();
		qm.setServer(server);
		qm.setPort(port);
		qm.setQuestion(q);
		qm.setTimeOut(Math.max(1, timeoutMs));
		qm.setRetry(QUERY_RETRY);
		qm.setDeadline(deadline);
		if( Resolver.isValidating() ) {
			//  Ask for the DNSSEC records (DO, RFC 3225) and, should this be a
			//  recursive server, for answers it could not validate itself (CD):
			//  we validate them
			qm.addAdditional(us.bringardner.net.dns.Edns.newOpt(0, true));
			qm.getHeader().setCD(true);
		}

		long start = System.currentTimeMillis();
		lastReq = start;
		msgSent.incrementAndGet();

		Message ret = null;
		try {
			ret = qm.query();
		} catch(Exception ex) {
			//  Timeout or I/O error, counted as a failure below
		}

		long rtt = System.currentTimeMillis()-start;
		totResp.addAndGet(rtt);
		if( ret != null ) {
			msgRec.incrementAndGet();
			recordRtt(Math.max(1, rtt));
			consecutiveFailures.set(0);
			inactiveUntil = 0;
		} else {
			//  A timeout counts as a slow answer so the server sorts behind responsive ones
			recordRtt(Math.max(rtt, QUERY_TIMEOUT) * 2L);
			failed();
		}

		return ret;
	}

	/** Count a failure; past MAX_TRIES in a row, hold the server off (doubling, up to DEACTIVATE). */
	private void failed() {
		int n = consecutiveFailures.incrementAndGet();
		if( n > MAX_TRIES ) {
			inactiveUntil = System.currentTimeMillis()+holdOff(n - MAX_TRIES);
		}
	}

	/** Hold-off (ms) after the k-th failure past MAX_TRIES (k >= 1): HOLD_OFF_MIN doubled k-1 times, at most DEACTIVATE. */
	static long holdOff(int k) {
		long max = DEACTIVATE;
		long ret = HOLD_OFF_MIN;
		for(int i=1; i < k && ret < max; i++ ) {
			ret *= 2;
		}
		return Math.max(1, Math.min(ret, max));
	}

	/** When this server may be queried again (ms); 0 or a past time if it is active. */
	public long getInactiveUntil() {
		return inactiveUntil;
	}

	/**
	 * May an inactive server be probed now? True at most once per
	 * PROBE_INTERVAL, so while every server of a zone is down each one gets
	 * one query a second from all threads together.
	 */
	boolean tryProbe() {
		long now = System.currentTimeMillis();
		long next = nextProbe.get();
		return now >= next && nextProbe.compareAndSet(next, now + PROBE_INTERVAL);
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
