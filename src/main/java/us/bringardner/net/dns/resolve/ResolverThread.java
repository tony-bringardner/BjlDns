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

import java.io.IOException;
import java.net.*;

import us.bringardner.net.dns.*;

/**
 * These threads do recursive resolution and prevent the server from getting backed up.
 * Creation date: (10/15/2003 5:23:16 PM)
 * @author: Tony Bringardner
 */
public class ResolverThread extends us.bringardner.net.dns.DnsBaseClass implements Runnable 
{
	private static final String PROP_RESOLVER_BACKLOG = "Resolver.maxBacklog";
	private static SimpleObjectFIFO fifo;
	private volatile Thread thread;
	//  Set to false by stop() from another thread
	private volatile boolean running = false;


	private DatagramSocket sock;

	static {
		initResolverThread();
	}

	/**
	 * ResolverThread constructor comment.
	 */
	public ResolverThread() throws SocketException {
		super();
		sock = us.bringardner.net.dns.server.UDPProsessor.getSock();
	}
	
	//  Counters for getStats()
	private static final java.util.concurrent.atomic.AtomicLong dropped = new java.util.concurrent.atomic.AtomicLong();
	private static final java.util.concurrent.atomic.AtomicLong failed = new java.util.concurrent.atomic.AtomicLong();

	/**
	 * Queue a recursive query for a resolver thread.
	 * 
	 * @return false if it could not be queued (backlog full). The caller must
	 * then answer the client itself (SERVFAIL); it used to be dropped silently
	 * and the client waited for its own timeout.
	 */
	public static boolean addQuery(QueryData query) {
		boolean ret = false;
		try {
			synchronized (fifo) {
				if( !fifo.isFull() ) {
					fifo.add(query);
					ret = true;
				}
			}
		} catch(Exception ex) {}
		if( !ret ) {
			dropped.incrementAndGet();
		}
		return ret;
	}

	/** How often backlogFullWarning() returns a message. */
	static final long FULL_WARNING_INTERVAL_MS = 10_000;
	private static final java.util.concurrent.atomic.AtomicLong lastFullWarning = new java.util.concurrent.atomic.AtomicLong();
	private static final java.util.concurrent.atomic.AtomicLong droppedAtLastWarning = new java.util.concurrent.atomic.AtomicLong();

	/**
	 * Call after addQuery returned false. Returns a message to log at most
	 * once every 10 seconds (with the number of queries turned away since the
	 * last one), otherwise null. Under overload the server used to log an
	 * error for every query it could not queue.
	 */
	/** Test hook: the next backlogFullWarning() returns a message. */
	static void resetBacklogWarning() {
		lastFullWarning.set(0);
	}

	public static String backlogFullWarning() {
		long now = System.currentTimeMillis();
		long last = lastFullWarning.get();
		if( now - last < FULL_WARNING_INTERVAL_MS || !lastFullWarning.compareAndSet(last, now) ) {
			return null;
		}
		long total = dropped.get();
		long since = total - droppedAtLastWarning.getAndSet(total);
		return "Resolver backlog full (capacity "+getMaxBackLog()+", "+PROP_RESOLVER_BACKLOG+"): "
				+since+" queries answered without recursion since the last warning, "+total+" in total";
	}

	/** Discard all queued queries. @return how many were removed */
	public static int clearBacklog() {
		int n = 0;
		synchronized (fifo) {
			while( fifo.getSize() > 0 ) {
				try {
					fifo.remove();
				} catch(InterruptedException ex) {
					break;
				}
				n++;
			}
		}
		return n;
	}

	/** Queries refused because the backlog was full. */
	public static long getDropped() {
		return dropped.get();
	}

	/** Queries answered with SERVFAIL because resolution failed or threw. */
	public static long getFailed() {
		return failed.get();
	}

	/**
	 * One response for a CNAME chain from our zones that points outside them:
	 * the question and CNAME records of 'partial' followed by the records
	 * resolved for the target. The RCODE is the target's (RFC 6604); AA is off
	 * because part of the answer is not ours. If the target could not be
	 * resolved (resolved == null) the chain is returned with SERVFAIL.
	 */
	public static Message completeCnameAnswer(Message partial, Message resolved) {
		Message ret = new Message();
		us.bringardner.net.dns.Header h = partial.getHeader().copy();
		h.setAA(false);
		h.setTC(false);
		h.setRA(true);
		ret.setHeader(h);
		ret.setMessageTypeResponse();
		for(Section q : partial.getQuestion()) {
			ret.addQuestion(new Section(q));
		}
		for(RR rr : partial.getAnswer()) {
			ret.addAnswer(rr);
		}
		if( resolved == null ) {
			ret.setResponseCode(DNS.SERVER_ERROR);
			return ret;
		}
		for(RR rr : resolved.getAnswer()) {
			ret.addAnswer(rr);
		}
		for(RR rr : resolved.getAuthority()) {
			ret.addAuthority(rr);
		}
		for(RR rr : resolved.getAdditional()) {
			ret.addAdditional(rr);
		}
		ret.setResponseCode(resolved.getResponseCode());
		return ret;
	}

	/**
	 * A response to 'query' with no data and the given RCODE (e.g. SERVFAIL):
	 * same ID, opcode, RD and question as the request, QR=1, RA=1, AA=0.
	 */
	public static Message failure(QueryData query, int rcode) {
		Message req = query.getMessage();
		Message ret = new Message();
		us.bringardner.net.dns.Header h = req.getHeader().copy();
		h.setAA(false);
		h.setTC(false);
		h.setRA(true);
		ret.setHeader(h);
		ret.setMessageTypeResponse();
		ret.setResponseCode(rcode);
		//  The question as the client sent it (QueryData's may have followed a CNAME)
		Section q = req.getFirstQuestion() != null ? req.getFirstQuestion() : query.getQuestion();
		if( q != null ) {
			ret.setQuestion(new Section(q));
		}
		return ret;
	}
	
	public static int backlog() {
		return fifo.getSize();
	}
	
	public static int getBacklog() {
		return fifo.getSize();
	}
	
	public static int getMaxBackLog() {
		return fifo.getCapacity();
	}
	
	/**
	 * Default for Resolver.maxBacklog. It was 20: a short burst of cache
	 * misses (e.g. a page load that looks up 30 names) already overflowed it.
	 */
	public static final int DEFAULT_MAX_BACKLOG = 200;

	private static void initResolverThread() {
		int maxBacklog = DEFAULT_MAX_BACKLOG;

		String tmp = System.getProperty(PROP_RESOLVER_BACKLOG);

		if( tmp != null ) {
			try {
				maxBacklog = Integer.parseInt(tmp);
			} catch(Exception ex) {}
		}

		fifo = new SimpleObjectFIFO(maxBacklog);
	}
	
	public static void notifyThreads() {
		fifo.notifyAll();
	}
	
	/**
	 * When an object implementing interface <code>Runnable</code> is used 
	 * to create a thread, starting the thread causes the object's 
	 * <code>run</code> method to be called in that separately executing 
	 * thread. 
	 * <p>
	 * The general contract of the method <code>run</code> is that it may 
	 * take any action whatsoever.
	 *
	 * @see     java.lang.Thread#run()
	 */
	public void run() {
		//  'running' is set by start(): setting it here raced with stop() and
		//  a thread stopped right after starting would run forever.
		while( running ) {
			try {
				setState("Waiting on fifo");
				QueryData question = (QueryData)fifo.remove();
				setState("Returned on fifo");
				if( running && question != null ) {
					setState("Call Resolver", question);
					Message msg = null;
					Section toResolve = question.getResolveQuestion();
					try {
						msg = Resolver.resolve(toResolve);
					} catch(RuntimeException | StackOverflowError ex) {
						logError("Resolver failed for "+toResolve, ex);
					}
					setState("Returned from resolver");
					Message partial = question.getPartialAnswer();
					if( partial != null ) {
						//  Complete a local CNAME chain that pointed outside our zones
						if( msg == null ) {
							failed.incrementAndGet();
						}
						msg = completeCnameAnswer(partial, msg);
					} else if( msg == null ) {
						//  No answer (all servers timed out, no servers, or an error):
						//  tell the client instead of leaving it to time out.
						failed.incrementAndGet();
						msg = failure(question, DNS.SERVER_ERROR);
					}
					sendResponse(msg,question);
				}
			} catch(InterruptedException ex) {
				//  stop() interrupts the wait on the queue
				if( !running ) {
					break;
				}
			} catch(Exception ex) {
				logError("Unexpected error in resolver thread", ex);
			}
		}

		setState("Stopped");
		running = false;
	}
	
	/**
	 * 
	 * Creation date: (8/26/2001 10:41:48 AM)
	 * @param msg JDns.Message
	 */
	public void sendResponse(Message msg, QueryData query) {

		setState("SendResponse Begin");
		if( msg != null && query.getPort() != -1) {

			//  Just in case;
			msg.setID(query.getMessage().getID());

			//  The old code cut the byte array at MAXUDPLEN (a corrupt packet
			//  ending mid-record) and set TC on the shared message.
			//  EDNS: drop an upstream OPT, echo ours if the client sent one
			us.bringardner.net.dns.Edns.applyToResponse(msg, query.getEdns());
			byte [] data = msg.toByteArray(us.bringardner.net.dns.server.UDPProsessor.udpLimit(query.getEdns()));
			int dataSize = data.length;

			setState("SendResponse getPacket");
			DatagramPacket pckt = new DatagramPacket(data,dataSize,query.getClient(),query.getPort());

			setState("SendResponse gotPacket");
			try {
				setState("SendResponse before sock.send");

				sock.send(pckt);
				setState("SendResponse after sock.send");	

			} catch(IOException ex) {
				log("IOException sending reply",ex);
				setState("SendResponse IOError");
			}
		}
		setState("SendResponse End");
	}
	
	public synchronized void start(String name) {
		if( !running ) {
			running = true;
			thread = new Thread(this);
			thread.setName(name);
			thread.start();
			setState("Started");
		}
	}
	
	public void stop() {
		running = false;
		Thread t = thread;
		if( t != null ) {
			t.interrupt();
		}
	}

	/** Wait up to ms for this resolver thread to finish. @return true if it has */
	public boolean join(long ms) throws InterruptedException {
		Thread t = thread;
		if( t != null ) {
			t.join(ms);
			return !t.isAlive();
		}
		return true;
	}
	
}
