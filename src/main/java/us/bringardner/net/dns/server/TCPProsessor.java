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
package us.bringardner.net.dns.server;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import us.bringardner.net.dns.ByteBuffer;
import us.bringardner.net.dns.DnsFormatException;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.Utility;
import us.bringardner.net.dns.resolve.QueryData;

/**
 * DNS over TCP.
 * <p>
 * A TCPProsessor is an acceptor: it accepts connections on the shared
 * listen socket and hands each one to a bounded pool, where a
 * {@link Connection} serves it (any number of length-prefixed messages,
 * RFC 1035 4.2.2 / RFC 7766) until the client closes it, it is idle for
 * the idle timeout, or an error occurs.
 * <p>
 * The old design served each connection in the acceptor thread itself
 * with a 2 minute read timeout, so 4 idle clients (TCPProcCount) blocked
 * all TCP service for 2 minutes.
 * <p>
 * When maxConnections connections are open, a new connection is closed at
 * once (the client can retry) rather than queued behind idle ones.
 * 
 * Creation date: (8/26/2001 10:41:48 AM)
 * @author: Tony Bringardner
 */
public class TCPProsessor extends DnsRequestProcessor implements Runnable {

	/** Default idle timeout (ms). RFC 7766 6.2.3: seconds, not the 2 minutes of RFC 1035. */
	public static final int DEFAULT_IDLE_TIMEOUT = 10_000;
	/** Default maximum number of connections served at once. */
	public static final int DEFAULT_MAX_CONNECTIONS = 64;
	/** Largest message a 16 bit TCP length prefix can describe. */
	static final int MAX_TCP_MESSAGE = 0xFFFF;

	private static final Object syncLok = new Object();
	//  The shared listen socket
	private static volatile ServerSocket serverSocket;
	//  Serves accepted connections
	private static volatile ThreadPoolExecutor connectionPool;
	//  Open client connections (closed on shutdown)
	private static final Set<Socket> openConnections = ConcurrentHashMap.newKeySet();
	private static volatile int idleTimeout = DEFAULT_IDLE_TIMEOUT;
	private static final AtomicLong rejected = new AtomicLong();
	//  Connection slots. A slot is taken by the acceptor and given back as
	//  the last thing a Connection does, so a freed slot can be used at once
	//  (the pool thread may still be finishing; the new connection then waits
	//  in the pool queue for a moment instead of being rejected).
	private static volatile Semaphore slots = new Semaphore(DEFAULT_MAX_CONNECTIONS);
	private static volatile int maxSlots = DEFAULT_MAX_CONNECTIONS;

	public static volatile boolean debug = false;

	/**
	 * 
	 * Creation date: (8/26/2001 11:37:51 AM)
	 * @param me int
	 */
	public TCPProsessor(DnsServer svr, int me) {
		server   = svr;
	}

	/** The shared TCP listen socket (null before initTCPProsessor). */
	public static ServerSocket getServerSocket() {
		return serverSocket;
	}

	public static void initTCPProsessor(int bindPort,int backlog,InetAddress bindAddress, int timeout) throws IOException {
		initTCPProsessor(bindPort, backlog, bindAddress, timeout, DEFAULT_MAX_CONNECTIONS, DEFAULT_IDLE_TIMEOUT);
	}

	/**
	 * @param timeout accept() timeout (ms), how often acceptors check for shutdown
	 * @param maxConnections most connections served at once
	 * @param idleTimeoutMs a connection with no request for this long is closed
	 */
	public synchronized static void initTCPProsessor(int bindPort,int backlog,InetAddress bindAddress, int timeout,
			int maxConnections, int idleTimeoutMs) throws IOException {
		//  A previous pool (re-initialization) is shut down first
		shutdownConnections(1000);

		serverSocket = new ServerSocket(bindPort,backlog,bindAddress);
		serverSocket.setSoTimeout(timeout);
		idleTimeout = idleTimeoutMs > 0 ? idleTimeoutMs : DEFAULT_IDLE_TIMEOUT;

		int max = maxConnections > 0 ? maxConnections : DEFAULT_MAX_CONNECTIONS;
		final AtomicInteger n = new AtomicInteger();
		//  Admission is limited by the slots semaphore, so the queue never
		//  holds more than a connection or two waiting for a thread to finish.
		ThreadPoolExecutor pool = new ThreadPoolExecutor(max, max, 30, TimeUnit.SECONDS,
				new LinkedBlockingQueue<Runnable>(), r -> {
					Thread t = new Thread(r, "TCPConn"+n.incrementAndGet());
					t.setDaemon(true);
					return t;
				});
		pool.allowCoreThreadTimeOut(true);
		slots = new Semaphore(max);
		maxSlots = max;
		connectionPool = pool;
	}

	/** Number of TCP connections being served now. */
	public static int getActiveConnections() {
		return maxSlots - slots.availablePermits();
	}

	/** Connections closed at once because maxConnections were already open. */
	public static long getRejected() {
		return rejected.get();
	}

	public static int getIdleTimeout() {
		return idleTimeout;
	}

	/**
	 * Close every open client connection and stop the connection pool.
	 * @return true if the pool finished within ms
	 */
	public static boolean shutdownConnections(long ms) {
		ThreadPoolExecutor pool = connectionPool;
		connectionPool = null;
		for(Socket s : openConnections) {
			try {
				s.close();
			} catch(IOException ex) {
			}
		}
		if( pool == null ) {
			return true;
		}
		pool.shutdownNow();
		try {
			return pool.awaitTermination(Math.max(1, ms), TimeUnit.MILLISECONDS);
		} catch(InterruptedException ex) {
			Thread.currentThread().interrupt();
			return false;
		}
	}

	/**
	 * Accept connections and hand them to the pool until shutdown.
	 **/
	public void run ()
	{
		if( serverSocket == null ) {
			log("Can't run without init");
			setState("No socket, can't run");
			return;
		}

		setState("Running Enter");

		while( !DnsServer.isShutdown())  {
			Socket sock = null;
			ServerSocket ss = serverSocket;
			try {
				setState("Running before sync");
				synchronized (syncLok) {
					setState("Waiting for connection");
					if( !DnsServer.isShutdown() ) {
						sock = ss.accept();
					}
				}
			} catch(InterruptedIOException ex) {
				// accept() timed out: check for shutdown
				continue;
			} catch(Exception ex) {
				if( !DnsServer.isShutdown() && !(ss != null && ss.isClosed()) ) {
					//  (the socket is closed on shutdown or after a failed start; that is not an error)
					log("Exception in TCP sock.accept()",ex);
				}
				if( ss == null || ss.isClosed() ) {
					break;
				}
				continue;
			}
			if( sock == null ) {
				continue;
			}

			ThreadPoolExecutor pool = connectionPool;
			Semaphore free = slots;
			boolean taken = false;
			try {
				if( pool == null ) {
					throw new RejectedExecutionException("no connection pool");
				}
				if( !free.tryAcquire() ) {
					throw new RejectedExecutionException("all connection slots busy");
				}
				taken = true;
				pool.execute(new Connection(server, sock, free));
				setState("Handed off connection from", sock.getInetAddress());
			} catch(RejectedExecutionException ex) {
				//  All connection slots busy: close now, the client can retry
				if( taken ) {
					free.release();
				}
				rejected.incrementAndGet();
				if( DnsServer.isDebug() ) {
					final InetAddress from = sock.getInetAddress();
					log(() -> "TCP connection from "+from+" rejected, "+getActiveConnections()+" connections open");
				}
				try {
					sock.close();
				} catch(IOException e) {
				}
			}
		}
		setState("Running Exit");
	}

	/** Acceptors never answer queries themselves (see Connection). */
	public void sendResponse(Message msg) {
		throw new IllegalStateException("TCPProsessor is an acceptor; responses are sent by Connection");
	}

	/**
	 * Write one length-prefixed DNS message (RFC 1035 4.2.2).
	 * Messages over 65535 bytes are sent truncated (TC) instead of with a
	 * corrupt 16 bit length.
	 */
	static void writeMessage(OutputStream out, byte [] data) throws IOException {
		byte [] sz = new byte[2];
		Utility.setShort(sz,0,data.length);
		out.write(sz);
		out.write(data);
		out.flush();
	}

	/**
	 * Serves one accepted TCP connection.
	 */
	static final class Connection extends DnsRequestProcessor implements Runnable {
		private final Socket sock;
		private final InetAddress client;
		private final Semaphore slot;

		Connection(DnsServer svr, Socket sock, Semaphore slot) {
			this.server = svr;
			this.sock = sock;
			this.slot = slot;
			this.client = sock.getInetAddress();
		}

		public void run() {
			openConnections.add(sock);
			byte [] sz = new byte[2];
			byte [] data = null;
			ByteBuffer buf = null;
			try {
				sock.setSoTimeout(idleTimeout);
				sock.setTcpNoDelay(true);
				InputStream in = sock.getInputStream();
				if( DnsServer.isDebug() ) {
					log(() -> "New TCP Connection from "+client);
				}

				// Client may send multiple requests
				boolean done = false;
				while( !done && !DnsServer.isShutdown() ) {
					try {
						// 16bit size comes in first
						Message.readArray(in,sz);
						int len = Utility.makeShort(sz[0], sz[1]);
						if( len < 12 ) {
							//  Smaller than a DNS header: framing is broken
							done = true;
							continue;
						}
						data = new byte[len];
						Message.readArray(in,data);
						buf = new ByteBuffer(data);

						if ( debug ) {
							buf.dump();
						}
						Message msg = new Message(buf);
						QueryData query = new QueryData(client,-1,msg);
						process(query);
					} catch(DnsFormatException ex) {
						// Malformed message: answer FORMERR and drop the connection
						// (framing can't be trusted after a bad message).
						if( DnsServer.isDebug() ) {
							log(() -> "Malformed TCP message from "+client+" "+ex.getMessage());
						}
						sendFormatError(data);
						done = true;
					} catch(IOException ex) {
						//  EOF, idle timeout or closed on shutdown
						done=true;
					}
				}
			} catch(StackOverflowError ex) {
				log(() -> "StackOverflowError processing TCP message from "+client);
			} catch(Exception ex) {
				log("Unexpected exception in TCP connection from "+client,ex);
				if( buf != null && UDPProsessor.dumpBuf != null ) {
					ex.printStackTrace(UDPProsessor.dumpBuf);
					UDPProsessor.dumpBuf.println("TCP Exception "+client);
					buf.dump(UDPProsessor.dumpBuf);
				}
			} finally {
				openConnections.remove(sock);
				try {
					sock.close();
				} catch(IOException ex) {
				}
				slot.release();
			}
		}

		/**
		 * Reply FORMERR to a TCP request that could not be parsed.
		 */
		private void sendFormatError(byte [] data) {
			byte [] reply = UDPProsessor.buildFormatError(data, data == null ? 0 : data.length);
			if( reply == null ) {
				return;
			}
			try {
				writeMessage(sock.getOutputStream(), reply);
			} catch(IOException ex) {
				log("IOException sending FORMERR",ex);
			}
		}

		public void sendResponse(Message msg) {
			if( msg != null ) {
				try {
					writeMessage(sock.getOutputStream(), msg.toByteArray(MAX_TCP_MESSAGE));
					if( UDPProsessor.dumpBuf != null ) {
						UDPProsessor.dumpBuf.println("TCP("+sock+")->"+msg.toSmallString());
					}
				} catch(IOException ex) {
					log("IOException sending reply to "+client,ex);
				}
			}
		}
	}
}
