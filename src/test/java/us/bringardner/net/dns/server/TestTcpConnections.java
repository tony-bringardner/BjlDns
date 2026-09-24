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
package us.bringardner.net.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.ByteBuffer;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.Utility;

/**
 * Offline tests for the TCP connection handling: idle clients must not
 * block others, idle connections time out, several queries per connection,
 * a full server rejects instead of queueing, shutdown closes connections.
 */
public class TestTcpConnections {

	private static File dir;
	private static DnsServer server;

	@BeforeAll
	public static void setup() throws IOException {
		dir = Files.createTempDirectory("tcpconn").toFile();
		File zone = new File(dir,"tcp.test.txt");
		try(FileWriter w = new FileWriter(zone)) {
			w.write("@\tIN\tSOA\tns1.tcp.test. postmaster.tcp.test. (\n"
					+"\t\t\t1 ; serial\n\t\t\t3600 ; refresh\n\t\t\t1800 ; retry\n"
					+"\t\t\t1209600 ; expire\n\t\t\t300 ) ; minimum\n\n"
					+"\t\tNS\tns1\n"
					+"ns1\tIN\tA\t10.0.0.53\n"
					+"www\tIN\tA\t10.0.0.80\n");
		}
		server = new DnsServer();
		server.addZone(new Zone(zone));
		server.setRecursionAvailable(false);
	}

	@AfterAll
	public static void cleanup() {
		for(File f : dir.listFiles()) {
			f.delete();
		}
		dir.delete();
	}

	/** A running TCP listener with the given limits; close() stops it. */
	private static class Listener implements AutoCloseable {
		final int port;
		final Thread acceptor;

		Listener(int maxConnections, int idleTimeoutMs) throws IOException {
			TCPProsessor.initTCPProsessor(0, 10, InetAddress.getLoopbackAddress(), 200, maxConnections, idleTimeoutMs);
			port = TCPProsessor.getServerSocket().getLocalPort();
			acceptor = new Thread(new TCPProsessor(server,0),"TestTCPAcceptor");
			acceptor.setDaemon(true);
			acceptor.start();
		}

		@Override
		public void close() throws Exception {
			DnsServer.setShutdown(true);
			TCPProsessor.getServerSocket().close();
			assertTrue(TCPProsessor.shutdownConnections(5000));
			acceptor.join(5000);
			DnsServer.setShutdown(false);
		}
	}

	private static Message query(int port, String name) throws IOException {
		Message m = new Message();
		m.setServer(InetAddress.getLoopbackAddress());
		m.setPort(port);
		m.setTimeOut(3000);
		m.setRetry(1);
		m.setQuestion(name, DNS.A, DNS.IN);
		return m.queryTCP();
	}

	private static Socket idleClient(int port) throws IOException {
		Socket s = new Socket(InetAddress.getLoopbackAddress(), port);
		s.setSoTimeout(5000);
		return s;
	}

	private static void waitFor(java.util.function.BooleanSupplier cond, long ms) throws InterruptedException {
		long end = System.currentTimeMillis()+ms;
		while( !cond.getAsBoolean() && System.currentTimeMillis() < end ) {
			Thread.sleep(10);
		}
	}

	/** true if the server closed this connection (read returns EOF) within the socket timeout */
	private static boolean closedByServer(Socket s) throws IOException {
		try {
			return s.getInputStream().read() == -1;
		} catch(SocketTimeoutException ex) {
			return false;
		} catch(IOException ex) {
			return true;   // reset
		}
	}

	@Test
	public void idleConnectionsDoNotBlockQueries() throws Exception {
		// Before: 4 acceptor threads, each held by a connection for up to 2
		// minutes, so 4 idle clients blocked all TCP service.
		try(Listener l = new Listener(16, 5000)) {
			List<Socket> idle = new ArrayList<Socket>();
			for(int i=0; i< 6; i++ ) {
				idle.add(idleClient(l.port));
			}
			waitFor(() -> TCPProsessor.getActiveConnections() == 6, 3000);
			long start = System.currentTimeMillis();
			Message r = query(l.port, "www.tcp.test");
			assertEquals(1, r.getAnswerCount());
			assertTrue(System.currentTimeMillis()-start < 2000, "answered promptly");
			for(Socket s : idle) {
				s.close();
			}
		}
	}

	@Test
	public void idleConnectionIsClosed() throws Exception {
		try(Listener l = new Listener(8, 300)) {
			try(Socket s = idleClient(l.port)) {
				long start = System.currentTimeMillis();
				assertTrue(closedByServer(s), "server closes an idle connection");
				long took = System.currentTimeMillis()-start;
				assertTrue(took >= 200 && took < 3000, "after about the idle timeout, took "+took);
			}
			waitFor(() -> TCPProsessor.getActiveConnections() == 0, 2000);
			assertEquals(0, TCPProsessor.getActiveConnections());
		}
	}

	@Test
	public void severalQueriesOnOneConnection() throws Exception {
		try(Listener l = new Listener(8, 5000); Socket s = idleClient(l.port)) {
			OutputStream out = s.getOutputStream();
			InputStream in = s.getInputStream();
			for(int id=100; id< 103; id++ ) {
				Message q = new Message();
				q.setQuestion("www.tcp.test", DNS.A, DNS.IN);
				q.setID(id);
				TCPProsessor.writeMessage(out, q.toByteArray());
			}
			for(int id=100; id< 103; id++ ) {
				byte [] sz = new byte[2];
				Message.readArray(in, sz);
				byte [] data = new byte[Utility.makeShort(sz[0],sz[1])];
				Message.readArray(in, data);
				Message r = new Message(new ByteBuffer(data));
				assertEquals(id, r.getID());
				assertEquals(1, r.getAnswerCount());
			}
		}
	}

	@Test
	public void fullServerRejectsInsteadOfQueueing() throws Exception {
		try(Listener l = new Listener(2, 5000)) {
			Socket a = idleClient(l.port);
			Socket b = idleClient(l.port);
			waitFor(() -> TCPProsessor.getActiveConnections() == 2, 3000);
			long rejectedBefore = TCPProsessor.getRejected();
			try(Socket c = idleClient(l.port)) {
				assertTrue(closedByServer(c), "third connection is closed at once");
			}
			assertEquals(rejectedBefore+1, TCPProsessor.getRejected());

			a.close();
			waitFor(() -> TCPProsessor.getActiveConnections() == 1, 3000);
			assertEquals(1, query(l.port, "www.tcp.test").getAnswerCount(), "a freed slot serves again");
			b.close();
		}
	}

	/**
	 * With one slot, back-to-back clients must all be served: the slot is
	 * free as soon as the previous connection is closed, even if its pool
	 * thread has not quite finished (that used to reject some of them).
	 */
	@Test
	public void freedSlotIsReusableAtOnce() throws Exception {
		try(Listener l = new Listener(1, 5000)) {
			long rejectedBefore = TCPProsessor.getRejected();
			for(int i=0; i < 300; i++ ) {
				waitFor(() -> TCPProsessor.getActiveConnections() == 0, 3000);
				assertEquals(1, query(l.port, "www.tcp.test").getAnswerCount(), "query "+i);
			}
			assertEquals(rejectedBefore, TCPProsessor.getRejected(), "no connection rejected");
		}
	}

	@Test
	public void shutdownClosesOpenConnections() throws Exception {
		Listener l = new Listener(8, 30_000);
		Socket s = idleClient(l.port);
		waitFor(() -> TCPProsessor.getActiveConnections() == 1, 3000);
		long start = System.currentTimeMillis();
		l.close();
		assertTrue(closedByServer(s));
		assertTrue(System.currentTimeMillis()-start < 5000, "did not wait for the 30s idle timeout");
		assertEquals(0, TCPProsessor.getActiveConnections());
		s.close();
	}
}
