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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.A;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.resolve.QueryData;
import us.bringardner.net.dns.resolve.Resolver;

/**
 * Offline tests: no System.exit from request threads; JVM errors reach
 * FatalErrorHandler, which halts only for VirtualMachineError when enabled.
 */
public class TestFatalErrors {

	/** A server whose every query runs out of memory. */
	private static class OomServer extends DnsServer {
		@Override
		public List<Message> query(QueryData req) {
			throw new OutOfMemoryError("simulated");
		}
	}

	private static QueryData request() {
		Message m = new Message();
		m.setQuestion("www.oom.test", DNS.A, DNS.IN);
		return new QueryData(InetAddress.getLoopbackAddress(), 5353, m);
	}

	/** Run body with the halter replaced by a recorder; returns the halt code or -1. */
	private interface Body {
		void run() throws Exception;
	}

	private static int haltCodeDuring(boolean haltOnFatal, Body body) throws Exception {
		AtomicInteger code = new AtomicInteger(-1);
		FatalErrorHandler.setHalter(c -> code.set(c));
		FatalErrorHandler.setHaltOnFatal(haltOnFatal);
		try {
			body.run();
		} finally {
			FatalErrorHandler.setHalter(c -> Runtime.getRuntime().halt(c));
			FatalErrorHandler.setHaltOnFatal(false);
		}
		return code.get();
	}

	private static void dieWith(Throwable t) throws InterruptedException {
		Thread th = new Thread(() -> {
			if( t instanceof Error ) {
				throw (Error)t;
			}
			throw (RuntimeException)t;
		},"TestDyingThread");
		th.setUncaughtExceptionHandler(FatalErrorHandler.getInstance());
		th.start();
		th.join(5000);
	}

	@Test
	public void processDoesNotSwallowOutOfMemory() {
		// The old process() caught it, retried twice and then called System.exit(1)
		DnsRequestProcessor p = new DnsRequestProcessor() {
			@Override
			public void sendResponse(Message msg) {
			}
		};
		p.server = new OomServer();
		assertThrows(OutOfMemoryError.class, () -> p.process(request()));
	}

	@Test
	public void vmErrorHaltsWhenEnabled() throws Exception {
		long before = FatalErrorHandler.getThreadDeaths();
		int code = haltCodeDuring(true, () -> dieWith(new OutOfMemoryError("simulated")));
		assertEquals(1, code);
		assertEquals(before+1, FatalErrorHandler.getThreadDeaths());
	}

	@Test
	public void vmErrorOnlyLoggedWhenDisabled() throws Exception {
		long before = FatalErrorHandler.getThreadDeaths();
		int code = haltCodeDuring(false, () -> dieWith(new OutOfMemoryError("simulated")));
		assertEquals(-1, code);
		assertEquals(before+1, FatalErrorHandler.getThreadDeaths());
	}

	@Test
	public void ordinaryErrorNeverHalts() throws Exception {
		int code = haltCodeDuring(true, () -> dieWith(new IllegalStateException("bug")));
		assertEquals(-1, code, "only VirtualMachineError stops the process");
	}

	@Test
	public void udpThreadOutOfMemoryReachesHandler() throws Exception {
		// End to end: a real UDP processor thread hits OutOfMemoryError while
		// answering; it must reach the handler (not System.exit, not swallowed)
		int port;
		try(DatagramSocket probe = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
			port = probe.getLocalPort();
		}
		UDPProsessor.initUDPProsessor(port, InetAddress.getLoopbackAddress(), 200);
		final int p = port;
		int code = haltCodeDuring(true, () -> {
			Thread t = new Thread(new UDPProsessor(new OomServer(),0),"TestOomUDP");
			t.setUncaughtExceptionHandler(FatalErrorHandler.getInstance());
			t.setDaemon(true);
			t.start();
			byte [] q = request().getMessage().toByteArray();
			try(DatagramSocket client = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
				client.send(new DatagramPacket(q, q.length, InetAddress.getLoopbackAddress(), p));
			}
			t.join(5000);
			assertTrue(!t.isAlive(), "thread ended through the handler");
		});
		UDPProsessor.getSock().close();
		assertEquals(1, code);
	}

	@Test
	public void resetEmptiesCacheAndDelegations() {
		Message m = new Message();
		m.setQuestion("www.reset.test", DNS.A, DNS.IN);
		A a = new A("www.reset.test");
		a.setAddress("10.0.0.1");
		a.setTTL(300);
		m.addAnswer(a);
		Resolver.resolve("nothing.reset.test");   // make sure Resolver is initialised
		us.bringardner.net.dns.resolve.TestHooks.put(m);
		assertTrue(Resolver.cacheSize() > 0);
		Resolver.reset();
		assertEquals(0, Resolver.cacheSize());
		assertEquals(0, Resolver.delegationCount());
	}
}
