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
package us.bringardner.net.dns.resolve;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.A;
import us.bringardner.net.dns.ByteBuffer;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.Section;

/**
 * Offline tests for ServerA. A fake upstream DNS server on 127.0.0.1 answers
 * every query with an A record for the name asked, after a random delay so
 * that concurrent answers come back out of order.
 */
public class TestServerA {

	/** Minimal UDP DNS responder on 127.0.0.1 (random port). */
	static class FakeUpstream implements AutoCloseable {
		final DatagramSocket sock;
		final AtomicInteger received = new AtomicInteger();
		private final Thread thread;
		private volatile boolean running = true;
		private final Random rnd = new Random();

		FakeUpstream() throws Exception {
			sock = new DatagramSocket(0, InetAddress.getLoopbackAddress());
			thread = new Thread(this::loop,"FakeUpstream");
			thread.setDaemon(true);
			thread.start();
		}

		int port() {
			return sock.getLocalPort();
		}

		private void loop() {
			while( running ) {
				try {
					byte [] buf = new byte[DNS.MAXUDPLEN];
					DatagramPacket p = new DatagramPacket(buf,buf.length);
					sock.receive(p);
					received.incrementAndGet();
					final InetAddress from = p.getAddress();
					final int fromPort = p.getPort();
					final Message req = new Message(new ByteBuffer(p.getData()));
					final int delay = rnd.nextInt(15);
					Thread t = new Thread(() -> respond(req,from,fromPort,delay));
					t.setDaemon(true);
					t.start();
				} catch(Exception ex) {
					// closed
				}
			}
		}

		private void respond(Message req, InetAddress to, int port, int delay) {
			try {
				Thread.sleep(delay);
				Message r = new Message();
				r.setHeader(req.getHeader().copy());
				r.setMessageTypeResponse();
				Section q = req.getFirstQuestion();
				r.setQuestion(q);
				A a = new A(q.getName());
				a.setAddress("10.0.0.1");
				a.setTTL(60);
				r.addAnswer(a);
				byte [] d = r.toByteArray();
				sock.send(new DatagramPacket(d,d.length,to,port));
			} catch(Exception ex) {
			}
		}

		@Override
		public void close() {
			running = false;
			sock.close();
		}
	}

	private static ServerA serverFor(int port) {
		ServerA s = new ServerA("fake.example.com","127.0.0.1");
		s.setPort(port);
		return s;
	}

	/** A local UDP port with nothing listening (queries time out). */
	private static int deadPort() throws Exception {
		try(DatagramSocket s = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
			return s.getLocalPort();
		}
	}

	@Test
	public void singleQuery() throws Exception {
		try(FakeUpstream up = new FakeUpstream()) {
			ServerA s = serverFor(up.port());
			Message m = s.query(new Section("www.example.com",DNS.A,DNS.IN));
			assertNotNull(m);
			assertEquals("www.example.com", m.getFirstQuestion().getName());
			assertEquals(1, s.getMsgSent());
			assertEquals(1, s.getMsgRec());
		}
	}

	@Test
	public void concurrentQueriesGetTheirOwnAnswers() throws Exception {
		// Before this change all threads shared one query Message per server:
		// a thread could send another thread's question and get its answer.
		try(FakeUpstream up = new FakeUpstream()) {
			final ServerA s = serverFor(up.port());
			int threads = 8, loops = 40;
			CountDownLatch start = new CountDownLatch(1);
			AtomicReference<String> failure = new AtomicReference<String>();
			AtomicInteger answered = new AtomicInteger();
			List<Thread> list = new ArrayList<Thread>();
			for(int t=0; t< threads; t++ ) {
				final int tn = t;
				Thread th = new Thread(() -> {
					try {
						start.await();
						for(int i=0; i< loops && failure.get() == null; i++ ) {
							String name = "t"+tn+"-q"+i+".example.com";
							Message m = s.query(new Section(name,DNS.A,DNS.IN));
							if( m == null ) {
								continue;   // a timeout is not what we're testing
							}
							answered.incrementAndGet();
							String got = m.getFirstQuestion().getName();
							String ans = m.getAnswer().get(0).getName();
							if( !name.equals(got) || !name.equals(ans) ) {
								failure.compareAndSet(null,"asked "+name+" but got question="+got+" answer="+ans);
							}
						}
					} catch(Throwable ex) {
						failure.compareAndSet(null, ex.toString());
					}
				});
				list.add(th);
				th.start();
			}
			start.countDown();
			for(Thread th : list) {
				th.join(60_000);
			}
			assertNull(failure.get(), failure.get());
			assertTrue(answered.get() > threads*loops/2, "most queries should be answered, got "+answered.get());
			assertEquals(threads*loops, s.getMsgSent());
			assertEquals(answered.get(), s.getMsgRec());
		}
	}

	@Test
	public void deactivatesAfterRepeatedFailuresAndReactivates() throws Exception {
		int savedTimeout = ServerA.QUERY_TIMEOUT;
		long savedDeactivate = ServerA.DEACTIVATE;
		try {
			ServerA.QUERY_TIMEOUT = 50;
			ServerA.DEACTIVATE = 300;
			ServerA s = serverFor(deadPort());
			Section q = new Section("www.example.com",DNS.A,DNS.IN);

			for(int i=0; i<= ServerA.MAX_TRIES; i++ ) {
				assertTrue(s.isActive(), "still active after "+i+" failures");
				assertNull(s.query(q));
			}
			assertTrue(!s.isActive(), "inactive after "+(ServerA.MAX_TRIES+1)+" failures");

			// While inactive nothing is sent (the old code still sent queries here)
			int sent = s.getMsgSent();
			assertNull(s.query(q));
			assertEquals(sent, s.getMsgSent());

			// After DEACTIVATE it gets one more try; failing again deactivates it again
			Thread.sleep(ServerA.DEACTIVATE+50);
			assertTrue(s.isActive());
			assertNull(s.query(q));
			assertEquals(sent+1, s.getMsgSent());
			assertTrue(!s.isActive());

			s.setActive(true);
			assertTrue(s.isActive());
		} finally {
			ServerA.QUERY_TIMEOUT = savedTimeout;
			ServerA.DEACTIVATE = savedDeactivate;
		}
	}

	@Test
	public void successResetsFailureCount() throws Exception {
		int savedTimeout = ServerA.QUERY_TIMEOUT;
		try {
			ServerA.QUERY_TIMEOUT = 50;
			try(FakeUpstream up = new FakeUpstream()) {
				ServerA s = serverFor(deadPort());
				Section q = new Section("www.example.com",DNS.A,DNS.IN);
				for(int i=0; i< ServerA.MAX_TRIES; i++ ) {
					assertNull(s.query(q));
				}
				s.setPort(up.port());
				ServerA.QUERY_TIMEOUT = 2000;
				assertNotNull(s.query(q));
				ServerA.QUERY_TIMEOUT = 50;
				s.setPort(deadPort());
				for(int i=0; i< ServerA.MAX_TRIES; i++ ) {
					assertNull(s.query(q));
					assertTrue(s.isActive(), "count must restart after a success");
				}
			}
		} finally {
			ServerA.QUERY_TIMEOUT = savedTimeout;
		}
	}

	@Test
	public void statsBeforeAnyQuery() {
		ServerA s = new ServerA("fake.example.com","127.0.0.1");
		// used to throw ArithmeticException (divide by zero)
		assertEquals(0, s.aveResponseTime());
		assertEquals(0, s.battingAve());
	}
}
