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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Collections;

import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.Name;

/**
 * Offline tests for admin port security: challenge-response authentication
 * (JDns.adminSecret), local-only access without a secret, and the limit on
 * concurrent admin sessions.
 */
public class TestAdminAuth {

	/** An admin listener that hands connections to DnsServer.handleAdminConnection. */
	private static class AdminListener implements AutoCloseable {
		final DnsServer server = new DnsServer();
		final ServerSocket ss;
		final Thread thread;
		final String savedSecret = System.getProperty(DnsServer.PROP_ADMIN_SECRET);

		AdminListener(String secret, InetAddress bind) throws IOException {
			if( secret == null ) {
				System.clearProperty(DnsServer.PROP_ADMIN_SECRET);
			} else {
				System.setProperty(DnsServer.PROP_ADMIN_SECRET, secret);
			}
			ss = new ServerSocket(0, 10, bind);
			thread = new Thread(() -> {
				while( !ss.isClosed() ) {
					try {
						server.handleAdminConnection(ss.accept());
					} catch(IOException ex) {
					}
				}
			},"TestAdminListener");
			thread.setDaemon(true);
			thread.start();
		}

		AdminListener(String secret) throws IOException {
			this(secret, InetAddress.getLoopbackAddress());
		}

		int port() {
			return ss.getLocalPort();
		}

		@Override
		public void close() throws Exception {
			ss.close();
			thread.join(2000);
			if( savedSecret == null ) {
				System.clearProperty(DnsServer.PROP_ADMIN_SECRET);
			} else {
				System.setProperty(DnsServer.PROP_ADMIN_SECRET, savedSecret);
			}
		}
	}

	/** A raw line-based connection for protocol-level checks. */
	private static class Raw implements AutoCloseable {
		final Socket s;
		final BufferedReader in;
		final OutputStream out;

		Raw(InetAddress addr, int port) throws IOException {
			s = new Socket(addr, port);
			s.setSoTimeout(5000);
			in = new BufferedReader(new InputStreamReader(s.getInputStream()));
			out = s.getOutputStream();
		}

		String line() throws IOException {
			return in.readLine();
		}

		void send(String line) throws IOException {
			out.write((line+"\r\n").getBytes());
			out.flush();
		}

		@Override
		public void close() throws IOException {
			s.close();
		}
	}

	private static DnsAdminClient client(int port, String secret) throws IOException {
		DnsAdminClient c = new DnsAdminClient("127.0.0.1", port);
		c.setSecret(secret);
		c.setTimeout(5000);
		return c;
	}

	// ------------------------------------------------------------ AdminAuth

	@Test
	public void hmacAnswers() {
		String c = AdminAuth.newChallenge();
		assertEquals(32, c.length());
		assertTrue(!c.equals(AdminAuth.newChallenge()), "challenges are random");
		String answer = AdminAuth.response("s3cret", c);
		assertTrue(AdminAuth.verify("s3cret", c, answer));
		assertTrue(AdminAuth.verify("s3cret", c, answer.toUpperCase()));
		assertTrue(!AdminAuth.verify("other", c, answer));
		assertTrue(!AdminAuth.verify("s3cret", AdminAuth.newChallenge(), answer), "answer is bound to its challenge");
		assertTrue(!AdminAuth.verify("s3cret", c, "zz"));
		assertTrue(!AdminAuth.verify(null, c, answer));
		assertEquals(c, AdminAuth.challengeFrom("+JDns admin ready auth=hmac-sha256 challenge="+c));
		assertEquals(null, AdminAuth.challengeFrom("+JDns admin ready"));
	}

	// ------------------------------------------------------------ no secret

	@Test
	public void noSecretLocalClientWorks() throws Exception {
		try(AdminListener l = new AdminListener(null)) {
			DnsAdminClient c = client(l.port(), null);
			assertTrue(c.connect());
			c.addDomain("local.example");
			c.close();
			assertTrue(l.server.isCommon(new Name("www.local.example")));
		}
	}

	@Test
	public void noSecretRemoteClientRefused() throws Exception {
		InetAddress mine = null;
		for(NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
			if( !ni.isUp() || ni.isLoopback() ) {
				continue;
			}
			for(InetAddress a : Collections.list(ni.getInetAddresses())) {
				if( a instanceof Inet4Address && !a.isLoopbackAddress() && !a.isLinkLocalAddress() ) {
					mine = a;
				}
			}
		}
		if( mine == null ) {
			System.out.println("noSecretRemoteClientRefused: no non-loopback IPv4 address, skipped");
			return;
		}
		try(AdminListener l = new AdminListener(null, InetAddress.getByName("0.0.0.0"));
				Raw r = new Raw(mine, l.port())) {
			String greeting = r.line();
			assertNotNull(greeting);
			assertTrue(greeting.startsWith("-Admin access from"), greeting);
			assertEquals(null, r.line(), "connection closed");
			assertTrue(!l.server.isCommon(new Name("www.remote.example")));
		}
	}

	// ------------------------------------------------------------ with secret

	@Test
	public void secretRequiredBeforeCommands() throws Exception {
		try(AdminListener l = new AdminListener("s3cret");
				Raw r = new Raw(InetAddress.getLoopbackAddress(), l.port())) {
			String greeting = r.line();
			assertNotNull(AdminAuth.challengeFrom(greeting), greeting);
			r.send("add_domain sneaky.example");
			assertEquals("-Authentication required", r.line());
			r.send("");
			assertEquals("-Authentication required", r.line(), "empty line must not repeat a command");
			assertTrue(!l.server.isCommon(new Name("www.sneaky.example")));
		}
	}

	@Test
	public void correctSecretWorks() throws Exception {
		try(AdminListener l = new AdminListener("s3cret")) {
			DnsAdminClient c = client(l.port(), "s3cret");
			assertTrue(c.connect());
			c.addDomain("authed.example");
			c.close();
			assertTrue(l.server.isCommon(new Name("www.authed.example")));
		}
	}

	@Test
	public void clientWithoutOrWithWrongSecretFails() throws Exception {
		try(AdminListener l = new AdminListener("s3cret")) {
			assertTrue(!client(l.port(), null).connect());
			assertTrue(!client(l.port(), "wrong").connect());
		}
	}

	@Test
	public void wrongAnswerClosesConnection() throws Exception {
		try(AdminListener l = new AdminListener("s3cret");
				Raw r = new Raw(InetAddress.getLoopbackAddress(), l.port())) {
			String challenge = AdminAuth.challengeFrom(r.line());
			r.send("auth "+AdminAuth.response("wrong", challenge));
			assertEquals("-Authentication failed", r.line());
			assertEquals(null, r.line(), "connection closed");
		}
	}

	@Test
	public void replayedAnswerFails() throws Exception {
		try(AdminListener l = new AdminListener("s3cret")) {
			String oldAnswer;
			try(Raw r = new Raw(InetAddress.getLoopbackAddress(), l.port())) {
				String c1 = AdminAuth.challengeFrom(r.line());
				oldAnswer = AdminAuth.response("s3cret", c1);
				r.send("auth "+oldAnswer);
				assertEquals("+Authenticated", r.line());
			}
			try(Raw r = new Raw(InetAddress.getLoopbackAddress(), l.port())) {
				r.line();
				r.send("auth "+oldAnswer);
				assertEquals("-Authentication failed", r.line(), "an answer recorded from another session is useless");
			}
		}
	}

	// ------------------------------------------------------------ limits

	@Test
	public void adminSessionsAreLimited() throws Exception {
		try(AdminListener l = new AdminListener(null)) {
			l.server.setAdminMaxConnections(2);
			Raw a = new Raw(InetAddress.getLoopbackAddress(), l.port());
			Raw b = new Raw(InetAddress.getLoopbackAddress(), l.port());
			assertTrue(a.line().startsWith("+"));
			assertTrue(b.line().startsWith("+"));
			try(Raw c = new Raw(InetAddress.getLoopbackAddress(), l.port())) {
				assertEquals("-Too many admin connections", c.line());
			}
			a.close();
			long end = System.currentTimeMillis()+3000;
			while( l.server.getAvailableAdminSlots() == 0 && System.currentTimeMillis() < end ) {
				Thread.sleep(10);
			}
			try(Raw d = new Raw(InetAddress.getLoopbackAddress(), l.port())) {
				assertTrue(d.line().startsWith("+"), "a freed slot can be used again");
			}
			b.close();
		}
	}
}
