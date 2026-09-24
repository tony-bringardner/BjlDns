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

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocketFactory;

import org.junit.jupiter.api.Test;

/** JDns.adminTls picks the TLS server socket factory for the admin port. */
public class TestAdminTls {

	@Test
	public void tlsFactoryWhenEnabled() {
		ServerSocketFactory plain = ServerSocketFactory.getDefault();
		assertSame(plain, DnsServer.adminSocketFactory(null, plain));
		assertSame(plain, DnsServer.adminSocketFactory("false", plain));
		assertTrue(DnsServer.adminSocketFactory("true", plain) instanceof SSLServerSocketFactory);
		assertTrue(DnsServer.adminSocketFactory(" True ", plain) instanceof SSLServerSocketFactory);
	}

	@Test
	public void customFactoryIsKept() {
		ServerSocketFactory custom = new ServerSocketFactory() {
			public java.net.ServerSocket createServerSocket(int port) throws java.io.IOException {
				return new java.net.ServerSocket(port);
			}
			public java.net.ServerSocket createServerSocket(int port, int backlog) throws java.io.IOException {
				return new java.net.ServerSocket(port, backlog);
			}
			public java.net.ServerSocket createServerSocket(int port, int backlog, java.net.InetAddress a) throws java.io.IOException {
				return new java.net.ServerSocket(port, backlog, a);
			}
		};
		assertSame(custom, DnsServer.adminSocketFactory("true", custom));
	}
}
