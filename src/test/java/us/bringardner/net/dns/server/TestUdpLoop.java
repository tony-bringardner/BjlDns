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
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.file.Files;

import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.ByteBuffer;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Message;

/**
 * UDP processor loop: the reused receive buffer handles requests of
 * different sizes, and the thread ends when its socket is closed instead
 * of spinning.
 */
public class TestUdpLoop {

	@Test
	public void reusedBufferAndClosedSocket() throws Exception {
		File dir = Files.createTempDirectory("udploop").toFile();
		File zone = new File(dir,"loop.test.txt");
		try(FileWriter w = new FileWriter(zone)) {
			w.write("@\tIN\tSOA\tns1.loop.test. postmaster.loop.test. (\n"
					+"\t\t\t1 ; serial\n\t\t\t3600 ; refresh\n\t\t\t1800 ; retry\n"
					+"\t\t\t1209600 ; expire\n\t\t\t300 ) ; minimum\n\n"
					+"\t\tNS\tns1\n"
					+"ns1\tIN\tA\t10.0.0.53\n"
					+"www\tIN\tA\t10.0.0.80\n"
					+"a-much-longer-name-than-www\tIN\tA\t10.0.0.81\n");
		}
		DnsServer server = new DnsServer();
		server.addZone(new Zone(zone));
		server.setRecursionAvailable(false);
		int port;
		try(DatagramSocket probe = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
			port = probe.getLocalPort();
		}
		DnsServer.setShutdown(false);
		UDPProsessor.initUDPProsessor(port, InetAddress.getLoopbackAddress(), 60_000);
		UDPProsessor proc = new UDPProsessor(server,0);
		Thread t = new Thread(proc,"TestUdpLoop");
		t.setDaemon(true);
		t.start();
		try(DatagramSocket c = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
			c.setSoTimeout(3000);
			String [] names = {"a-much-longer-name-than-www.loop.test", "www.loop.test", "a-much-longer-name-than-www.loop.test", "www.loop.test"};
			String [] want = {"10.0.0.81", "10.0.0.80", "10.0.0.81", "10.0.0.80"};
			for(int i=0; i < names.length; i++ ) {
				Message q = new Message();
				q.setQuestion(names[i], DNS.A, DNS.IN);
				q.setID(100+i);
				byte [] b = q.toByteArray();
				c.send(new DatagramPacket(b, b.length, InetAddress.getLoopbackAddress(), port));
				byte [] buf = new byte[2048];
				DatagramPacket p = new DatagramPacket(buf, buf.length);
				c.receive(p);
				Message r = new Message(new ByteBuffer(java.util.Arrays.copyOf(buf, p.getLength())));
				assertEquals(100+i, r.getID());
				assertEquals(names[i], r.getFirstQuestion().getName(), "the whole (shorter) request was parsed");
				assertEquals(want[i], ((us.bringardner.net.dns.A)r.getAnswer().get(0)).getAddressString());
			}
		}
		//  Close the socket without setting the shutdown flag: the thread must end
		UDPProsessor.getSock().close();
		t.join(3000);
		assertTrue(!t.isAlive(), "ended instead of spinning on a closed socket");
		for(File f : dir.listFiles()) {
			f.delete();
		}
		dir.delete();
	}
}
