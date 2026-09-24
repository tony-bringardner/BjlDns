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
package us.bringardner.net.dns;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;

import org.junit.jupiter.api.Test;

/**
 * Offline tests for RFC 5452 response validation in Message.queryUDP/queryTCP.
 * A scripted fake upstream on 127.0.0.1 sends forged / bogus packets before
 * (or instead of) the genuine answer. Forged answers carry 6.6.6.6, the
 * genuine one 10.0.0.1.
 */
public class TestUpstreamValidation {

	static final String REAL = "10.0.0.1";
	static final String FORGED = "6.6.6.6";

	/** One packet to send back: payload and whether to send it from the spoof socket. */
	static class Out {
		final byte [] data;
		final boolean fromOtherPort;
		Out(byte [] data, boolean fromOtherPort) {
			this.data = data;
			this.fromOtherPort = fromOtherPort;
		}
		Out(Message m) {
			this(m.toByteArray(), false);
		}
	}

	/** UDP responder that answers each request with a scripted list of packets. */
	static class ScriptedUpstream implements AutoCloseable {
		final DatagramSocket sock;
		final DatagramSocket spoof;
		final List<Integer> ids = new ArrayList<Integer>();
		private volatile boolean running = true;

		ScriptedUpstream(Function<Message,List<Out>> script) throws Exception {
			sock = new DatagramSocket(0, InetAddress.getLoopbackAddress());
			spoof = new DatagramSocket(0, InetAddress.getLoopbackAddress());
			Thread t = new Thread(() -> {
				while( running ) {
					try {
						byte [] buf = new byte[DNS.MAXUDPLEN];
						DatagramPacket p = new DatagramPacket(buf,buf.length);
						sock.receive(p);
						Message req = new Message(new ByteBuffer(p.getData()));
						synchronized (ids) {
							ids.add(req.getID());
						}
						for(Out o : script.apply(req)) {
							DatagramPacket r = new DatagramPacket(o.data,o.data.length,p.getAddress(),p.getPort());
							(o.fromOtherPort ? spoof : sock).send(r);
						}
					} catch(Exception ex) {
					}
				}
			},"ScriptedUpstream");
			t.setDaemon(true);
			t.start();
		}

		int port() {
			return sock.getLocalPort();
		}

		@Override
		public void close() {
			running = false;
			sock.close();
			spoof.close();
		}
	}

	/** Build an answer to req with the given ID/QR/name and address. */
	static Message answer(Message req, int id, boolean qr, String name, String ip) {
		Section q = req.getFirstQuestion();
		Message r = new Message();
		r.setHeader(req.getHeader().copy());
		r.setID(id);
		if( qr ) {
			r.setMessageTypeResponse();
		}
		r.setQuestion(name, q.getType(), q.getDnsClass());
		A a = new A(name);
		a.setAddress(ip);
		a.setTTL(60);
		r.addAnswer(a);
		return r;
	}

	static Message genuine(Message req) {
		return answer(req, req.getID(), true, req.getFirstQuestion().getName(), REAL);
	}

	static Message query(int port, String name) {
		Message m = new Message();
		m.setServer(InetAddress.getLoopbackAddress());
		m.setPort(port);
		m.setTimeOut(500);
		m.setRetry(1);
		m.setQuestion(name, DNS.A, DNS.IN);
		return m;
	}

	static String address(Message m) {
		return ((A)m.getAnswer().get(0)).getAddressString();
	}

	static List<Out> list(Out ... o) {
		List<Out> ret = new ArrayList<Out>();
		for(Out x : o) {
			ret.add(x);
		}
		return ret;
	}

	@Test
	public void idsAreRandom() throws Exception {
		try(ScriptedUpstream up = new ScriptedUpstream(req -> list(new Out(genuine(req))))) {
			Message m = query(up.port(),"www.example.com");
			for(int i=0; i< 20; i++ ) {
				m.queryUDP();
			}
			Set<Integer> distinct = new HashSet<Integer>(up.ids);
			assertTrue(distinct.size() >= 18, "IDs should be random, got "+up.ids);
		}
	}

	@Test
	public void genuineAnswerAccepted() throws Exception {
		try(ScriptedUpstream up = new ScriptedUpstream(req -> list(new Out(genuine(req))))) {
			assertEquals(REAL, address(query(up.port(),"www.example.com").queryUDP()));
		}
	}

	@Test
	public void wrongIdIgnored() throws Exception {
		try(ScriptedUpstream up = new ScriptedUpstream(req -> list(
				new Out(answer(req, (req.getID()+1) & 0xffff, true, "www.example.com", FORGED)),
				new Out(genuine(req))))) {
			assertEquals(REAL, address(query(up.port(),"www.example.com").queryUDP()));
		}
	}

	@Test
	public void wrongQuestionIgnored() throws Exception {
		try(ScriptedUpstream up = new ScriptedUpstream(req -> list(
				new Out(answer(req, req.getID(), true, "evil.example.com", FORGED)),
				new Out(genuine(req))))) {
			assertEquals(REAL, address(query(up.port(),"www.example.com").queryUDP()));
		}
	}

	@Test
	public void wrongTypeIgnored() throws Exception {
		try(ScriptedUpstream up = new ScriptedUpstream(req -> {
			Message forged = answer(req, req.getID(), true, "www.example.com", FORGED);
			forged.setQuestion("www.example.com", DNS.MX, DNS.IN);
			return list(new Out(forged), new Out(genuine(req)));
		})) {
			assertEquals(REAL, address(query(up.port(),"www.example.com").queryUDP()));
		}
	}

	@Test
	public void queryInsteadOfResponseIgnored() throws Exception {
		try(ScriptedUpstream up = new ScriptedUpstream(req -> list(
				new Out(answer(req, req.getID(), false, "www.example.com", FORGED)),
				new Out(genuine(req))))) {
			assertEquals(REAL, address(query(up.port(),"www.example.com").queryUDP()));
		}
	}

	@Test
	public void otherSourcePortIgnored() throws Exception {
		try(ScriptedUpstream up = new ScriptedUpstream(req -> list(
				new Out(answer(req, req.getID(), true, "www.example.com", FORGED).toByteArray(), true),
				new Out(genuine(req))))) {
			assertEquals(REAL, address(query(up.port(),"www.example.com").queryUDP()));
		}
	}

	@Test
	public void malformedPacketIgnored() throws Exception {
		try(ScriptedUpstream up = new ScriptedUpstream(req -> {
			int id = req.getID();
			// right ID, QR=1, QDCOUNT=1, question name is a pointer loop
			byte [] bad = {(byte)(id>>8),(byte)id,(byte)0x81,0,0,1,0,0,0,0,0,0,(byte)0xC0,12,0,1,0,1};
			return list(new Out(bad,false), new Out(genuine(req)));
		})) {
			assertEquals(REAL, address(query(up.port(),"www.example.com").queryUDP()));
		}
	}

	@Test
	public void questionMatchIsCaseInsensitive() throws Exception {
		try(ScriptedUpstream up = new ScriptedUpstream(req -> list(
				new Out(answer(req, req.getID(), true, "WWW.Example.COM", REAL))))) {
			assertEquals(REAL, address(query(up.port(),"www.example.com").queryUDP()));
		}
	}

	@Test
	public void errorResponseWithoutQuestionAccepted() throws Exception {
		try(ScriptedUpstream up = new ScriptedUpstream(req -> {
			Message r = new Message();
			r.setHeader(req.getHeader().copy());
			r.setMessageTypeResponse();
			r.setResponseCodeFormatError();
			return list(new Out(r));
		})) {
			Message m = query(up.port(),"www.example.com").queryUDP();
			assertEquals(DNS.FORMAT_ERROR, m.getResponseCode());
		}
	}

	@Test
	public void onlyForgedAnswersTimesOut() throws Exception {
		try(ScriptedUpstream up = new ScriptedUpstream(req -> list(
				new Out(answer(req, (req.getID()+1) & 0xffff, true, "www.example.com", FORGED)),
				new Out(answer(req, req.getID(), true, "evil.example.com", FORGED)),
				new Out(answer(req, req.getID(), false, "www.example.com", FORGED))))) {
			Message m = query(up.port(),"www.example.com");
			m.setRetry(2);
			long start = System.currentTimeMillis();
			assertThrows(InterruptedIOException.class, () -> m.queryUDP());
			long took = System.currentTimeMillis()-start;
			assertTrue(took >= 900 && took < 5000, "should wait out both attempts, took "+took);
		}
	}

	// ------------------------------------------------------------------ TCP

	/** TCP responder: answers one connection with the message built by script. */
	static class TcpUpstream implements AutoCloseable {
		final ServerSocket ss;
		TcpUpstream(Function<Message,Message> script) throws Exception {
			ss = new ServerSocket(0, 5, InetAddress.getLoopbackAddress());
			Thread t = new Thread(() -> {
				while( !ss.isClosed() ) {
					try(Socket s = ss.accept()) {
						InputStream in = s.getInputStream();
						byte [] sz = new byte[2];
						Message.readArray(in,sz);
						byte [] data = new byte[Utility.makeShort(sz[0],sz[1])];
						Message.readArray(in,data);
						byte [] resp = script.apply(new Message(new ByteBuffer(data))).toByteArray();
						OutputStream out = s.getOutputStream();
						Utility.setShort(sz,0,resp.length);
						out.write(sz);
						out.write(resp);
						out.flush();
					} catch(IOException ex) {
					}
				}
			},"TcpUpstream");
			t.setDaemon(true);
			t.start();
		}
		@Override
		public void close() throws IOException {
			ss.close();
		}
	}

	@Test
	public void tcpGenuineAccepted() throws Exception {
		try(TcpUpstream up = new TcpUpstream(req -> genuine(req))) {
			Message m = query(up.ss.getLocalPort(),"www.example.com");
			assertEquals(REAL, address(m.queryTCP()));
		}
	}

	@Test
	public void tcpMismatchRejected() throws Exception {
		try(TcpUpstream up = new TcpUpstream(req -> answer(req, (req.getID()+1) & 0xffff, true, "www.example.com", FORGED))) {
			Message m = query(up.ss.getLocalPort(),"www.example.com");
			assertThrows(IOException.class, () -> m.queryTCP());
		}
		try(TcpUpstream up = new TcpUpstream(req -> answer(req, req.getID(), true, "evil.example.com", FORGED))) {
			Message m = query(up.ss.getLocalPort(),"www.example.com");
			assertThrows(IOException.class, () -> m.queryTCP());
		}
	}
}
