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
 */
package us.bringardner.net.dns.server;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import us.bringardner.net.dns.ByteBuffer;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.DnsBaseClass;
import us.bringardner.net.dns.Message;

/**
 * Sends DNS NOTIFY (RFC 1996) to secondary servers when a zone is loaded
 * or its SOA serial changes, so they transfer it without waiting for the
 * SOA refresh time. Messages go out over UDP from a background thread and
 * are retried until the secondary answers.
 */
public class ZoneNotifier extends DnsBaseClass {

	/** Default number of attempts per secondary. */
	public static final int DEFAULT_RETRIES = 5;
	/** Default wait for an answer (ms); doubled after each attempt. */
	public static final int DEFAULT_TIMEOUT = 2000;

	private final List<InetSocketAddress> targets;
	private final int retries;
	private final int timeout;
	private final ExecutorService sender = Executors.newSingleThreadExecutor(r -> {
		Thread t = new Thread(r, "ZoneNotifier");
		t.setDaemon(true);
		return t;
	});
	private final AtomicLong sent = new AtomicLong();
	private final AtomicLong acknowledged = new AtomicLong();
	private final AtomicLong failed = new AtomicLong();

	/**
	 * @param targets secondaries, e.g. "192.0.2.2, 192.0.2.3:5353, [2001:db8::2]:53"
	 */
	public ZoneNotifier(String targets, int retries, int timeout) {
		this.targets = parseTargets(targets);
		this.retries = Math.max(1, retries);
		this.timeout = Math.max(1, timeout);
	}

	/** Parse "addr[:port]" entries; IPv6 with a port is written [addr]:port. */
	static List<InetSocketAddress> parseTargets(String list) {
		List<InetSocketAddress> ret = new ArrayList<InetSocketAddress>();
		if( list == null ) {
			return ret;
		}
		for(String item : list.trim().split("[,\\s]+")) {
			if( item.isEmpty() ) {
				continue;
			}
			String host = item;
			int port = Message.DNSPORT;
			if( item.startsWith("[") ) {
				int end = item.indexOf(']');
				if( end < 0 ) {
					throw new IllegalArgumentException("Invalid notify target '"+item+"'");
				}
				host = item.substring(1, end);
				if( item.length() > end+1 ) {
					if( item.charAt(end+1) != ':' ) {
						throw new IllegalArgumentException("Invalid notify target '"+item+"'");
					}
					port = parsePort(item.substring(end+2), item);
				}
			} else if( item.indexOf(':') == item.lastIndexOf(':') && item.indexOf(':') > 0 ) {
				//  IPv4 or name with a port (a single ':')
				host = item.substring(0, item.indexOf(':'));
				port = parsePort(item.substring(item.indexOf(':')+1), item);
			}
			AddressMatcher.parse(host);		//  an address literal, never a name lookup
			try {
				ret.add(new InetSocketAddress(InetAddress.getByName(host), port));
			} catch(IOException e) {
				throw new IllegalArgumentException("Invalid notify target '"+item+"'");
			}
		}
		return Collections.unmodifiableList(ret);
	}

	private static int parsePort(String p, String item) {
		if( !p.matches("[0-9]{1,5}") || Integer.parseInt(p) > 65535 || Integer.parseInt(p) == 0 ) {
			throw new IllegalArgumentException("Invalid port in notify target '"+item+"'");
		}
		return Integer.parseInt(p);
	}

	public List<InetSocketAddress> getTargets() {
		return targets;
	}

	/** Notify every secondary about this zone (returns at once; sent in the background). */
	public void notifyZone(Zone zone) {
		if( targets.isEmpty() ) {
			return;
		}
		final String name = zone.getName();
		final us.bringardner.net.dns.RR soa = zone.getSoa().copy();
		for(InetSocketAddress t : targets) {
			try {
				sender.execute(() -> send(name, soa, t));
			} catch(java.util.concurrent.RejectedExecutionException ex) {
				//  shut down (the server is stopping)
				return;
			}
		}
	}

	/** The NOTIFY message for a zone (RFC 1996 3.7: SOA question, SOA in the answer). */
	static Message notifyMessage(String zoneName, us.bringardner.net.dns.RR soa, int id) {
		Message m = new Message();
		m.setID(id);
		m.getHeader().setOPCODE(DNS.NOTIFY);
		m.setAuthorityAnswerOn();
		m.setQuestion(zoneName, DNS.SOA, DNS.IN);
		m.getAnswer().add(soa);
		return m;
	}

	private void send(String zoneName, us.bringardner.net.dns.RR soa, InetSocketAddress target) {
		int id = new java.security.SecureRandom().nextInt(0x10000);
		byte [] data = notifyMessage(zoneName, soa, id).toByteArray();
		int wait = timeout;
		try(DatagramSocket sock = new DatagramSocket()) {
			for(int attempt=1; attempt <= retries; attempt++ ) {
				sock.send(new DatagramPacket(data, data.length, target));
				sent.incrementAndGet();
				long end = System.currentTimeMillis()+wait;
				byte [] buf = new byte[4096];
				while( System.currentTimeMillis() < end ) {
					sock.setSoTimeout((int)Math.max(1, end-System.currentTimeMillis()));
					DatagramPacket p = new DatagramPacket(buf, buf.length);
					try {
						sock.receive(p);
					} catch(SocketTimeoutException e) {
						break;
					}
					if( !p.getAddress().equals(target.getAddress()) || p.getPort() != target.getPort() ) {
						continue;
					}
					try {
						Message r = new Message(new ByteBuffer(java.util.Arrays.copyOf(buf, p.getLength())));
						if( r.getID() == id && !r.isQuery() && r.getHeader().getOPCODE() == DNS.NOTIFY ) {
							acknowledged.incrementAndGet();
							log(() -> "NOTIFY for "+zoneName+" acknowledged by "+target);
							return;
						}
					} catch(RuntimeException ignore) {
						//  not a DNS message
					}
				}
				wait *= 2;
			}
			failed.incrementAndGet();
			logError("NOTIFY for "+zoneName+" to "+target+" was not answered after "+retries+" attempts");
		} catch(IOException ex) {
			failed.incrementAndGet();
			logError("NOTIFY for "+zoneName+" to "+target+" failed: "+ex);
		}
	}

	public long getSent() { return sent.get(); }
	public long getAcknowledged() { return acknowledged.get(); }
	public long getFailed() { return failed.get(); }

	/** Stop sending (queued notifications are dropped). */
	public void shutdown() {
		sender.shutdownNow();
	}

	/** Wait until everything queued so far has been sent (or given up). For tests. */
	boolean awaitIdle(long ms) throws InterruptedException {
		java.util.concurrent.Future<?> f = sender.submit(() -> {});
		try {
			f.get(ms, TimeUnit.MILLISECONDS);
			return true;
		} catch(java.util.concurrent.ExecutionException | java.util.concurrent.TimeoutException e) {
			return false;
		}
	}
}
