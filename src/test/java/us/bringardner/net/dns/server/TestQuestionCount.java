package us.bringardner.net.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.ByteBuffer;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.resolve.QueryData;
import us.bringardner.net.dns.resolve.ResolverThread;

/**
 * Rec #53 / #54: a request must have exactly one question (RFC 9619; one
 * zone for UPDATE, RFC 2136 3.1.1), otherwise one FORMERR without a question
 * section. Responses (QR=1) are not answered.
 * <p>
 * Before: N questions got N responses, each answering the first question
 * (amplification, and N entries in the resolver backlog); no question threw
 * IndexOutOfBoundsException (logged with a stack trace for every packet);
 * a response got a REFUSED reply.
 */
public class TestQuestionCount {

	private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();
	private static File dir;
	private static DnsServer server;
	private static Thread udp;
	private static Thread tcp;
	private static int udpPort;
	private static int tcpPort;
	private static String savedZoneDir;
	private static String savedMaster;

	@BeforeAll
	public static void setup() throws Exception {
		dir = Files.createTempDirectory("qcount").toFile();
		try(FileWriter w = new FileWriter(new File(dir,"qc.test.txt"))) {
			w.write("@\tIN\tSOA\tns1.qc.test. postmaster.qc.test. (\n"
					+"\t\t\t1 ; serial\n\t\t\t3600 ; refresh\n\t\t\t1800 ; retry\n"
					+"\t\t\t1209600 ; expire\n\t\t\t300 ) ; minimum\n\n"
					+"\t\tNS\tns1\n"
					+"ns1\tIN\tA\t10.0.0.53\n"
					+"www\tIN\tA\t10.0.0.80\n");
		}
		savedZoneDir = System.getProperty(DnsServer.PROP_ZONE_DIR);
		savedMaster = System.getProperty(DnsServer.PROP_DEFAULT_ZONE);
		System.setProperty(DnsServer.PROP_ZONE_DIR, dir.getAbsolutePath());
		System.setProperty(DnsServer.PROP_DEFAULT_ZONE, "qc.test");
		server = new DnsServer();
		server.loadZones();
		server.setRecursionAvailable(false);

		try(DatagramSocket probe = new DatagramSocket(0, LOOPBACK)) {
			udpPort = probe.getLocalPort();
		}
		DnsServer.setShutdown(false);
		UDPProsessor.initUDPProsessor(udpPort, LOOPBACK, 200);
		udp = new Thread(new UDPProsessor(server,0),"TestQuestionCountUDP");
		udp.setDaemon(true);
		udp.start();

		TCPProsessor.initTCPProsessor(0, 10, LOOPBACK, 200, 8, 5000);
		tcpPort = TCPProsessor.getServerSocket().getLocalPort();
		tcp = new Thread(new TCPProsessor(server,0),"TestQuestionCountTCP");
		tcp.setDaemon(true);
		tcp.start();
	}

	@AfterAll
	public static void cleanup() throws Exception {
		DnsServer.setShutdown(true);
		udp.join(3000);
		UDPProsessor.getSock().close();
		TCPProsessor.getServerSocket().close();
		TCPProsessor.shutdownConnections(5000);
		tcp.join(3000);
		DnsServer.setShutdown(false);
		restore(DnsServer.PROP_ZONE_DIR, savedZoneDir);
		restore(DnsServer.PROP_DEFAULT_ZONE, savedMaster);
		for(File f : dir.listFiles()) {
			f.delete();
		}
		dir.delete();
	}

	private static void restore(String k, String v) {
		if( v == null ) {
			System.clearProperty(k);
		} else {
			System.setProperty(k, v);
		}
	}

	/** www.qc.test IN A on the wire */
	private static final byte [] QUESTION = {
			3,'w','w','w', 2,'q','c', 4,'t','e','s','t', 0,  0,1, 0,1 };

	/**
	 * A request with 'count' copies of the question.
	 * @param flags2 the third header byte (QR, OPCODE, AA, TC, RD)
	 */
	private static byte [] request(int id, int flags2, int count) {
		ByteArrayOutputStream b = new ByteArrayOutputStream();
		b.write(id >> 8);
		b.write(id);
		b.write(flags2);
		b.write(0);
		b.write(count >> 8);
		b.write(count);
		for(int i=0; i < 6; i++ ) {
			b.write(0);
		}
		for(int i=0; i < count; i++ ) {
			b.write(QUESTION, 0, QUESTION.length);
		}
		return b.toByteArray();
	}

	/** Send over UDP; every reply that arrives within waitMs. */
	private static List<byte []> udp(byte [] data, int waitMs) throws IOException {
		List<byte []> ret = new java.util.ArrayList<byte []>();
		try(DatagramSocket c = new DatagramSocket(0, LOOPBACK)) {
			c.send(new DatagramPacket(data, data.length, LOOPBACK, udpPort));
			long end = System.currentTimeMillis()+waitMs;
			while( true ) {
				long left = end - System.currentTimeMillis();
				if( left <= 0 ) {
					break;
				}
				c.setSoTimeout((int)left);
				byte [] buf = new byte[4096];
				DatagramPacket p = new DatagramPacket(buf, buf.length);
				try {
					c.receive(p);
				} catch(SocketTimeoutException ex) {
					break;
				}
				ret.add(java.util.Arrays.copyOf(buf, p.getLength()));
			}
		}
		return ret;
	}

	private static Message parse(byte [] wire) {
		return new Message(new ByteBuffer(wire));
	}

	private static void assertFormErr(Message r, int id) {
		assertEquals(id, r.getID());
		assertTrue(r.isResponse(), "QR set");
		assertEquals(DNS.FORMAT_ERROR, r.getResponseCode());
		assertEquals(0, r.getQuestionCount(), "no question section");
		assertEquals(0, r.getAnswerCount());
	}

	@Test
	public void manyQuestionsOverUdpGetOneSmallFormErr() throws Exception {
		long before = DnsServer.getQuestionCountErrors();
		byte [] req = request(0x1111, 0x01, 100);
		assertTrue(req.length > 1700);
		List<byte []> replies = udp(req, 1000);
		assertEquals(1, replies.size(), "one reply, not one per question");
		assertEquals(12, replies.get(0).length, "header only");
		assertFormErr(parse(replies.get(0)), 0x1111);
		assertEquals(before+1, DnsServer.getQuestionCountErrors());
	}

	@Test
	public void twoQuestionsOverUdp() throws Exception {
		List<byte []> replies = udp(request(0x2222, 0x00, 2), 1000);
		assertEquals(1, replies.size());
		assertFormErr(parse(replies.get(0)), 0x2222);
	}

	@Test
	public void noQuestionOverUdpGetsFormErr() throws Exception {
		long before = DnsServer.getQuestionCountErrors();
		List<byte []> replies = udp(request(0x3333, 0x01, 0), 1000);
		assertEquals(1, replies.size(), "used to throw IndexOutOfBoundsException and send nothing");
		assertFormErr(parse(replies.get(0)), 0x3333);
		assertEquals(before+1, DnsServer.getQuestionCountErrors());
	}

	@Test
	public void responsesAreNotAnswered() throws Exception {
		//  QR=1, with and without a question (used to get REFUSED)
		assertEquals(0, udp(request(0x4444, 0x80, 1), 500).size());
		assertEquals(0, udp(request(0x4445, 0x80, 0), 500).size());
		assertEquals(0, udp(request(0x4446, 0x80, 3), 500).size());
	}

	@Test
	public void oneQuestionStillAnswered() throws Exception {
		List<byte []> replies = udp(request(0x5555, 0x00, 1), 1000);
		assertEquals(1, replies.size());
		Message r = parse(replies.get(0));
		assertEquals(DNS.NOERROR, r.getResponseCode());
		assertEquals(1, r.getAnswerCount());
		assertEquals("www.qc.test", r.getFirstQuestion().getName());
	}

	@Test
	public void tcpFormErrKeepsTheConnection() throws Exception {
		try(Socket s = new Socket(LOOPBACK, tcpPort)) {
			s.setSoTimeout(3000);
			OutputStream out = s.getOutputStream();
			DataInputStream in = new DataInputStream(s.getInputStream());

			TCPProsessor.writeMessage(out, request(0x6666, 0x00, 0));
			byte [] r1 = new byte[in.readUnsignedShort()];
			in.readFully(r1);
			assertFormErr(parse(r1), 0x6666);

			TCPProsessor.writeMessage(out, request(0x6667, 0x00, 5));
			byte [] r2 = new byte[in.readUnsignedShort()];
			in.readFully(r2);
			assertFormErr(parse(r2), 0x6667);

			//  The framing is fine, so the connection is still usable
			TCPProsessor.writeMessage(out, request(0x6668, 0x00, 1));
			byte [] r3 = new byte[in.readUnsignedShort()];
			in.readFully(r3);
			Message ok = parse(r3);
			assertEquals(0x6668, ok.getID());
			assertEquals(DNS.NOERROR, ok.getResponseCode());
			assertEquals(1, ok.getAnswerCount());
		}
	}

	@Test
	public void recursiveMultiQuestionDoesNotFillTheBacklog() {
		ResolverThread.clearBacklog();
		try {
			server.setRecursionAvailable(true);
			Message q = new Message();
			q.setID(0x7777);
			q.recursiveDesired(true);
			for(int i=0; i < 50; i++ ) {
				q.addQuestion(new us.bringardner.net.dns.Section("www.example.com", DNS.A, DNS.IN));
			}
			Message in = parse(q.toByteArray());
			assertEquals(50, in.getQuestionCount());
			List<Message> r = server.query(new QueryData(LOOPBACK, 5353, in));
			assertEquals(1, r.size());
			assertFormErr(r.get(0), 0x7777);
			assertEquals(0, ResolverThread.getBacklog(), "nothing queued (used to be 50 entries)");
		} finally {
			server.setRecursionAvailable(false);
			ResolverThread.clearBacklog();
		}
	}

	@Test
	public void updateWithTwoZonesIsFormErr() {
		Message u = new Message();
		u.setID(0x8888);
		u.getHeader().setOPCODE(DNS.UPDATE);
		u.addQuestion(new us.bringardner.net.dns.Section("qc.test", DNS.SOA, DNS.IN));
		u.addQuestion(new us.bringardner.net.dns.Section("qc.test", DNS.SOA, DNS.IN));
		List<Message> r = server.query(new QueryData(LOOPBACK, 5353, parse(u.toByteArray())));
		assertEquals(1, r.size());
		assertFormErr(r.get(0), 0x8888);
		assertEquals(DNS.UPDATE, r.get(0).getHeader().getOPCODE());
	}

	@Test
	public void queryDataWithoutQuestion() {
		QueryData qd = new QueryData(LOOPBACK, 5353, parse(request(0x9999, 0x00, 0)));
		assertNull(qd.getQuestion());
		assertNotNull(qd.getMessage());
	}
}
