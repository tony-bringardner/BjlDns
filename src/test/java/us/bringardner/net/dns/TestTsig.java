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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Base64;

import org.junit.jupiter.api.Test;

/**
 * TSIG (RFC 8945): keys, signing and checking (rec #42).
 * The same code was also checked against dnspython (queries, AXFR, errors).
 */
public class TestTsig {

	private static final String SECRET = Base64.getEncoder().encodeToString("0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.US_ASCII));
	private static final Tsig.KeyRing KEYS = Tsig.KeyRing.parse(
			"k256:hmac-sha256:"+SECRET+", k512.example.:hmac-sha512:"+SECRET+" kmd5:hmac-md5:"+SECRET);

	private static byte [] query(int id) {
		Message m = new Message();
		m.setQuestion("www.example", DNS.A, DNS.IN);
		m.setID(id);
		return m.toByteArray();
	}

	private static byte [] response(byte [] request) {
		Message q = new Message(new ByteBuffer(request));
		Message r = new Message();
		r.setID(q.getID());
		r.setMessageTypeResponse();
		r.setQuestion(q.getQuestion().get(0));
		A a = new A("www.example");
		a.setAddress("10.0.0.1");
		r.addAnswer(a);
		return r.toByteArray();
	}

	// ------------------------------------------------------------ keys

	@Test
	public void keyRing() throws Exception {
		assertEquals(3, KEYS.size());
		assertEquals("hmac-sha256", KEYS.get("K256.").getAlgorithm(), "names are case and dot insensitive");
		assertEquals("hmac-md5.sig-alg.reg.int", KEYS.get("kmd5").getAlgorithm());
		assertNotNull(KEYS.get("k512.example"));
		assertNull(KEYS.get("nope"));
		for(String bad : new String[] {"k:hmac-sha3:"+SECRET, "k:hmac-sha256:not*base64", "k:hmac-sha256", "k:hmac-sha256:"+SECRET+" k:hmac-sha1:"+SECRET}) {
			assertThrows(IllegalArgumentException.class, () -> Tsig.KeyRing.parse(bad), bad);
		}
		File f = Files.createTempFile("keys", ".txt").toFile();
		try(FileWriter w = new FileWriter(f)) {
			w.write("# transfer keys\nxfr.example. hmac-sha256 "+SECRET+"   # for the secondaries\n\n");
		}
		assertEquals("hmac-sha256", Tsig.KeyRing.load(f).get("xfr.example").getAlgorithm());
		f.delete();
	}

	// ------------------------------------------------------------ exchange

	@Test
	public void signedRequestAndResponse() throws Exception {
		for(String name : new String[] {"k256", "k512.example", "kmd5"}) {
			Tsig.Session client = Tsig.Session.client(KEYS.get(name));
			byte [] req = client.signRequest(query(1000));
			Tsig.Session server = Tsig.Session.verifyRequest(KEYS, req);
			assertNotNull(server);
			assertEquals(Tsig.NOERROR, server.getError(), name);
			//  The request still parses as a message (the TSIG is one more additional record)
			assertEquals(1, new Message(new ByteBuffer(req)).getQuestionCount());
			byte [] resp = server.signResponse(response(req));
			client.verifyResponse(resp);
			assertEquals(1, new Message(new ByteBuffer(resp)).getAnswerCount());
		}
	}

	@Test
	public void unsignedRequestHasNoSession() {
		assertNull(Tsig.Session.verifyRequest(KEYS, query(1)));
		assertNull(Tsig.Session.verifyRequest(KEYS, null));
	}

	@Test
	public void multiMessageResponse() throws Exception {
		//  Like a zone transfer: each message covered by the MAC of the one before
		Tsig.Session client = Tsig.Session.client(KEYS.get("k256"));
		byte [] req = client.signRequest(query(7));
		Tsig.Session server = Tsig.Session.verifyRequest(KEYS, req);
		byte [][] msgs = new byte[5][];
		for(int i=0; i < msgs.length; i++ ) {
			msgs[i] = server.signResponse(response(req));
		}
		for(byte [] m : msgs) {
			client.verifyResponse(m);
		}
		//  Out of order fails
		Tsig.Session c2 = Tsig.Session.client(KEYS.get("k256"));
		byte [] req2 = c2.signRequest(query(8));
		Tsig.Session s2 = Tsig.Session.verifyRequest(KEYS, req2);
		byte [] first = s2.signResponse(response(req2));
		byte [] second = s2.signResponse(response(req2));
		assertThrows(Tsig.TsigException.class, () -> c2.verifyResponse(second));
		c2.verifyResponse(first);
	}

	@Test
	public void tamperedRequestIsBadSig() {
		byte [] req = Tsig.Session.client(KEYS.get("k256")).signRequest(query(55));
		req[13] ^= 1;		//  inside the question name
		assertEquals(Tsig.BADSIG, Tsig.Session.verifyRequest(KEYS, req).getError());
	}

	@Test
	public void unknownKeyOrAlgorithmIsBadKey() {
		Tsig.Key other = new Tsig.Key("stranger", "hmac-sha256", new byte[32]);
		assertEquals(Tsig.BADKEY, Tsig.Session.verifyRequest(KEYS, Tsig.Session.client(other).signRequest(query(1))).getError());
		Tsig.Key sameNameOtherAlg = new Tsig.Key("k256", "hmac-sha1", Base64.getDecoder().decode(SECRET));
		assertEquals(Tsig.BADKEY, Tsig.Session.verifyRequest(KEYS, Tsig.Session.client(sameNameOtherAlg).signRequest(query(1))).getError());
	}

	@Test
	public void clockSkewIsBadTimeAndTheResponseIsStillSigned() throws Exception {
		Tsig.Session client = Tsig.Session.client(KEYS.get("k256"));
		byte [] req = client.signRequest(query(9));
		long now = System.currentTimeMillis()/1000;
		assertEquals(Tsig.NOERROR, Tsig.Session.verifyRequest(KEYS, req, now+Tsig.DEFAULT_FUDGE).getError(), "at the edge of the window");
		Tsig.Session server = Tsig.Session.verifyRequest(KEYS, req, now+Tsig.DEFAULT_FUDGE+60);
		assertEquals(Tsig.BADTIME, server.getError());
		byte [] resp = server.signResponse(response(req));
		Tsig.TsigException ex = assertThrows(Tsig.TsigException.class, () -> client.verifyResponse(resp));
		assertEquals(Tsig.BADTIME, ex.error, "the client sees the (verified) BADTIME");
		assertEquals(6, Tsig.find(resp).other.length, "with the server's time");
	}

	@Test
	public void errorResponsesForBadRequestsAreUnsigned() {
		byte [] req = Tsig.Session.client(new Tsig.Key("stranger", "hmac-sha256", new byte[32])).signRequest(query(3));
		Tsig.Session server = Tsig.Session.verifyRequest(KEYS, req);
		Tsig.Record r = Tsig.find(server.signResponse(response(req)));
		assertEquals(Tsig.BADKEY, r.error);
		assertEquals(0, r.mac.length);
	}

	@Test
	public void truncatedMacs() {
		Tsig.Key k = KEYS.get("k256");
		byte [] req = Tsig.Session.client(k).signRequest(query(11));
		Tsig.Record r = Tsig.find(req);
		//  Keep 16 of 32 bytes (allowed: at least half, at least 10)
		byte [] mac16 = java.util.Arrays.copyOf(r.mac, 16);
		byte [] body = Tsig.strip(req, r);
		byte [] t16 = Tsig.append(body, r.keyName, r.algorithm, r.timeSigned, r.fudge, mac16, r.originalId, 0, new byte[0]);
		assertEquals(Tsig.NOERROR, Tsig.Session.verifyRequest(KEYS, t16).getError());
		byte [] t8 = Tsig.append(body, r.keyName, r.algorithm, r.timeSigned, r.fudge, java.util.Arrays.copyOf(r.mac, 8), r.originalId, 0, new byte[0]);
		assertEquals(Tsig.BADTRUNC, Tsig.Session.verifyRequest(KEYS, t8).getError());
	}

	@Test
	public void tsigMustBeTheLastRecord() {
		byte [] req = Tsig.Session.client(KEYS.get("k256")).signRequest(query(12));
		//  Add another additional record (an OPT) after the TSIG
		byte [] opt = {0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0};
		byte [] bad = java.util.Arrays.copyOf(req, req.length+opt.length);
		System.arraycopy(opt, 0, bad, req.length, opt.length);
		bad[11]++;
		assertThrows(DnsFormatException.class, () -> Tsig.find(bad));
	}

	@Test
	public void stripRestoresTheOriginalMessage() {
		byte [] q = query(99);
		byte [] req = Tsig.Session.client(KEYS.get("k256")).signRequest(q);
		assertArrayEquals(q, Tsig.strip(req, Tsig.find(req)));
	}
}
