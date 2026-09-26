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
package us.bringardner.net.dns.dnssec;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.A;
import us.bringardner.net.dns.ByteBuffer;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Dnskey;
import us.bringardner.net.dns.Ds;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.Mx;
import us.bringardner.net.dns.Nsec;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.Rrsig;

/**
 * DNSSEC records, keys, canonical form and signatures (RFC 4034), checked
 * against the RFC examples where there are some.
 */
public class TestDnssec {

	private static byte [] hex(String h) {
		h = h.replaceAll("\\s", "");
		byte [] b = new byte[h.length()/2];
		for(int i=0; i < b.length; i++ ) {
			b[i] = (byte)Integer.parseInt(h.substring(2*i, 2*i+2), 16);
		}
		return b;
	}

	private static File tempDir() throws IOException {
		return Files.createTempDirectory("dnssec").toFile();
	}

	private static void delete(File dir) {
		File [] list = dir.listFiles();
		if( list != null ) {
			for(File f : list) {
				f.delete();
			}
		}
		dir.delete();
	}

	// ------------------------------------------------------------ RFC examples

	@Test
	public void keyTagAndDsOfTheRfc4509Example() {
		Dnskey k = new Dnskey("dskey.example.com", DNS.IN);
		k.setFlags(256);
		k.setProtocol(3);
		k.setAlgorithm(5);
		k.setKey(Base64.getDecoder().decode("AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZ"
				+"DRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9XzcnOf+EPbtG9DMBmADjFDc2w/r"
				+"ljwvFw=="));
		assertEquals(60485, k.getKeyTag());
		Ds ds = DnssecKey.ds("dskey.example.com", k, Ds.SHA256, 86400);
		assertEquals(60485, ds.getKeyTag());
		assertEquals(5, ds.getAlgorithm());
		assertEquals("D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A", ds.getDigestHex());
	}

	@Test
	public void nsecWireFormOfTheRfc4034Example() {
		//  RFC 4034 4.3: alfa.example.com. NSEC host.example.com. A MX RRSIG NSEC TYPE1234
		Nsec n = new Nsec("alfa.example.com", DNS.IN);
		n.setTTL(86400);
		n.setNext("host.example.com.");
		n.setTypes(Arrays.asList(DNS.A, DNS.MX, DNS.RRSIG, DNS.NSEC, 1234));
		byte [] expected = hex("04686f7374076578616d706c6503636f6d00"
				+"0006400100000003"
				+"041b000000000000000000000000000000000000000000000000000020");
		assertArrayEquals(expected, Canonical.rdata(n));
		assertEquals("host.example.com. A MX RRSIG NSEC TYPE1234", n.getRdataAsString());
		//  And back
		RR back = roundTrip(n);
		assertTrue(back instanceof Nsec);
		assertEquals(n.getTypes(), ((Nsec)back).getTypes());
		assertEquals("host.example.com", ((Nsec)back).getNext());
	}

	@Test
	public void canonicalNameOrderOfTheRfc4034Example() {
		List<String> expected = Arrays.asList("example", "a.example", "yljkjljk.a.example", "Z.a.example",
				"zABC.a.EXAMPLE", "z.example", "*.z.example");
		List<String> shuffled = new ArrayList<String>(expected);
		Collections.reverse(shuffled);
		shuffled.sort(Canonical.NAME_ORDER);
		assertEquals(expected, shuffled);
		assertEquals(0, Canonical.compareNames("WWW.Example.COM.", "www.example.com"));
		assertEquals(2, Canonical.labelCount("*.a.example"));
		assertEquals(3, Canonical.labelCount("b.a.example."));
	}

	// ------------------------------------------------------------ records

	private static RR roundTrip(RR rr) {
		Message m = new Message();
		m.setQuestion("x.test", DNS.A, DNS.IN);
		m.addAnswer(rr);
		Message back = new Message(new ByteBuffer(m.toByteArray()));
		return back.getAnswer().get(0);
	}

	@Test
	public void recordsSurviveTheWire() {
		Dnskey k = new Dnskey("example.test", DNS.IN);
		k.setFlags(257);
		k.setAlgorithm(13);
		k.setKey(new byte[64]);
		Dnskey k2 = (Dnskey)roundTrip(k);
		assertEquals(k.getRdataAsString(), k2.getRdataAsString());
		assertEquals(k.getKeyTag(), k2.getKeyTag());
		assertTrue(k2.isKsk());

		Ds ds = new Ds("child.example.test", DNS.IN);
		ds.setKeyTag(12345);
		ds.setAlgorithm(13);
		ds.setDigestType(2);
		ds.setDigest("0123 4567 89ab cdef");
		assertEquals("12345 13 2 0123456789ABCDEF", ((Ds)roundTrip(ds)).getRdataAsString());

		Rrsig s = new Rrsig("www.example.test", DNS.IN);
		s.setTypeCovered(DNS.A);
		s.setAlgorithm(13);
		s.setLabels(3);
		s.setOrigTtl(3600);
		s.setExpiration(0xF0000000L);
		s.setInception(1700000000L);
		s.setKeyTag(65000);
		s.setSigner("Example.Test.");
		s.setSignature(new byte[] {1,2,3});
		Rrsig s2 = (Rrsig)roundTrip(s);
		assertEquals(s.getRdataAsString(), s2.getRdataAsString());
		assertEquals(0xF0000000L, s2.getExpiration());
		assertEquals(65000, s2.getKeyTag());
		//  The signer name is never compressed, and lower case in the data that is signed
		assertTrue(new String(s.rdataWithoutSignature(), StandardCharsets.ISO_8859_1).contains("\007example\004test\000"));
	}

	// ------------------------------------------------------------ signatures

	private static List<RR> mxSet() {
		List<RR> ret = new ArrayList<RR>();
		for(String host : new String[] {"Mail2.Example.Test", "mail1.example.test"}) {
			Mx mx = new Mx("example.test");
			mx.setPref((short)10);
			mx.setExchange(host);
			mx.setTTL(300);
			ret.add(mx);
		}
		return ret;
	}

	@Test
	public void everyAlgorithmSignsAndVerifies() throws Exception {
		long now = System.currentTimeMillis()/1000;
		for(int alg : new int[] {Algorithm.RSASHA256, Algorithm.RSASHA512, Algorithm.ECDSAP256SHA256, Algorithm.ECDSAP384SHA384, Algorithm.ED25519}) {
			DnssecKey key;
			try {
				key = DnssecKey.generate("example.test", Algorithm.of(alg), false, alg == Algorithm.RSASHA512 ? 1024 : 0);
			} catch(java.security.GeneralSecurityException ex) {
				assertEquals(Algorithm.ED25519, alg, "only ED25519 may be missing (Java before 15)");
				continue;
			}
			List<RR> set = mxSet();
			Rrsig sig = Canonical.sign("example.test", set, 300, key, now-3600, now+3600);
			assertEquals(DNS.MX, sig.getTypeCovered());
			assertEquals(2, sig.getLabels());
			assertTrue(Canonical.verify(sig, "example.test", set, key.getDnskey()), "algorithm "+alg);
			//  Record order and name case don't matter (canonical form)
			List<RR> reversed = new ArrayList<RR>(set);
			Collections.reverse(reversed);
			((Mx)reversed.get(0)).setExchange("MAIL1.EXAMPLE.TEST");
			assertTrue(Canonical.verify(sig, "example.test", reversed, key.getDnskey()), "algorithm "+alg);
			//  Any change of the data does
			((Mx)reversed.get(1)).setPref((short)20);
			assertFalse(Canonical.verify(sig, "example.test", reversed, key.getDnskey()), "algorithm "+alg);
			//  So does a signature over the wire and back
			Rrsig back = (Rrsig)roundTrip(sig);
			assertTrue(Canonical.verify(back, "example.test", mxSet(), key.getDnskey()), "algorithm "+alg);
		}
	}

	// ------------------------------------------------------------ key files

	@Test
	public void keyFilesRoundTrip() throws Exception {
		File dir = tempDir();
		try {
			DnssecKey k = DnssecKey.generate("Example.Test.", Algorithm.of("ecdsap256sha256"), true, 0);
			File f = k.save(dir);
			assertEquals(k.baseName()+".key", f.getName());
			assertTrue(f.getName().matches("Kexample\\.test\\.\\+013\\+\\d{5}\\.key"), f.getName());
			File priv = new File(dir, k.baseName()+".private");
			String p = new String(Files.readAllBytes(priv.toPath()), StandardCharsets.US_ASCII);
			assertTrue(p.startsWith("Private-key-format: v1.3\nAlgorithm: 13 (ECDSAP256SHA256)\nPrivateKey: "), p);
			DnssecKey back = DnssecKey.load(f);
			assertEquals(k.getKeyTag(), back.getKeyTag());
			assertEquals("example.test", back.getZone());
			assertTrue(back.isKsk());
			assertTrue(back.hasPrivateKey());
			long now = System.currentTimeMillis()/1000;
			assertTrue(back.isActive(now+10));
			//  The loaded private key makes signatures the public key verifies
			List<RR> set = mxSet();
			Rrsig sig = Canonical.sign("example.test", set, 300, back, now, now+60);
			assertTrue(Canonical.verify(sig, "example.test", set, k.getDnskey()));
			//  Grouped by zone
			Map<String, List<DnssecKey>> all = DnssecKey.loadDir(dir, new ArrayList<String>());
			assertEquals(1, all.get("example.test").size());
		} finally {
			delete(dir);
		}
	}

	@Test
	public void publicOnlyKeysAndTiming() throws Exception {
		File dir = tempDir();
		try {
			DnssecKey k = DnssecKey.generate("example.test", Algorithm.of(13), false, 0);
			File f = k.save(dir);
			File priv = new File(dir, k.baseName()+".private");
			//  BIND timing: Activate in the future, Delete later still
			String text = new String(Files.readAllBytes(priv.toPath()), StandardCharsets.US_ASCII)
					.replaceAll("Activate: \\d+", "Activate: 20991231000000")+"Delete: 21000101000000\n";
			Files.write(priv.toPath(), text.getBytes(StandardCharsets.US_ASCII));
			DnssecKey timed = DnssecKey.load(f);
			long now = System.currentTimeMillis()/1000;
			assertTrue(timed.isPublished(now));
			assertFalse(timed.isActive(now), "not active before Activate");
			assertTrue(timed.nextEvent(now) > now);
			assertFalse(timed.isPublished(4102444800L+1), "deleted after Delete");
			//  Without its .private file a key is only published
			assertTrue(priv.delete());
			DnssecKey pub = DnssecKey.load(f);
			assertFalse(pub.hasPrivateKey());
			assertTrue(pub.isPublished(now));
			assertFalse(pub.isActive(now));
			assertThrows(IllegalStateException.class, () -> pub.sign(new byte[1]));
		} finally {
			delete(dir);
		}
	}

	@Test
	public void mismatchedPrivateKeyIsRejected() throws Exception {
		File dir = tempDir();
		try {
			DnssecKey a = DnssecKey.generate("example.test", Algorithm.of(13), false, 0);
			DnssecKey b = DnssecKey.generate("example.test", Algorithm.of(13), false, 0);
			File fa = a.save(dir);
			b.save(dir);
			//  a's .key with b's .private
			Files.copy(new File(dir, b.baseName()+".private").toPath(), new File(dir, a.baseName()+".private").toPath(),
					java.nio.file.StandardCopyOption.REPLACE_EXISTING);
			IOException ex = assertThrows(IOException.class, () -> DnssecKey.load(fa));
			assertTrue(ex.getMessage().contains("does not hold the private key"), ex.getMessage());
			List<String> errors = new ArrayList<String>();
			Map<String, List<DnssecKey>> all = DnssecKey.loadDir(dir, errors);
			assertEquals(1, errors.size(), errors.toString());
			assertEquals(1, all.get("example.test").size(), "the good key is still loaded");
		} finally {
			delete(dir);
		}
	}

	@Test
	public void keyFileWithBindLayout() throws Exception {
		File dir = tempDir();
		try {
			//  As dnssec-keygen writes it: comments, no TTL, the key split over lines in ( )
			DnssecKey k = DnssecKey.generate("bind.test", Algorithm.of(13), true, 0);
			k.save(dir);
			File f = new File(dir, k.baseName()+".key");
			String b64 = Base64.getEncoder().encodeToString(k.getDnskey().getKey());
			Files.write(f.toPath(), ("; This is a key-signing key, keyid "+k.getKeyTag()+", for bind.test.\n"
					+"; Created: 20260926000000 (Sat Sep 26 00:00:00 2026)\n"
					+"bind.test. IN DNSKEY 257 3 13 ( "+b64.substring(0, 40)+"\n\t"+b64.substring(40)+" )\n").getBytes(StandardCharsets.US_ASCII));
			DnssecKey back = DnssecKey.load(f);
			assertEquals(k.getKeyTag(), back.getKeyTag());
			assertEquals(3600, back.getDnskey().getTTL(), "default TTL");
		} finally {
			delete(dir);
		}
	}

	@Test
	public void keyTool() throws Exception {
		File dir = tempDir();
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			ByteArrayOutputStream err = new ByteArrayOutputStream();
			assertEquals(0, DnssecKeyTool.run(new String[] {"keygen", "-d", dir.getPath(), "tool.test"}, new PrintStream(out), new PrintStream(err)));
			String text = out.toString("UTF-8");
			assertTrue(text.contains("tool.test. IN DS "), text);
			assertEquals(2, dir.listFiles().length);
			out.reset();
			assertEquals(0, DnssecKeyTool.run(new String[] {"ds", "-d", dir.getPath(), "tool.test."}, new PrintStream(out), new PrintStream(err)));
			assertTrue(out.toString("UTF-8").matches("tool\\.test\\. IN DS \\d+ 13 2 [0-9A-F]{64}\\s*"), out.toString("UTF-8"));
			//  A zone signing key has no DS
			out.reset();
			assertEquals(0, DnssecKeyTool.run(new String[] {"keygen", "-zsk", "-a", "ECDSAP384SHA384", "-d", dir.getPath(), "zsk.test"}, new PrintStream(out), new PrintStream(err)));
			assertFalse(out.toString("UTF-8").contains(" IN DS "), out.toString("UTF-8"));
			assertTrue(out.toString("UTF-8").contains("ZSK ECDSAP384SHA384"), out.toString("UTF-8"));
			assertEquals(2, DnssecKeyTool.run(new String[] {"keygen"}, new PrintStream(out), new PrintStream(err)), "usage");
			assertEquals(1, DnssecKeyTool.run(new String[] {"keygen", "-a", "RSAMD5", "-d", dir.getPath(), "x.test"}, new PrintStream(out), new PrintStream(err)));
		} finally {
			delete(dir);
		}
	}

	@Test
	public void unsupportedAlgorithm() {
		assertThrows(IllegalArgumentException.class, () -> Algorithm.of(5));
		assertThrows(IllegalArgumentException.class, () -> Algorithm.of("DSA"));
		assertNotNull(Algorithm.of("RSASHA256"));
		assertEquals(Algorithm.ED25519, Algorithm.of("ed25519").getNumber());
	}

	@Test
	public void aRecordCanonicalData() {
		//  Owner lower case, uncompressed, with the original TTL: RFC 4034 6.2
		A a = new A("WWW.Example.Test");
		a.setAddress("192.0.2.1");
		a.setTTL(10);
		Rrsig sig = new Rrsig("www.example.test", DNS.IN);
		sig.setTypeCovered(DNS.A);
		sig.setOrigTtl(3600);
		sig.setSigner("example.test");
		byte [] data = Canonical.signedData(sig, "WWW.Example.Test", Collections.singletonList(a));
		byte [] fixed = sig.rdataWithoutSignature();
		byte [] tail = Arrays.copyOfRange(data, fixed.length, data.length);
		assertArrayEquals(hex("03777777076578616d706c65047465737400 0001 0001 00000e10 0004 c0000201"), tail);
	}
}
