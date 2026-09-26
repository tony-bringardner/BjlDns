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

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The DNSSEC signing algorithms this server supports (RFC 8624 lists what
 * to use): 8 RSASHA256, 10 RSASHA512, 13 ECDSAP256SHA256 (the default),
 * 14 ECDSAP384SHA384 and 15 ED25519 (needs Java 15 or later at run time).
 * Each knows its DNSKEY public key format, its signature format and the
 * fields of its BIND style private key file.
 */
public abstract class Algorithm {

	public static final int RSASHA256 = 8;
	public static final int RSASHA512 = 10;
	public static final int ECDSAP256SHA256 = 13;
	public static final int ECDSAP384SHA384 = 14;
	public static final int ED25519 = 15;

	private final int number;
	private final String mnemonic;

	Algorithm(int number, String mnemonic) {
		this.number = number;
		this.mnemonic = mnemonic;
	}

	public int getNumber() {
		return number;
	}

	/** The name used in key files (e.g. ECDSAP256SHA256). */
	public String getMnemonic() {
		return mnemonic;
	}

	/** Make a key pair (bits is used by RSA only; 0 means the default). */
	public abstract KeyPair generate(int bits) throws GeneralSecurityException;

	/** The DNSKEY public key field for a public key. */
	public abstract byte [] publicKeyField(PublicKey pub);

	/** The private key file fields (after Private-key-format and Algorithm). */
	public abstract Map<String, String> privateFields(KeyPair pair);

	/** A private key from the private key file fields. */
	public abstract PrivateKey privateKey(Map<String, String> fields, byte [] publicKeyField) throws GeneralSecurityException;

	/** Sign data: the result is in DNSSEC signature format. */
	public abstract byte [] sign(PrivateKey key, byte [] data);

	/** Check a DNSSEC format signature with a DNSKEY public key field. */
	public abstract boolean verify(byte [] publicKeyField, byte [] data, byte [] signature);

	private static final Map<Integer, Algorithm> ALL = new LinkedHashMap<Integer, Algorithm>();
	static {
		ALL.put(RSASHA256, new Rsa(RSASHA256, "RSASHA256", "SHA256withRSA"));
		ALL.put(RSASHA512, new Rsa(RSASHA512, "RSASHA512", "SHA512withRSA"));
		ALL.put(ECDSAP256SHA256, new Ecdsa(ECDSAP256SHA256, "ECDSAP256SHA256", "secp256r1", "SHA256withECDSA", 32));
		ALL.put(ECDSAP384SHA384, new Ecdsa(ECDSAP384SHA384, "ECDSAP384SHA384", "secp384r1", "SHA384withECDSA", 48));
		ALL.put(ED25519, new Ed25519());
	}

	/** @throws IllegalArgumentException for an algorithm that is not supported */
	public static Algorithm of(int number) {
		Algorithm a = ALL.get(number);
		if( a == null ) {
			throw new IllegalArgumentException("DNSSEC algorithm "+number+" is not supported (use 8, 10, 13, 14 or 15)");
		}
		return a;
	}

	/** By number or mnemonic (case ignored). */
	public static Algorithm of(String name) {
		String n = name.trim();
		if( n.matches("\\d+") ) {
			return of(Integer.parseInt(n));
		}
		for(Algorithm a : ALL.values()) {
			if( a.mnemonic.equalsIgnoreCase(n) ) {
				return a;
			}
		}
		throw new IllegalArgumentException("Unknown DNSSEC algorithm '"+name+"' (use RSASHA256, RSASHA512, ECDSAP256SHA256, ECDSAP384SHA384 or ED25519)");
	}

	public static boolean isSupported(int number) {
		return ALL.containsKey(number);
	}

	static String b64(byte [] b) {
		return Base64.getEncoder().encodeToString(b);
	}

	static byte [] unb64(Map<String, String> fields, String name) {
		String v = fields.get(name);
		if( v == null ) {
			throw new IllegalArgumentException("private key file has no "+name);
		}
		return Base64.getMimeDecoder().decode(v.trim());
	}

	/** Unsigned big-endian bytes of v, without a leading zero (or padded to len when len > 0). */
	static byte [] unsigned(BigInteger v, int len) {
		byte [] b = v.toByteArray();
		if( b.length > 1 && b[0] == 0 ) {
			b = Arrays.copyOfRange(b, 1, b.length);
		}
		if( len > 0 && b.length < len ) {
			byte [] p = new byte[len];
			System.arraycopy(b, 0, p, len-b.length, b.length);
			b = p;
		}
		return b;
	}

	// ------------------------------------------------------------ RSA (RFC 3110, RFC 5702)

	static final class Rsa extends Algorithm {
		private final String sigAlg;

		Rsa(int n, String m, String sigAlg) {
			super(n, m);
			this.sigAlg = sigAlg;
		}

		@Override
		public KeyPair generate(int bits) throws GeneralSecurityException {
			KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
			g.initialize(new RSAKeyGenParameterSpec(bits <= 0 ? 2048 : bits, RSAKeyGenParameterSpec.F4));
			return g.generateKeyPair();
		}

		@Override
		public byte [] publicKeyField(PublicKey pub) {
			RSAPublicKey k = (RSAPublicKey)pub;
			byte [] e = unsigned(k.getPublicExponent(), 0);
			byte [] m = unsigned(k.getModulus(), 0);
			java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
			if( e.length <= 255 ) {
				out.write(e.length);
			} else {
				out.write(0);
				out.write(e.length >> 8);
				out.write(e.length & 0xff);
			}
			out.write(e, 0, e.length);
			out.write(m, 0, m.length);
			return out.toByteArray();
		}

		private static RSAPublicKeySpec publicSpec(byte [] field) {
			int pos = 0;
			int elen = field[pos++]&0xff;
			if( elen == 0 ) {
				elen = ((field[pos]&0xff) << 8) | (field[pos+1]&0xff);
				pos += 2;
			}
			BigInteger e = new BigInteger(1, Arrays.copyOfRange(field, pos, pos+elen));
			BigInteger m = new BigInteger(1, Arrays.copyOfRange(field, pos+elen, field.length));
			return new RSAPublicKeySpec(m, e);
		}

		@Override
		public Map<String, String> privateFields(KeyPair pair) {
			RSAPrivateCrtKey k = (RSAPrivateCrtKey)pair.getPrivate();
			Map<String, String> f = new LinkedHashMap<String, String>();
			f.put("Modulus", b64(unsigned(k.getModulus(), 0)));
			f.put("PublicExponent", b64(unsigned(k.getPublicExponent(), 0)));
			f.put("PrivateExponent", b64(unsigned(k.getPrivateExponent(), 0)));
			f.put("Prime1", b64(unsigned(k.getPrimeP(), 0)));
			f.put("Prime2", b64(unsigned(k.getPrimeQ(), 0)));
			f.put("Exponent1", b64(unsigned(k.getPrimeExponentP(), 0)));
			f.put("Exponent2", b64(unsigned(k.getPrimeExponentQ(), 0)));
			f.put("Coefficient", b64(unsigned(k.getCrtCoefficient(), 0)));
			return f;
		}

		@Override
		public PrivateKey privateKey(Map<String, String> f, byte [] pub) throws GeneralSecurityException {
			RSAPrivateCrtKeySpec spec = new RSAPrivateCrtKeySpec(
					new BigInteger(1, unb64(f, "Modulus")),
					new BigInteger(1, unb64(f, "PublicExponent")),
					new BigInteger(1, unb64(f, "PrivateExponent")),
					new BigInteger(1, unb64(f, "Prime1")),
					new BigInteger(1, unb64(f, "Prime2")),
					new BigInteger(1, unb64(f, "Exponent1")),
					new BigInteger(1, unb64(f, "Exponent2")),
					new BigInteger(1, unb64(f, "Coefficient")));
			return KeyFactory.getInstance("RSA").generatePrivate(spec);
		}

		@Override
		public byte [] sign(PrivateKey key, byte [] data) {
			try {
				Signature s = Signature.getInstance(sigAlg);
				s.initSign(key);
				s.update(data);
				return s.sign();
			} catch(GeneralSecurityException ex) {
				throw new IllegalStateException(ex);
			}
		}

		@Override
		public boolean verify(byte [] field, byte [] data, byte [] signature) {
			try {
				PublicKey k = KeyFactory.getInstance("RSA").generatePublic(publicSpec(field));
				Signature s = Signature.getInstance(sigAlg);
				s.initVerify(k);
				s.update(data);
				return s.verify(signature);
			} catch(GeneralSecurityException | RuntimeException ex) {
				return false;
			}
		}
	}

	// ------------------------------------------------------------ ECDSA (RFC 6605)

	static final class Ecdsa extends Algorithm {
		private final String curve;
		private final String sigAlg;
		private final int size;

		Ecdsa(int n, String m, String curve, String sigAlg, int size) {
			super(n, m);
			this.curve = curve;
			this.sigAlg = sigAlg;
			this.size = size;
		}

		private ECParameterSpec params() throws GeneralSecurityException {
			AlgorithmParameters p = AlgorithmParameters.getInstance("EC");
			p.init(new ECGenParameterSpec(curve));
			return p.getParameterSpec(ECParameterSpec.class);
		}

		@Override
		public KeyPair generate(int bits) throws GeneralSecurityException {
			KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
			g.initialize(new ECGenParameterSpec(curve));
			return g.generateKeyPair();
		}

		@Override
		public byte [] publicKeyField(PublicKey pub) {
			ECPoint w = ((ECPublicKey)pub).getW();
			byte [] ret = new byte[2*size];
			System.arraycopy(unsigned(w.getAffineX(), size), 0, ret, 0, size);
			System.arraycopy(unsigned(w.getAffineY(), size), 0, ret, size, size);
			return ret;
		}

		@Override
		public Map<String, String> privateFields(KeyPair pair) {
			Map<String, String> f = new LinkedHashMap<String, String>();
			f.put("PrivateKey", b64(unsigned(((ECPrivateKey)pair.getPrivate()).getS(), size)));
			return f;
		}

		@Override
		public PrivateKey privateKey(Map<String, String> f, byte [] pub) throws GeneralSecurityException {
			return KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(new BigInteger(1, unb64(f, "PrivateKey")), params()));
		}

		@Override
		public byte [] sign(PrivateKey key, byte [] data) {
			try {
				Signature s = Signature.getInstance(sigAlg);
				s.initSign(key);
				s.update(data);
				return derToRaw(s.sign(), size);
			} catch(GeneralSecurityException ex) {
				throw new IllegalStateException(ex);
			}
		}

		@Override
		public boolean verify(byte [] field, byte [] data, byte [] signature) {
			try {
				if( field.length != 2*size || signature.length != 2*size ) {
					return false;
				}
				ECPoint w = new ECPoint(new BigInteger(1, Arrays.copyOfRange(field, 0, size)), new BigInteger(1, Arrays.copyOfRange(field, size, 2*size)));
				PublicKey k = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(w, params()));
				Signature s = Signature.getInstance(sigAlg);
				s.initVerify(k);
				s.update(data);
				return s.verify(rawToDer(signature, size));
			} catch(GeneralSecurityException | RuntimeException ex) {
				return false;
			}
		}

		/** ASN.1 SEQUENCE { INTEGER r, INTEGER s } to r|s, each size bytes (RFC 6605 4). */
		static byte [] derToRaw(byte [] der, int size) {
			int pos = 2;
			if( (der[1]&0xff) > 0x80 ) {
				pos += (der[1]&0x7f);
			}
			byte [] ret = new byte[2*size];
			for(int part=0; part < 2; part++ ) {
				if( der[pos] != 0x02 ) {
					throw new IllegalStateException("bad ECDSA signature encoding");
				}
				int len = der[pos+1]&0xff;
				pos += 2;
				BigInteger v = new BigInteger(1, Arrays.copyOfRange(der, pos, pos+len));
				System.arraycopy(unsigned(v, size), 0, ret, part*size, size);
				pos += len;
			}
			return ret;
		}

		static byte [] rawToDer(byte [] raw, int size) {
			byte [] r = new BigInteger(1, Arrays.copyOfRange(raw, 0, size)).toByteArray();
			byte [] s = new BigInteger(1, Arrays.copyOfRange(raw, size, 2*size)).toByteArray();
			int len = 2+r.length+2+s.length;
			java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
			out.write(0x30);
			if( len > 127 ) {
				out.write(0x81);
			}
			out.write(len);
			out.write(0x02);
			out.write(r.length);
			out.write(r, 0, r.length);
			out.write(0x02);
			out.write(s.length);
			out.write(s, 0, s.length);
			return out.toByteArray();
		}
	}

	// ------------------------------------------------------------ Ed25519 (RFC 8080)

	static final class Ed25519 extends Algorithm {
		//  DER prefixes of the PKCS#8 private key and X.509 public key encodings
		private static final byte [] PKCS8_PREFIX = hex("302e020100300506032b657004220420");
		private static final byte [] X509_PREFIX = hex("302a300506032b6570032100");

		Ed25519() {
			super(ED25519, "ED25519");
		}

		private static byte [] hex(String h) {
			byte [] b = new byte[h.length()/2];
			for(int i=0; i < b.length; i++ ) {
				b[i] = (byte)Integer.parseInt(h.substring(2*i, 2*i+2), 16);
			}
			return b;
		}

		private static byte [] concat(byte [] a, byte [] b) {
			byte [] r = Arrays.copyOf(a, a.length+b.length);
			System.arraycopy(b, 0, r, a.length, b.length);
			return r;
		}

		private static KeyFactory factory() throws GeneralSecurityException {
			try {
				return KeyFactory.getInstance("Ed25519");
			} catch(GeneralSecurityException ex) {
				throw new GeneralSecurityException("ED25519 needs Java 15 or later", ex);
			}
		}

		@Override
		public KeyPair generate(int bits) throws GeneralSecurityException {
			factory();
			return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
		}

		@Override
		public byte [] publicKeyField(PublicKey pub) {
			byte [] enc = pub.getEncoded();
			return Arrays.copyOfRange(enc, enc.length-32, enc.length);
		}

		@Override
		public Map<String, String> privateFields(KeyPair pair) {
			byte [] enc = pair.getPrivate().getEncoded();
			Map<String, String> f = new LinkedHashMap<String, String>();
			//  The 32 byte seed follows the fixed prefix
			f.put("PrivateKey", b64(Arrays.copyOfRange(enc, PKCS8_PREFIX.length, PKCS8_PREFIX.length+32)));
			return f;
		}

		@Override
		public PrivateKey privateKey(Map<String, String> f, byte [] pub) throws GeneralSecurityException {
			return factory().generatePrivate(new PKCS8EncodedKeySpec(concat(PKCS8_PREFIX, unb64(f, "PrivateKey"))));
		}

		@Override
		public byte [] sign(PrivateKey key, byte [] data) {
			try {
				Signature s = Signature.getInstance("Ed25519");
				s.initSign(key);
				s.update(data);
				return s.sign();
			} catch(GeneralSecurityException ex) {
				throw new IllegalStateException(ex);
			}
		}

		@Override
		public boolean verify(byte [] field, byte [] data, byte [] signature) {
			try {
				PublicKey k = factory().generatePublic(new X509EncodedKeySpec(concat(X509_PREFIX, field)));
				Signature s = Signature.getInstance("Ed25519");
				s.initVerify(k);
				s.update(data);
				return s.verify(signature);
			} catch(GeneralSecurityException | RuntimeException ex) {
				return false;
			}
		}
	}
}
