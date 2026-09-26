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
package us.bringardner.net.dns;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * TSIG, secret key transaction authentication (RFC 8945): keys, finding and
 * checking the TSIG record of a message, and signing messages. A
 * {@link Session} holds the state of one signed exchange (a request and its
 * response, or all the messages of a zone transfer).
 * <p>
 * Works on the wire bytes of messages, since the MAC covers exactly the bytes
 * that were sent.
 */
public final class Tsig {

	public static final int TYPE = 250;
	public static final int CLASS_ANY = 255;

	/** RCODE of a response to a request that failed TSIG checks. */
	public static final int NOTAUTH = 9;
	//  TSIG error codes (in the TSIG record)
	public static final int NOERROR = 0;
	public static final int BADSIG = 16;
	public static final int BADKEY = 17;
	public static final int BADTIME = 18;
	public static final int BADTRUNC = 22;

	/** Default time window (seconds) either side of our clock. */
	public static final int DEFAULT_FUDGE = 300;

	//  TSIG algorithm name -> Java MAC algorithm
	private static final Map<String, String> ALGORITHMS = new LinkedHashMap<String, String>();
	static {
		ALGORITHMS.put("hmac-md5.sig-alg.reg.int", "HmacMD5");
		ALGORITHMS.put("hmac-sha1", "HmacSHA1");
		ALGORITHMS.put("hmac-sha224", "HmacSHA224");
		ALGORITHMS.put("hmac-sha256", "HmacSHA256");
		ALGORITHMS.put("hmac-sha384", "HmacSHA384");
		ALGORITHMS.put("hmac-sha512", "HmacSHA512");
	}

	private Tsig() {
	}

	// ------------------------------------------------------------ keys

	/** A shared secret key. */
	public static final class Key {
		private final String name;
		private final String algorithm;
		private final String macAlgorithm;
		private final byte [] secret;

		/**
		 * @param name key name (a domain name, e.g. "transfer.example.")
		 * @param algorithm hmac-sha256 (recommended), hmac-sha512, hmac-sha384, hmac-sha224, hmac-sha1 or hmac-md5
		 * @param secret the secret (at least 16 bytes is recommended)
		 */
		public Key(String name, String algorithm, byte [] secret) {
			this.name = canonical(name);
			if( this.name.isEmpty() ) {
				throw new IllegalArgumentException("TSIG key needs a name");
			}
			String alg = canonical(algorithm);
			if( alg.equals("hmac-md5") ) {
				alg = "hmac-md5.sig-alg.reg.int";
			}
			this.macAlgorithm = ALGORITHMS.get(alg);
			if( macAlgorithm == null ) {
				throw new IllegalArgumentException("Unsupported TSIG algorithm '"+algorithm+"'");
			}
			this.algorithm = alg;
			if( secret == null || secret.length == 0 ) {
				throw new IllegalArgumentException("TSIG key "+name+" has no secret");
			}
			this.secret = secret.clone();
		}

		public String getName() { return name; }
		public String getAlgorithm() { return algorithm; }

		/** Full MAC length in bytes. */
		public int macLength() {
			return mac().getMacLength();
		}

		Mac mac() {
			try {
				Mac m = Mac.getInstance(macAlgorithm);
				m.init(new SecretKeySpec(secret, macAlgorithm));
				return m;
			} catch(GeneralSecurityException e) {
				throw new IllegalStateException("TSIG "+algorithm+" not available", e);
			}
		}

		@Override
		public String toString() {
			return name+" ("+algorithm+")";
		}
	}

	/** The keys this server knows, by name. */
	public static final class KeyRing {
		public static final KeyRing EMPTY = new KeyRing(Collections.<String, Key>emptyMap());
		private final Map<String, Key> keys;

		private KeyRing(Map<String, Key> keys) {
			this.keys = keys;
		}

		/**
		 * Keys from a property value: "name:algorithm:base64secret" entries
		 * separated by commas or white space, e.g.
		 * "xfr.example:hmac-sha256:aGVsbG8gd29ybGQgMTIzNDU2Nzg5MA==".
		 */
		public static KeyRing parse(String spec) {
			Map<String, Key> ret = new HashMap<String, Key>();
			if( spec != null ) {
				for(String item : spec.trim().split("[,\\s]+")) {
					if( item.isEmpty() ) {
						continue;
					}
					String [] p = item.split(":", 3);
					if( p.length != 3 ) {
						throw new IllegalArgumentException("TSIG key must be name:algorithm:secret");
					}
					add(ret, p[0], p[1], p[2]);
				}
			}
			return new KeyRing(Collections.unmodifiableMap(ret));
		}

		/**
		 * Keys from a file: one "name algorithm base64secret" per line,
		 * '#' starts a comment. Keeps the secrets out of the properties file.
		 */
		public static KeyRing load(File file) throws IOException {
			Map<String, Key> ret = new HashMap<String, Key>();
			try(BufferedReader in = new BufferedReader(new FileReader(file))) {
				String line;
				int n = 0;
				while( (line = in.readLine()) != null ) {
					n++;
					int hash = line.indexOf('#');
					if( hash >= 0 ) {
						line = line.substring(0, hash);
					}
					line = line.trim();
					if( line.isEmpty() ) {
						continue;
					}
					String [] p = line.split("\\s+");
					if( p.length != 3 ) {
						throw new IOException(file+" line "+n+": expected 'name algorithm secret'");
					}
					try {
						add(ret, p[0], p[1], p[2]);
					} catch(IllegalArgumentException e) {
						throw new IOException(file+" line "+n+": "+e.getMessage());
					}
				}
			}
			return new KeyRing(Collections.unmodifiableMap(ret));
		}

		/** Both sets of keys (a key in other wins). */
		public KeyRing with(KeyRing other) {
			Map<String, Key> ret = new HashMap<String, Key>(keys);
			ret.putAll(other.keys);
			return new KeyRing(Collections.unmodifiableMap(ret));
		}

		private static void add(Map<String, Key> ret, String name, String alg, String secret) {
			byte [] s;
			try {
				s = Base64.getDecoder().decode(secret);
			} catch(IllegalArgumentException e) {
				throw new IllegalArgumentException("TSIG key "+name+": the secret must be base64");
			}
			Key k = new Key(name, alg, s);
			if( ret.put(k.getName(), k) != null ) {
				throw new IllegalArgumentException("TSIG key "+name+" defined twice");
			}
		}

		public Key get(String name) {
			return name == null ? null : keys.get(canonical(name));
		}

		public boolean isEmpty() {
			return keys.isEmpty();
		}

		public int size() {
			return keys.size();
		}
	}

	/** Lower case, without the trailing dot. */
	static String canonical(String name) {
		String n = name == null ? "" : name.trim().toLowerCase(Locale.ROOT);
		return n.endsWith(".") ? n.substring(0, n.length()-1) : n;
	}

	// ------------------------------------------------------------ the TSIG record

	/** A TSIG record read from the end of a message. */
	public static final class Record {
		/** Where the record starts in the message. */
		public final int start;
		public final String keyName;
		public final String algorithm;
		public final long timeSigned;
		public final int fudge;
		public final byte [] mac;
		public final int originalId;
		public final int error;
		public final byte [] other;

		Record(int start, String keyName, String algorithm, long timeSigned, int fudge, byte [] mac, int originalId, int error, byte [] other) {
			this.start = start;
			this.keyName = keyName;
			this.algorithm = algorithm;
			this.timeSigned = timeSigned;
			this.fudge = fudge;
			this.mac = mac;
			this.originalId = originalId;
			this.error = error;
			this.other = other;
		}
	}

	private static int u16(byte [] b, int p) {
		if( p+2 > b.length ) {
			throw new DnsFormatException("Message ends inside a record");
		}
		return ((b[p]&0xff) << 8) | (b[p+1]&0xff);
	}

	/** Read a (possibly compressed) name at pos[0]; pos[0] ends after it. */
	private static String readName(byte [] b, int [] pos) {
		StringBuilder ret = new StringBuilder();
		int p = pos[0];
		int end = -1;
		int jumps = 0;
		while( true ) {
			if( p >= b.length ) {
				throw new DnsFormatException("Name runs past the end of the message");
			}
			int len = b[p]&0xff;
			if( (len & 0xc0) == 0xc0 ) {
				if( ++jumps > 64 ) {
					throw new DnsFormatException("Compression loop");
				}
				if( end < 0 ) {
					end = p+2;
				}
				p = u16(b, p) & 0x3fff;
				continue;
			}
			if( (len & 0xc0) != 0 ) {
				throw new DnsFormatException("Invalid label");
			}
			p++;
			if( len == 0 ) {
				break;
			}
			if( p+len > b.length ) {
				throw new DnsFormatException("Label runs past the end of the message");
			}
			if( ret.length() > 0 ) {
				ret.append('.');
			}
			ret.append(new String(b, p, len, java.nio.charset.StandardCharsets.ISO_8859_1));
			p += len;
		}
		pos[0] = end >= 0 ? end : p;
		return ret.toString().toLowerCase(Locale.ROOT);
	}

	/**
	 * Find the TSIG record of a message.
	 * @return null if the message has none
	 * @throws DnsFormatException if the message is malformed, or has a TSIG
	 *   record that is not the last record (RFC 8945 5.1)
	 */
	public static Record find(byte [] msg) {
		if( msg == null || msg.length < 12 ) {
			return null;
		}
		int qd = u16(msg, 4);
		int total = u16(msg, 6) + u16(msg, 8) + u16(msg, 10);
		int [] pos = {12};
		for(int i=0; i < qd; i++ ) {
			readName(msg, pos);
			pos[0] += 4;
		}
		Record ret = null;
		for(int i=0; i < total; i++ ) {
			int start = pos[0];
			String owner = readName(msg, pos);
			int type = u16(msg, pos[0]);
			int rdlen = u16(msg, pos[0]+8);
			int rdata = pos[0]+10;
			if( rdata+rdlen > msg.length ) {
				throw new DnsFormatException("Record runs past the end of the message");
			}
			if( type == TYPE ) {
				if( i != total-1 || i < total - u16(msg, 10) ) {
					throw new DnsFormatException("TSIG must be the last record of the additional section");
				}
				int [] p = {rdata};
				String alg = readName(msg, p);
				int q = p[0];
				long time = ((long)u16(msg, q) << 32) | ((long)u16(msg, q+2) << 16) | u16(msg, q+4);
				int fudge = u16(msg, q+6);
				int macLen = u16(msg, q+8);
				q += 10;
				if( q+macLen+6 > rdata+rdlen ) {
					throw new DnsFormatException("Invalid TSIG record");
				}
				byte [] mac = java.util.Arrays.copyOfRange(msg, q, q+macLen);
				q += macLen;
				int orig = u16(msg, q);
				int error = u16(msg, q+2);
				int otherLen = u16(msg, q+4);
				q += 6;
				if( q+otherLen != rdata+rdlen ) {
					throw new DnsFormatException("Invalid TSIG record");
				}
				byte [] other = java.util.Arrays.copyOfRange(msg, q, q+otherLen);
				ret = new Record(start, owner, alg, time, fudge, mac, orig, error, other);
			}
			pos[0] = rdata+rdlen;
		}
		return ret;
	}

	/** The message as it was before the TSIG was added: no TSIG record, ARCOUNT one less, the original ID. */
	static byte [] strip(byte [] msg, Record r) {
		byte [] ret = java.util.Arrays.copyOf(msg, r.start);
		int ar = u16(ret, 10) - 1;
		ret[10] = (byte)(ar >> 8);
		ret[11] = (byte)ar;
		ret[0] = (byte)(r.originalId >> 8);
		ret[1] = (byte)r.originalId;
		return ret;
	}

	private static void name(ByteArrayOutputStream out, String name) {
		for(String label : canonical(name).split("[.]")) {
			if( !label.isEmpty() ) {
				byte [] b = label.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
				out.write(b.length);
				out.write(b, 0, b.length);
			}
		}
		out.write(0);
	}

	private static void u16(ByteArrayOutputStream out, int v) {
		out.write(v >> 8);
		out.write(v);
	}

	private static void time(ByteArrayOutputStream out, long t) {
		u16(out, (int)(t >> 32) & 0xffff);
		u16(out, (int)(t >> 16) & 0xffff);
		u16(out, (int)t & 0xffff);
	}

	/** The TSIG variables of RFC 8945 4.3.3 (or only the timers, for later messages of a transfer). */
	private static byte [] variables(String keyName, String alg, long time, int fudge, int error, byte [] other, boolean timersOnly) {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		if( !timersOnly ) {
			name(out, keyName);
			u16(out, CLASS_ANY);
			u16(out, 0);
			u16(out, 0);		//  TTL 0
			name(out, alg);
		}
		time(out, time);
		u16(out, fudge);
		if( !timersOnly ) {
			u16(out, error);
			u16(out, other.length);
			out.write(other, 0, other.length);
		}
		return out.toByteArray();
	}

	private static byte [] withLength(byte [] mac) {
		byte [] ret = new byte[mac.length+2];
		ret[0] = (byte)(mac.length >> 8);
		ret[1] = (byte)mac.length;
		System.arraycopy(mac, 0, ret, 2, mac.length);
		return ret;
	}

	/** Append a TSIG record (and count it in ARCOUNT). */
	static byte [] append(byte [] msg, String keyName, String alg, long time, int fudge, byte [] mac, int originalId, int error, byte [] other) {
		ByteArrayOutputStream rd = new ByteArrayOutputStream();
		name(rd, alg);
		time(rd, time);
		u16(rd, fudge);
		u16(rd, mac.length);
		rd.write(mac, 0, mac.length);
		u16(rd, originalId);
		u16(rd, error);
		u16(rd, other.length);
		rd.write(other, 0, other.length);
		byte [] rdata = rd.toByteArray();

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		out.write(msg, 0, msg.length);
		name(out, keyName);
		u16(out, TYPE);
		u16(out, CLASS_ANY);
		u16(out, 0);
		u16(out, 0);
		u16(out, rdata.length);
		out.write(rdata, 0, rdata.length);
		byte [] ret = out.toByteArray();
		int ar = u16(ret, 10) + 1;
		ret[10] = (byte)(ar >> 8);
		ret[11] = (byte)ar;
		return ret;
	}

	/** Bytes a TSIG record adds to a message. */
	static int recordSize(String keyName, String alg, int macLen, int otherLen) {
		return (canonical(keyName).length()+2) + 10 + (canonical(alg).length()+2) + 10 + macLen + 6 + otherLen;
	}

	private static long now() {
		return System.currentTimeMillis()/1000;
	}

	/** A TSIG check that failed; error is BADSIG, BADKEY, BADTIME or BADTRUNC. */
	public static final class TsigException extends Exception {
		private static final long serialVersionUID = 1L;
		public final int error;

		TsigException(int error, String message) {
			super(message);
			this.error = error;
		}
	}

	// ------------------------------------------------------------ an exchange

	/**
	 * One signed exchange: a request and its response(s). The server starts
	 * one with {@link #verifyRequest}, a client with {@link #client}.
	 * Responses are signed / checked in order; for a zone transfer each
	 * message after the first is covered by the MAC of the one before
	 * (RFC 8945 5.3.1).
	 */
	public static final class Session {
		private final Key key;
		private final String keyName;
		private final String algorithm;
		private final int fudge;
		private byte [] priorMac;		//  the request's MAC, then each response's
		private boolean first = true;
		private final int error;		//  server: the error to report (0 = none)
		private final long requestTime;
		private boolean signed;

		private Session(Key key, String keyName, String algorithm, int fudge, byte [] priorMac, int error, long requestTime) {
			this.key = key;
			this.keyName = keyName;
			this.algorithm = algorithm;
			this.fudge = fudge;
			this.priorMac = priorMac;
			this.error = error;
			this.requestTime = requestTime;
		}

		/** The key, or null when the request named a key we don't have. */
		public Key getKey() { return key; }

		/** The TSIG error this session reports (0 when the request was good). */
		public int getError() { return error; }

		// -------------------------------------------------------- server

		/**
		 * Check the TSIG of a request (RFC 8945 5.2).
		 * @return null if the request has no TSIG; otherwise a session, whose
		 *   getError() is 0 when the request is good, or the error to report
		 *   in the response (the request must then not be processed)
		 * @throws DnsFormatException for a malformed TSIG (answer FORMERR)
		 */
		public static Session verifyRequest(KeyRing keys, byte [] msg) {
			return verifyRequest(keys, msg, now());
		}

		static Session verifyRequest(KeyRing keys, byte [] msg, long now) {
			Record r = find(msg);
			if( r == null ) {
				return null;
			}
			Key key = keys.get(r.keyName);
			if( key == null || !key.getAlgorithm().equals(r.algorithm) ) {
				return new Session(null, r.keyName, r.algorithm, r.fudge, new byte[0], BADKEY, r.timeSigned);
			}
			int full = key.macLength();
			if( r.mac.length > full || r.mac.length < Math.max(10, full/2) ) {
				return new Session(null, r.keyName, r.algorithm, r.fudge, new byte[0],
						r.mac.length > full ? BADSIG : BADTRUNC, r.timeSigned);
			}
			Mac mac = key.mac();
			mac.update(strip(msg, r));
			mac.update(variables(r.keyName, r.algorithm, r.timeSigned, r.fudge, r.error, r.other, false));
			byte [] expect = java.util.Arrays.copyOf(mac.doFinal(), r.mac.length);
			if( !MessageDigest.isEqual(expect, r.mac) ) {
				return new Session(null, r.keyName, r.algorithm, r.fudge, new byte[0], BADSIG, r.timeSigned);
			}
			if( Math.abs(now - r.timeSigned) > r.fudge ) {
				//  Signed with a good key, but our clocks disagree: the response is signed
				return new Session(key, r.keyName, r.algorithm, r.fudge, r.mac, BADTIME, r.timeSigned);
			}
			return new Session(key, r.keyName, r.algorithm, r.fudge, r.mac, NOERROR, r.timeSigned);
		}

		/** Room to leave for the TSIG record when a response has a size limit. */
		public int reserve() {
			int macLen = error == BADKEY || error == BADSIG || error == BADTRUNC || key == null ? 0 : key.macLength();
			return recordSize(keyName, algorithm, macLen, 6);
		}

		/**
		 * Sign a response (the next one of the exchange). For BADKEY / BADSIG /
		 * BADTRUNC the TSIG has no MAC (we can't sign it); for BADTIME it is
		 * signed and carries our time.
		 */
		public byte [] signResponse(byte [] msg) {
			int id = u16(msg, 0);
			if( error == BADKEY || error == BADSIG || error == BADTRUNC ) {
				return append(msg, keyName, algorithm, requestTime, fudge, new byte[0], id, error, new byte[0]);
			}
			long time = error == BADTIME ? requestTime : now();
			byte [] other = new byte[0];
			if( error == BADTIME ) {
				ByteArrayOutputStream o = new ByteArrayOutputStream();
				time(o, now());
				other = o.toByteArray();
			}
			Mac mac = key.mac();
			mac.update(withLength(priorMac));
			mac.update(msg);
			mac.update(variables(keyName, algorithm, time, fudge, error, other, !first));
			byte [] m = mac.doFinal();
			first = false;
			priorMac = m;
			return append(msg, keyName, algorithm, time, fudge, m, id, error, other);
		}

		// -------------------------------------------------------- client

		/** A client session with a key. */
		public static Session client(Key key) {
			return new Session(key, key.getName(), key.getAlgorithm(), DEFAULT_FUDGE, null, NOERROR, 0);
		}

		/** Sign a request. */
		public byte [] signRequest(byte [] msg) {
			long time = now();
			Mac mac = key.mac();
			mac.update(msg);
			mac.update(variables(keyName, algorithm, time, fudge, NOERROR, new byte[0], false));
			byte [] m = mac.doFinal();
			priorMac = m;
			first = true;
			signed = true;
			return append(msg, keyName, algorithm, time, fudge, m, u16(msg, 0), NOERROR, new byte[0]);
		}

		/**
		 * Check a response (the next one of the exchange).
		 * @throws TsigException if it is not signed, or not correctly signed, by our key
		 */
		public void verifyResponse(byte [] msg) throws TsigException {
			if( !signed ) {
				throw new IllegalStateException("signRequest first");
			}
			Record r = find(msg);
			if( r == null ) {
				throw new TsigException(BADSIG, "the response is not signed");
			}
			if( !r.keyName.equals(keyName) || !r.algorithm.equals(algorithm) ) {
				throw new TsigException(BADKEY, "the response is signed with another key");
			}
			if( r.error != NOERROR && r.mac.length == 0 ) {
				throw new TsigException(r.error, "the server reported TSIG error "+r.error);
			}
			Mac mac = key.mac();
			mac.update(withLength(priorMac));
			mac.update(strip(msg, r));
			mac.update(variables(r.keyName, r.algorithm, r.timeSigned, r.fudge, r.error, r.other, !first));
			byte [] expect = java.util.Arrays.copyOf(mac.doFinal(), r.mac.length);
			if( r.mac.length < Math.max(10, key.macLength()/2) || !MessageDigest.isEqual(expect, r.mac) ) {
				throw new TsigException(BADSIG, "bad response MAC");
			}
			if( r.error != NOERROR ) {
				throw new TsigException(r.error, "the server reported TSIG error "+r.error);
			}
			if( Math.abs(now() - r.timeSigned) > r.fudge ) {
				throw new TsigException(BADTIME, "response time outside the fudge window");
			}
			first = false;
			priorMac = r.mac;
		}
	}
}
