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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Dnskey;
import us.bringardner.net.dns.Ds;

/**
 * A zone's DNSSEC key: the public DNSKEY and (for a key that signs) the
 * private key, stored as a pair of BIND style files, K&lt;zone&gt;.+&lt;alg&gt;+&lt;tag&gt;.key
 * and .private, so keys made with dnssec-keygen work here and the other way
 * round.
 * <p>
 * The BIND timing fields in the private file are honoured: a key is
 * published (in the DNSKEY set) from Publish until Delete, and signs from
 * Activate until Inactive. A missing field means "always". A .key file
 * without its .private is published but never signs (for a key rollover).
 */
public final class DnssecKey {

	private final String zone;
	private final Dnskey dnskey;
	private final Algorithm algorithm;
	private final PrivateKey privateKey;
	private final File keyFile;
	private final Map<String, Long> times;

	private DnssecKey(String zone, Dnskey dnskey, PrivateKey privateKey, File keyFile, Map<String, Long> times) {
		this.zone = Canonical.key(zone);
		this.dnskey = dnskey;
		this.algorithm = Algorithm.of(dnskey.getAlgorithm());
		this.privateKey = privateKey;
		this.keyFile = keyFile;
		this.times = times;
	}

	/** The zone (lower case, no trailing dot). */
	public String getZone() {
		return zone;
	}

	/** The DNSKEY record (a copy). */
	public Dnskey getDnskey() {
		return (Dnskey)dnskey.copy();
	}

	public int getAlgorithm() {
		return algorithm.getNumber();
	}

	public int getKeyTag() {
		return dnskey.getKeyTag();
	}

	/** A key signing key (flags 257): signs the DNSKEY set, and the parent's DS points at it. */
	public boolean isKsk() {
		return dnskey.isKsk();
	}

	public boolean hasPrivateKey() {
		return privateKey != null;
	}

	/** The .key file this key was read from (null if it was never saved). */
	public File getKeyFile() {
		return keyFile;
	}

	/** A BIND timing field (Publish, Activate, Inactive, Delete) in seconds since 1970, or null. */
	public Long getTime(String name) {
		return times.get(name);
	}

	/** In the DNSKEY set at this time (seconds since 1970)? */
	public boolean isPublished(long now) {
		Long p = times.get("Publish");
		Long d = times.get("Delete");
		return (p == null || p <= now) && (d == null || d > now);
	}

	/** Signs at this time? */
	public boolean isActive(long now) {
		Long a = times.get("Activate");
		Long i = times.get("Inactive");
		return privateKey != null && isPublished(now) && (a == null || a <= now) && (i == null || i > now);
	}

	/** The first timing event after now, or Long.MAX_VALUE. */
	public long nextEvent(long now) {
		long ret = Long.MAX_VALUE;
		for(Long t : times.values()) {
			if( t != null && t > now ) {
				ret = Math.min(ret, t);
			}
		}
		return ret;
	}

	/** Sign data with the private key (DNSSEC signature format). */
	public byte [] sign(byte [] data) {
		if( privateKey == null ) {
			throw new IllegalStateException("key "+getKeyTag()+" of "+zone+" has no private key");
		}
		return algorithm.sign(privateKey, data);
	}

	/**
	 * The DS record for the parent zone (RFC 4034 5.1.4): digest of the owner
	 * name and the DNSKEY rdata.
	 *
	 * @param digestType Ds.SHA256 or Ds.SHA384
	 */
	public Ds toDs(int digestType, int ttl) {
		return ds(zone, dnskey, digestType, ttl);
	}

	/** The DS record for a DNSKEY at owner (RFC 4034 5.1.4). */
	public static Ds ds(String owner, Dnskey dnskey, int digestType, int ttl) {
		String alg = digestType == Ds.SHA256 ? "SHA-256" : digestType == Ds.SHA384 ? "SHA-384" : null;
		if( alg == null ) {
			throw new IllegalArgumentException("DS digest type "+digestType+" is not supported (use 2 or 4)");
		}
		try {
			MessageDigest md = MessageDigest.getInstance(alg);
			md.update(Canonical.nameWire(owner));
			md.update(dnskey.rdataBytes());
			Ds ds = new Ds(Canonical.key(owner), DNS.IN);
			ds.setTTL(ttl);
			ds.setKeyTag(dnskey.getKeyTag());
			ds.setAlgorithm(dnskey.getAlgorithm());
			ds.setDigestType(digestType);
			ds.setDigest(md.digest());
			return ds;
		} catch(GeneralSecurityException ex) {
			throw new IllegalStateException(ex);
		}
	}

	/** Base file name: K&lt;zone&gt;.+&lt;alg&gt;+&lt;tag&gt; (BIND's naming). */
	public String baseName() {
		return String.format("K%s.+%03d+%05d", zone, getAlgorithm(), getKeyTag());
	}

	@Override
	public String toString() {
		return zone+" "+(isKsk() ? "KSK" : "ZSK")+" "+algorithm.getMnemonic()+" tag "+getKeyTag()+(privateKey == null ? " (public only)" : "");
	}

	// ------------------------------------------------------------ making keys

	/**
	 * Make a new key.
	 *
	 * @param ksk true for a key signing key (flags 257), false for a zone signing key (256)
	 * @param bits RSA key size (0 for the default, 2048); ignored for the others
	 */
	public static DnssecKey generate(String zone, Algorithm alg, boolean ksk, int bits) throws GeneralSecurityException {
		KeyPair pair = alg.generate(bits);
		Dnskey k = new Dnskey(Canonical.key(zone), DNS.IN);
		k.setFlags(Dnskey.FLAG_ZONE | (ksk ? Dnskey.FLAG_SEP : 0));
		k.setProtocol(3);
		k.setAlgorithm(alg.getNumber());
		k.setKey(alg.publicKeyField(pair.getPublic()));
		k.setTTL(3600);
		Map<String, Long> times = new LinkedHashMap<String, Long>();
		long now = System.currentTimeMillis()/1000;
		times.put("Created", now);
		times.put("Publish", now);
		times.put("Activate", now);
		DnssecKey ret = new DnssecKey(zone, k, pair.getPrivate(), null, times);
		ret.pair = pair;
		return ret;
	}

	//  Only set for a key made by generate(), until it is saved
	private KeyPair pair;

	/**
	 * Write the .key and .private files into dir (the private file readable
	 * by the owner only, where the file system allows it).
	 *
	 * @return the .key file
	 */
	public File save(File dir) throws IOException {
		if( pair == null ) {
			throw new IllegalStateException("only a newly generated key can be saved");
		}
		File key = new File(dir, baseName()+".key");
		File priv = new File(dir, baseName()+".private");
		if( key.exists() || priv.exists() ) {
			throw new IOException(key+" already exists");
		}
		StringBuilder p = new StringBuilder();
		p.append("Private-key-format: v1.3\n");
		p.append("Algorithm: ").append(getAlgorithm()).append(" (").append(algorithm.getMnemonic()).append(")\n");
		for(Map.Entry<String, String> e : algorithm.privateFields(pair).entrySet()) {
			p.append(e.getKey()).append(": ").append(e.getValue()).append('\n');
		}
		for(String t : new String[] {"Created", "Publish", "Activate"}) {
			if( times.get(t) != null ) {
				p.append(t).append(": ").append(timeText(times.get(t))).append('\n');
			}
		}
		Files.write(priv.toPath(), new byte[0]);
		try {
			java.util.Set<java.nio.file.attribute.PosixFilePermission> perms = java.nio.file.attribute.PosixFilePermissions.fromString("rw-------");
			Files.setPosixFilePermissions(priv.toPath(), perms);
		} catch(UnsupportedOperationException ex) {
			//  not a POSIX file system
		}
		try(Writer w = new OutputStreamWriter(new FileOutputStream(priv), StandardCharsets.US_ASCII)) {
			w.write(p.toString());
		}
		StringBuilder k = new StringBuilder();
		k.append("; This is a ").append(isKsk() ? "key-signing" : "zone-signing").append(" key, keyid ")
			.append(getKeyTag()).append(", for ").append(zone).append(".\n");
		for(String t : new String[] {"Created", "Publish", "Activate"}) {
			if( times.get(t) != null ) {
				k.append("; ").append(t).append(": ").append(timeText(times.get(t))).append(" (")
					.append(new Date(times.get(t)*1000)).append(")\n");
			}
		}
		k.append(zone).append(". ").append(dnskey.getTTL()).append(" IN DNSKEY ").append(dnskey.getRdataAsString()).append('\n');
		Files.write(key.toPath(), k.toString().getBytes(StandardCharsets.US_ASCII));
		return key;
	}

	// ------------------------------------------------------------ reading keys

	/**
	 * Read a key from its .key file and, if it exists next to it, the
	 * .private file.
	 */
	public static DnssecKey load(File keyFile) throws IOException {
		Dnskey k = readKeyFile(keyFile);
		String path = keyFile.getPath();
		File priv = new File(path.substring(0, path.length()-".key".length())+".private");
		PrivateKey pk = null;
		Map<String, Long> times = new LinkedHashMap<String, Long>();
		if( priv.isFile() ) {
			Map<String, String> fields = readFields(priv);
			String alg = fields.get("Algorithm");
			if( alg == null || !alg.trim().startsWith(String.valueOf(k.getAlgorithm())) ) {
				throw new IOException(priv.getName()+": algorithm '"+alg+"' does not match the .key file ("+k.getAlgorithm()+")");
			}
			try {
				pk = Algorithm.of(k.getAlgorithm()).privateKey(fields, k.getKey());
			} catch(GeneralSecurityException | RuntimeException ex) {
				throw new IOException(priv.getName()+": "+ex.getMessage(), ex);
			}
			for(String t : new String[] {"Created", "Publish", "Activate", "Inactive", "Delete"}) {
				String v = fields.get(t);
				if( v != null ) {
					times.put(t, parseTime(priv, t, v.trim()));
				}
			}
			//  The private key must belong to the public key
			byte [] probe = "BjlDns key check".getBytes(StandardCharsets.US_ASCII);
			Algorithm a = Algorithm.of(k.getAlgorithm());
			if( !a.verify(k.getKey(), probe, a.sign(pk, probe)) ) {
				throw new IOException(priv.getName()+" does not hold the private key of "+keyFile.getName());
			}
		}
		return new DnssecKey(k.getName(), k, pk, keyFile, times);
	}

	private static Long parseTime(File f, String name, String v) throws IOException {
		try {
			SimpleDateFormat fmt = new SimpleDateFormat("yyyyMMddHHmmss");
			fmt.setTimeZone(TimeZone.getTimeZone("UTC"));
			fmt.setLenient(false);
			return fmt.parse(v.split("\\s+")[0]).getTime()/1000;
		} catch(ParseException ex) {
			throw new IOException(f.getName()+": bad "+name+" time '"+v+"'");
		}
	}

	static String timeText(long secs) {
		SimpleDateFormat fmt = new SimpleDateFormat("yyyyMMddHHmmss");
		fmt.setTimeZone(TimeZone.getTimeZone("UTC"));
		return fmt.format(new Date(secs*1000));
	}

	private static Map<String, String> readFields(File f) throws IOException {
		Map<String, String> ret = new LinkedHashMap<String, String>();
		try(BufferedReader in = new BufferedReader(new InputStreamReader(Files.newInputStream(f.toPath()), StandardCharsets.US_ASCII))) {
			String line;
			while( (line = in.readLine()) != null ) {
				int i = line.indexOf(':');
				if( i > 0 ) {
					ret.put(line.substring(0, i).trim(), line.substring(i+1).trim());
				}
			}
		}
		return ret;
	}

	/** The DNSKEY record in a .key file: owner [ttl] [class] DNSKEY flags protocol algorithm key. */
	static Dnskey readKeyFile(File f) throws IOException {
		StringBuilder text = new StringBuilder();
		try(BufferedReader in = new BufferedReader(new InputStreamReader(Files.newInputStream(f.toPath()), StandardCharsets.US_ASCII))) {
			String line;
			while( (line = in.readLine()) != null ) {
				int c = line.indexOf(';');
				if( c >= 0 ) {
					line = line.substring(0, c);
				}
				text.append(line.replace('(', ' ').replace(')', ' ')).append(' ');
			}
		}
		List<String> t = new ArrayList<String>();
		for(String s : text.toString().trim().split("\\s+")) {
			if( !s.isEmpty() ) {
				t.add(s);
			}
		}
		int i = t.indexOf("DNSKEY");
		if( i < 0 ) {
			for(int j=0; j < t.size(); j++ ) {
				if( t.get(j).equalsIgnoreCase("DNSKEY") ) {
					i = j;
				}
			}
		}
		if( i < 1 || t.size() < i+5 ) {
			throw new IOException(f.getName()+": no DNSKEY record");
		}
		int ttl = 3600;
		for(int j=1; j < i; j++ ) {
			if( t.get(j).matches("\\d+") ) {
				ttl = Integer.parseInt(t.get(j));
			}
		}
		Dnskey k = new Dnskey(Canonical.key(t.get(0)), DNS.IN);
		try {
			k.setFlags(Integer.parseInt(t.get(i+1)));
			k.setProtocol(Integer.parseInt(t.get(i+2)));
			k.setAlgorithm(Integer.parseInt(t.get(i+3)));
			StringBuilder b64 = new StringBuilder();
			for(int j=i+4; j < t.size(); j++ ) {
				b64.append(t.get(j));
			}
			k.setKey(Base64.getDecoder().decode(b64.toString()));
		} catch(IllegalArgumentException ex) {
			throw new IOException(f.getName()+": bad DNSKEY record: "+ex.getMessage());
		}
		if( (k.getFlags() & Dnskey.FLAG_ZONE) == 0 || k.getProtocol() != 3 ) {
			throw new IOException(f.getName()+": not a zone key (flags "+k.getFlags()+", protocol "+k.getProtocol()+")");
		}
		if( !Algorithm.isSupported(k.getAlgorithm()) || !Algorithm.of(k.getAlgorithm()).canSign() ) {
			throw new IOException(f.getName()+": algorithm "+k.getAlgorithm()+" is not supported for signing");
		}
		k.setTTL(ttl);
		return k;
	}

	/**
	 * All the keys in a directory (files K*.key), grouped by zone (lower
	 * case, no trailing dot). A key file that can't be read is reported to
	 * errors and skipped.
	 */
	public static Map<String, List<DnssecKey>> loadDir(File dir, List<String> errors) {
		Map<String, List<DnssecKey>> ret = new LinkedHashMap<String, List<DnssecKey>>();
		File [] list = dir == null ? null : dir.listFiles((d, n) -> n.startsWith("K") && n.endsWith(".key"));
		if( list == null ) {
			return ret;
		}
		java.util.Arrays.sort(list);
		for(File f : list) {
			try {
				DnssecKey k = load(f);
				ret.computeIfAbsent(k.getZone(), z -> new ArrayList<DnssecKey>()).add(k);
			} catch(IOException | RuntimeException ex) {
				errors.add(f.getName()+": "+ex.getMessage());
			}
		}
		return ret;
	}

	/** A stamp that changes when a key file is added, removed or changed. */
	public static long dirStamp(File dir) {
		File [] list = dir == null ? null : dir.listFiles((d, n) -> n.startsWith("K") && (n.endsWith(".key") || n.endsWith(".private")));
		if( list == null ) {
			return 0;
		}
		java.util.Arrays.sort(list);
		long ret = 17;
		for(File f : list) {
			ret = ret*31 + f.getName().hashCode();
			ret = ret*31 + f.lastModified();
			ret = ret*31 + f.length();
		}
		return ret;
	}
}
