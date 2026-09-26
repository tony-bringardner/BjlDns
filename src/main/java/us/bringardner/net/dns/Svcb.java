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

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * The SVCB resource record (RFC 9460): priority, target name and service
 * parameters (SvcParams). {@link Https} is the same record for HTTPS.
 * <p>
 * Priority 0 is AliasMode (the target is an alias, no parameters); any other
 * priority is ServiceMode. A target of "." (the root) means the owner name
 * in ServiceMode. Parameters are kept in wire form, ordered by key.
 */
public class Svcb extends RR {

	//  SvcParamKeys (RFC 9460 14.3.2)
	public static final int KEY_MANDATORY = 0;
	public static final int KEY_ALPN = 1;
	public static final int KEY_NO_DEFAULT_ALPN = 2;
	public static final int KEY_PORT = 3;
	public static final int KEY_IPV4HINT = 4;
	public static final int KEY_ECH = 5;
	public static final int KEY_IPV6HINT = 6;

	private static final String [] KEY_NAMES = {"mandatory","alpn","no-default-alpn","port","ipv4hint","ech","ipv6hint"};

	private int priority;
	private Name target = new Name("");
	private TreeMap<Integer, byte[]> params = new TreeMap<Integer, byte[]>();

	public Svcb() {
		this("", SVCB, IN);
	}

	public Svcb(String name) {
		this(name, SVCB, IN);
	}

	public Svcb(String name, int dnsClass) {
		this(name, SVCB, dnsClass);
	}

	protected Svcb(String name, int type, int dnsClass) {
		super(name, type, dnsClass);
		isBase = false;
		dirty = true;
	}

	/** A record from a generic record read from the wire. */
	public Svcb(RR rr) {
		super(rr);
		//  Again: the field initializers ran after super() had parsed the rdata
		setFromRdata();
		isBase = false;
	}

	@Override
	public RR copy() {
		Svcb ret = new Svcb();
		copyTo(ret);
		return ret;
	}

	protected void copyTo(Svcb ret) {
		super.copy(ret);
		ret.priority = priority;
		ret.target = target;
		ret.params = new TreeMap<Integer, byte[]>(params);
	}

	// ------------------------------------------------------------ fields

	public int getPriority() { return priority; }

	/** @return true for AliasMode (priority 0) */
	public boolean isAliasMode() { return priority == 0; }

	/** @return the target name ("" for the root, i.e. "."). */
	public String getTarget() { return target.toString(); }

	/** @return the parameters in wire form, by key (a copy). */
	public Map<Integer, byte[]> getParams() {
		return new TreeMap<Integer, byte[]>(params);
	}

	/** @return the wire value of a parameter, or null. */
	public byte [] getParam(int key) {
		return params.get(key);
	}

	public void setPriority(int priority) {
		if( priority < 0 || priority > 0xffff ) {
			throw new IllegalArgumentException("priority must be 0-65535: "+priority);
		}
		this.priority = priority;
		dirty = true;
	}

	/** @param target the target name; "" or "." for the root */
	public void setTarget(String target) {
		this.target = new Name(target == null || target.equals(".") ? "" : target);
		dirty = true;
	}

	public void setParam(int key, byte [] value) {
		if( key < 0 || key > 0xffff ) {
			throw new IllegalArgumentException("SvcParamKey must be 0-65535: "+key);
		}
		if( value.length > 0xffff ) {
			throw new IllegalArgumentException("SvcParamValue too long");
		}
		params.put(key, value.clone());
		dirty = true;
	}

	/** @return the ALPN ids (empty if there is no alpn parameter). */
	public List<String> getAlpn() {
		List<String> ret = new ArrayList<String>();
		byte [] v = params.get(KEY_ALPN);
		for(int i=0; v != null && i < v.length; ) {
			int len = v[i++]&0xff;
			ret.add(new String(v, i, Math.min(len, v.length-i), StandardCharsets.ISO_8859_1));
			i += len;
		}
		return ret;
	}

	/** @return the port parameter, or -1. */
	public int getPort() {
		byte [] v = params.get(KEY_PORT);
		return v == null || v.length != 2 ? -1 : ((v[0]&0xff) << 8) | (v[1]&0xff);
	}

	// ------------------------------------------------------------ presentation

	/** The presentation name of a key (keyNNNNN for keys without a name). */
	public static String keyName(int key) {
		return key < KEY_NAMES.length ? KEY_NAMES[key] : "key"+key;
	}

	/** The key number of a presentation name (mandatory, alpn, ..., keyNNNNN). */
	public static int keyOf(String name) {
		String n = name.toLowerCase(java.util.Locale.ROOT);
		for(int i=0; i < KEY_NAMES.length; i++ ) {
			if( KEY_NAMES[i].equals(n) ) {
				return i;
			}
		}
		if( n.matches("key[0-9]{1,5}") ) {
			int k = Integer.parseInt(n.substring(3));
			if( k <= 0xffff ) {
				return k;
			}
		}
		throw new IllegalArgumentException("Unknown SvcParamKey '"+name+"'");
	}

	/**
	 * Set the parameters from their presentation form (as in a zone file),
	 * e.g. "alpn=h2,h3", "port=8443", "ipv4hint=192.0.2.1", "no-default-alpn",
	 * and check them (RFC 9460 section 8).
	 */
	public void setParams(List<String> presentation) {
		TreeMap<Integer, byte[]> p = new TreeMap<Integer, byte[]>();
		for(String item : presentation) {
			int eq = item.indexOf('=');
			String k = eq < 0 ? item : item.substring(0, eq);
			String v = eq < 0 ? null : item.substring(eq+1);
			int key = keyOf(k);
			if( p.containsKey(key) ) {
				throw new IllegalArgumentException("SvcParamKey "+keyName(key)+" given twice");
			}
			p.put(key, parseValue(key, v));
		}
		params = p;
		dirty = true;
		validate();
	}

	private static byte [] parseValue(int key, String v) {
		switch(key) {
		case KEY_NO_DEFAULT_ALPN:
			if( v != null && !v.isEmpty() ) {
				throw new IllegalArgumentException("no-default-alpn takes no value");
			}
			return new byte[0];
		case KEY_MANDATORY: {
			List<Integer> keys = new ArrayList<Integer>();
			for(String s : list(need(key, v))) {
				int k = keyOf(s);
				if( keys.contains(k) ) {
					throw new IllegalArgumentException("mandatory lists "+s+" twice");
				}
				keys.add(k);
			}
			java.util.Collections.sort(keys);
			byte [] ret = new byte[keys.size()*2];
			for(int i=0; i < keys.size(); i++ ) {
				ret[i*2] = (byte)(keys.get(i) >> 8);
				ret[i*2+1] = (byte)(int)keys.get(i);
			}
			return ret;
		}
		case KEY_ALPN: {
			java.io.ByteArrayOutputStream b = new java.io.ByteArrayOutputStream();
			for(String id : list(need(key, v))) {
				byte [] x = id.getBytes(StandardCharsets.ISO_8859_1);
				if( x.length == 0 || x.length > 255 ) {
					throw new IllegalArgumentException("Invalid alpn id '"+id+"'");
				}
				b.write(x.length);
				b.write(x, 0, x.length);
			}
			return b.toByteArray();
		}
		case KEY_PORT: {
			String s = need(key, v);
			if( !s.matches("[0-9]{1,5}") || Integer.parseInt(s) > 0xffff ) {
				throw new IllegalArgumentException("Invalid port '"+s+"'");
			}
			int port = Integer.parseInt(s);
			return new byte[] {(byte)(port >> 8), (byte)port};
		}
		case KEY_IPV4HINT: {
			List<String> addrs = list(need(key, v));
			byte [] ret = new byte[addrs.size()*4];
			for(int i=0; i < addrs.size(); i++ ) {
				A a = new A("");
				a.setAddress(addrs.get(i));
				System.arraycopy(a.getAddress(), 0, ret, i*4, 4);
			}
			return ret;
		}
		case KEY_IPV6HINT: {
			List<String> addrs = list(need(key, v));
			byte [] ret = new byte[addrs.size()*16];
			for(int i=0; i < addrs.size(); i++ ) {
				AAAA a = new AAAA("");
				a.setAddress(addrs.get(i));
				System.arraycopy(a.getAddress(), 0, ret, i*16, 16);
			}
			return ret;
		}
		case KEY_ECH:
			try {
				return Base64.getDecoder().decode(need(key, v));
			} catch(IllegalArgumentException e) {
				throw new IllegalArgumentException("ech must be base64: "+e.getMessage());
			}
		default:
			//  Unknown keys: the value as characters, with \DDD for other bytes
			return v == null ? new byte[0] : unescape(v);
		}
	}

	private static String need(int key, String v) {
		if( v == null || v.isEmpty() ) {
			throw new IllegalArgumentException(keyName(key)+" needs a value");
		}
		return v;
	}

	/** Split a comma separated list; "\," is a comma inside an item. */
	private static List<String> list(String v) {
		List<String> ret = new ArrayList<String>();
		StringBuilder b = new StringBuilder();
		for(int i=0; i < v.length(); i++ ) {
			char c = v.charAt(i);
			if( c == '\\' && i+1 < v.length() ) {
				b.append(v.charAt(++i));
			} else if( c == ',' ) {
				ret.add(b.toString());
				b.setLength(0);
			} else {
				b.append(c);
			}
		}
		ret.add(b.toString());
		for(String s : ret) {
			if( s.isEmpty() ) {
				throw new IllegalArgumentException("Empty item in '"+v+"'");
			}
		}
		return ret;
	}

	private static byte [] unescape(String v) {
		java.io.ByteArrayOutputStream b = new java.io.ByteArrayOutputStream();
		for(int i=0; i < v.length(); i++ ) {
			char c = v.charAt(i);
			if( c == '\\' && i+3 < v.length() && Character.isDigit(v.charAt(i+1)) && Character.isDigit(v.charAt(i+2)) && Character.isDigit(v.charAt(i+3)) ) {
				b.write(Integer.parseInt(v.substring(i+1, i+4)));
				i += 3;
			} else if( c == '\\' && i+1 < v.length() ) {
				b.write(v.charAt(++i));
			} else {
				b.write(c);
			}
		}
		return b.toByteArray();
	}

	/**
	 * Check the parameters (RFC 9460 sections 2.4.1, 7 and 8).
	 * @throws IllegalArgumentException if they are not valid
	 */
	public void validate() {
		if( priority == 0 && !params.isEmpty() ) {
			throw new IllegalArgumentException("AliasMode (priority 0) can't have SvcParams");
		}
		byte [] m = params.get(KEY_MANDATORY);
		if( m != null ) {
			if( m.length == 0 || m.length % 2 != 0 ) {
				throw new IllegalArgumentException("Invalid mandatory list");
			}
			for(int i=0; i < m.length; i += 2 ) {
				int k = ((m[i]&0xff) << 8) | (m[i+1]&0xff);
				if( k == KEY_MANDATORY ) {
					throw new IllegalArgumentException("mandatory can't list itself");
				}
				if( !params.containsKey(k) ) {
					throw new IllegalArgumentException("mandatory lists "+keyName(k)+", which is not present");
				}
			}
		}
		if( params.containsKey(KEY_NO_DEFAULT_ALPN) && !params.containsKey(KEY_ALPN) ) {
			throw new IllegalArgumentException("no-default-alpn needs alpn");
		}
	}

	/** The value of a parameter in presentation form ("" for no value). */
	public String valueString(int key) {
		byte [] v = params.get(key);
		if( v == null ) {
			return null;
		}
		StringBuilder b = new StringBuilder();
		switch(key) {
		case KEY_MANDATORY:
			for(int i=0; i+1 < v.length; i += 2 ) {
				if( i > 0 ) {
					b.append(',');
				}
				b.append(keyName(((v[i]&0xff) << 8) | (v[i+1]&0xff)));
			}
			return b.toString();
		case KEY_ALPN:
			for(String id : getAlpn()) {
				if( b.length() > 0 ) {
					b.append(',');
				}
				b.append(id.replace("\\","\\\\").replace(",","\\,"));
			}
			return b.toString();
		case KEY_NO_DEFAULT_ALPN:
			return "";
		case KEY_PORT:
			return String.valueOf(getPort());
		case KEY_IPV4HINT:
			for(int i=0; i+3 < v.length; i += 4 ) {
				if( i > 0 ) {
					b.append(',');
				}
				b.append(v[i]&0xff).append('.').append(v[i+1]&0xff).append('.').append(v[i+2]&0xff).append('.').append(v[i+3]&0xff);
			}
			return b.toString();
		case KEY_IPV6HINT:
			for(int i=0; i+15 < v.length; i += 16 ) {
				if( i > 0 ) {
					b.append(',');
				}
				AAAA a = new AAAA("");
				a.setRdata(java.util.Arrays.copyOfRange(v, i, i+16));
				b.append(a.getAddressString());
			}
			return b.toString();
		case KEY_ECH:
			return Base64.getEncoder().encodeToString(v);
		default:
			for(byte x : v) {
				int c = x&0xff;
				if( c > 0x20 && c < 0x7f && c != '"' && c != '\\' && c != ';' ) {
					b.append((char)c);
				} else {
					b.append(String.format("\\%03d", c));
				}
			}
			return b.toString();
		}
	}

	// ------------------------------------------------------------ wire

	@Override
	public void setFromRdata() {
		ByteBuffer in = new ByteBuffer(rdata);
		int end = rdata == null ? 0 : rdata.length;
		if( source != null ) {
			in = new ByteBuffer(source.getBuf(), sourcePos);
			end = sourcePos + rdlength;
		}
		if( rdlength < 3 && (rdata == null || rdata.length < 3) ) {
			throw new DnsFormatException("Invalid "+Utility.TYPENAMES[getType()]+" rdata");
		}
		priority = in.nextShort();
		target = new Name(in);
		TreeMap<Integer, byte[]> p = new TreeMap<Integer, byte[]>();
		int last = -1;
		while( in.getReadPos() < end ) {
			if( in.getReadPos()+4 > end ) {
				throw new DnsFormatException("Truncated SvcParam");
			}
			int key = in.nextShort();
			int len = in.nextShort();
			if( key <= last ) {
				throw new DnsFormatException("SvcParamKeys out of order");
			}
			if( in.getReadPos()+len > end ) {
				throw new DnsFormatException("Truncated SvcParamValue");
			}
			byte [] v = new byte[len];
			for(int i=0; i < len; i++ ) {
				v[i] = (byte)in.next();
			}
			p.put(key, v);
			last = key;
		}
		params = p;
		dirty = false;
	}

	@Override
	public void toByteArray(ByteBuffer out) {
		super.toByteArray(out);
		out.setShort(priority);
		//  Not compressed (RFC 9460 2.2)
		Srv.writeUncompressed(out, target.toString());
		for(Map.Entry<Integer, byte[]> e : params.entrySet()) {
			out.setShort(e.getKey());
			out.setShort(e.getValue().length);
			out.setBytes(e.getValue());
		}
		out.setRdLength();
	}

	@Override
	public String getRdataAsString() {
		StringBuilder b = new StringBuilder();
		b.append(priority).append(' ');
		String t = target.toString();
		b.append(t.isEmpty() ? "." : t+".");
		for(int key : params.keySet()) {
			b.append(' ').append(keyName(key));
			String v = valueString(key);
			if( v != null && !v.isEmpty() ) {
				b.append('=');
				if( key >= KEY_NAMES.length ) {
					b.append('"').append(v).append('"');
				} else {
					b.append(v);
				}
			}
		}
		return b.toString();
	}

	@Override
	public String toString() {
		return super.toString()+" "+getRdataAsString();
	}
}
