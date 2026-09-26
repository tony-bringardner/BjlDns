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

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.TimeZone;
import java.util.function.UnaryOperator;

import us.bringardner.net.dns.Base32Hex;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Dnskey;
import us.bringardner.net.dns.Nsec;
import us.bringardner.net.dns.Nsec3;
import us.bringardner.net.dns.Nsec3param;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.Rrsig;
import us.bringardner.net.dns.Utility;

/**
 * Zone file text of the DNSSEC records (RFC 4034, RFC 5155 presentation
 * formats), for zones signed by another tool.
 */
final class PresignedRecords implements DNS {

	private PresignedRecords() {
	}

	/**
	 * @param rdata the fields after the type
	 * @param fixName makes a zone file name absolute
	 */
	static RR parse(int type, String owner, int dnsClass, List<String> rdata, UnaryOperator<String> fixName) {
		try {
			switch(type) {
			case DNSKEY: {
				need(rdata, 4, "DNSKEY needs flags protocol algorithm key");
				Dnskey k = new Dnskey(owner, dnsClass);
				k.setFlags(Integer.parseInt(rdata.get(0)));
				k.setProtocol(Integer.parseInt(rdata.get(1)));
				k.setAlgorithm(Integer.parseInt(rdata.get(2)));
				k.setKey(base64(rdata, 3));
				return k;
			}
			case RRSIG: {
				need(rdata, 9, "RRSIG needs type algorithm labels ttl expiration inception keytag signer signature");
				Rrsig s = new Rrsig(owner, dnsClass);
				s.setTypeCovered(typeCode(rdata.get(0)));
				s.setAlgorithm(Integer.parseInt(rdata.get(1)));
				s.setLabels(Integer.parseInt(rdata.get(2)));
				s.setOrigTtl((int)Long.parseLong(rdata.get(3)));
				s.setExpiration(time(rdata.get(4)));
				s.setInception(time(rdata.get(5)));
				s.setKeyTag(Integer.parseInt(rdata.get(6)));
				s.setSigner(name(rdata.get(7), fixName));
				s.setSignature(base64(rdata, 8));
				return s;
			}
			case NSEC: {
				need(rdata, 1, "NSEC needs the next name");
				Nsec n = new Nsec(owner, dnsClass);
				n.setNext(name(rdata.get(0), fixName));
				n.setTypes(types(rdata, 1));
				return n;
			}
			case NSEC3: {
				need(rdata, 5, "NSEC3 needs algorithm flags iterations salt next-hash");
				Nsec3 n = new Nsec3(owner, dnsClass);
				n.setHashAlgorithm(Integer.parseInt(rdata.get(0)));
				n.setFlags(Integer.parseInt(rdata.get(1)));
				n.setIterations(Integer.parseInt(rdata.get(2)));
				n.setSalt(salt(rdata.get(3)));
				n.setNextHashed(Base32Hex.decode(rdata.get(4)));
				n.setTypes(types(rdata, 5));
				return n;
			}
			case NSEC3PARAM: {
				need(rdata, 4, "NSEC3PARAM needs algorithm flags iterations salt");
				Nsec3param p = new Nsec3param(owner, dnsClass);
				p.setHashAlgorithm(Integer.parseInt(rdata.get(0)));
				p.setFlags(Integer.parseInt(rdata.get(1)));
				p.setIterations(Integer.parseInt(rdata.get(2)));
				p.setSalt(salt(rdata.get(3)));
				return p;
			}
			default:
				throw new IllegalArgumentException("not a DNSSEC type: "+type);
			}
		} catch(NumberFormatException ex) {
			throw new IllegalArgumentException("Invalid "+Utility.TYPENAMES[type]+" record: "+ex.getMessage(), ex);
		}
	}

	private static void need(List<String> rdata, int n, String msg) {
		if( rdata.size() < n ) {
			throw new IllegalArgumentException(msg);
		}
	}

	private static String name(String n, UnaryOperator<String> fixName) {
		return n.equals(".") ? "" : fixName.apply(n);
	}

	/** Base64 that may be split over several fields. */
	private static byte [] base64(List<String> rdata, int from) {
		StringBuilder b = new StringBuilder();
		for(int i=from; i < rdata.size(); i++ ) {
			b.append(rdata.get(i));
		}
		return Base64.getDecoder().decode(b.toString());
	}

	private static byte [] salt(String s) {
		if( s.equals("-") ) {
			return new byte[0];
		}
		if( (s.length() & 1) != 0 || !s.matches("[0-9A-Fa-f]+") ) {
			throw new IllegalArgumentException("Invalid NSEC3 salt '"+s+"'");
		}
		byte [] b = new byte[s.length()/2];
		for(int i=0; i < b.length; i++ ) {
			b[i] = (byte)Integer.parseInt(s.substring(2*i, 2*i+2), 16);
		}
		return b;
	}

	/** YYYYMMDDHHmmSS (UTC) or seconds since 1970 (RFC 4034 3.2). */
	static long time(String t) {
		if( t.length() == 14 && t.matches("\\d+") ) {
			try {
				SimpleDateFormat f = new SimpleDateFormat("yyyyMMddHHmmss");
				f.setTimeZone(TimeZone.getTimeZone("UTC"));
				f.setLenient(false);
				return f.parse(t).getTime()/1000;
			} catch(ParseException ex) {
				throw new IllegalArgumentException("Invalid RRSIG time '"+t+"'");
			}
		}
		return Long.parseLong(t);
	}

	/** A type name, TYPEnnn (RFC 3597) or number. */
	static int typeCode(String t) {
		if( t.regionMatches(true, 0, "TYPE", 0, 4) && t.length() > 4 && t.substring(4).matches("\\d+") ) {
			return Integer.parseInt(t.substring(4));
		}
		if( t.equalsIgnoreCase("CAA") ) {
			return CAA;
		}
		int ret = Utility.typeOf(t);
		if( ret <= 0 || ret == QTYPE_ALL ) {
			throw new IllegalArgumentException("Unknown type '"+t+"'");
		}
		return ret;
	}

	private static List<Integer> types(List<String> rdata, int from) {
		List<Integer> ret = new ArrayList<Integer>();
		for(int i=from; i < rdata.size(); i++ ) {
			ret.add(typeCode(rdata.get(i)));
		}
		return ret;
	}
}
