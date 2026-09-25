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
 *
 * ~version~V000.00.05-V000.00.00-
 */
package us.bringardner.net.dns;


/*
	Copyright Tony Bringardner 1999, 2000
 */


/**
Host Address Resource Record
The RDATA for this resource record is a four byte integer array containing the IP6 address of the host.
 **/
public class AAAA extends RR {

	/**
		Default constructor 
	 **/
	public AAAA() {
		super();
		setType(AAAA);
		setDnsClass(IN);
		isBase = false;
		dirty = true;
		
	}

	/**
		Construct an 'AAAA' resource record for a given host name (class defaults to IN)
	 **/
	public AAAA(String name) {
		super(name,AAAA,IN);
		isBase = false;
		dirty = true;
	
	}

	/**
		Construct an 'AAAA' resource record for a given host name and class
	 **/
	public AAAA(String name, int dnsClass) {
		super(name,AAAA,dnsClass);
		isBase = false;
		dirty = true;
		
	}

	/**
		Construct an 'A' Resource record from another resorce record (It sould be an 'A' record)
	 **/
	public AAAA(RR rr) {
		super(rr);
	}

	/**
	 * Set the address of this host from a String representation in dot notation (201:2db7::fa00:0040:6669)
	 **/
	public RR copy(){
		AAAA ret = new AAAA();
		super.copy(ret);

		return ret;
	}

	/**
		Get the 16 byte address
	 **/
	public byte []  getAddress() { 
		return super.getRdata();
	}

	/**
	 * The address in the canonical text form of RFC 5952: lower case, leading
	 * zeros dropped, the longest run of two or more zero groups shown as "::".
	 * (The old formatter left out zero groups and produced forms such as
	 * "2001:db8:::::1".)
	 **/
	public String getAddressString() {
		byte [] r = rdata;
		if( r == null || r.length != 16 ) {
			return "";
		}
		int [] g = new int[8];
		for(int i=0; i < 8; i++ ) {
			g[i] = ((r[i*2]&0xff) << 8) | (r[i*2+1]&0xff);
		}
		//  IPv4-mapped (::ffff:a.b.c.d)
		if( g[0]==0 && g[1]==0 && g[2]==0 && g[3]==0 && g[4]==0 && g[5]==0xffff ) {
			return "::ffff:"+(r[12]&0xff)+"."+(r[13]&0xff)+"."+(r[14]&0xff)+"."+(r[15]&0xff);
		}
		int bestStart = -1, bestLen = 0;
		for(int i=0; i < 8; ) {
			if( g[i] == 0 ) {
				int j = i;
				while( j < 8 && g[j] == 0 ) {
					j++;
				}
				if( j-i > bestLen ) {
					bestStart = i;
					bestLen = j-i;
				}
				i = j;
			} else {
				i++;
			}
		}
		if( bestLen < 2 ) {
			bestStart = -1;
		}
		StringBuilder buf = new StringBuilder();
		for(int i=0; i < 8; i++ ) {
			if( i == bestStart ) {
				buf.append("::");
				i += bestLen-1;
				continue;
			}
			if( buf.length() > 0 && buf.charAt(buf.length()-1) != ':' ) {
				buf.append(':');
			}
			buf.append(Integer.toHexString(g[i]));
		}
		return buf.toString();
	}

	/**
		Convert to a human readable String (name/address)
	 **/
	public  String getRdataAsString(){ 
		return getAddressString();
	}

	/**
	 * Set the address from its text form: any valid IPv6 form, e.g. 2001:db8::1,
	 * ::1, 2001:0db8:0:0:0:0:0:1 or ::ffff:192.0.2.1. (The old parser rejected
	 * common forms such as 2001:db8::1.)
	 * 
	 * @throws IllegalArgumentException if it is not an IPv6 address
	 */
	public void setAddress(String a) {
		if( a == null ) {
			throw new IllegalArgumentException("Invalid IPv6 address: null");
		}
		String addr = a.trim();
		//  Only characters of an IPv6 literal, so InetAddress never does a name lookup
		if( addr.indexOf(':') < 0 || !addr.matches("[0-9A-Fa-f:.]+") ) {
			throw new IllegalArgumentException("Invalid IPv6 address: '"+a+"'");
		}
		byte [] tmp;
		try {
			java.net.InetAddress ia = java.net.InetAddress.getByName(addr);
			tmp = ia.getAddress();
		} catch (java.net.UnknownHostException e) {
			throw new IllegalArgumentException("Invalid IPv6 address: '"+a+"'");
		}
		if( tmp.length == 4 ) {
			//  Java turns ::ffff:a.b.c.d into an Inet4Address
			byte [] mapped = new byte[16];
			mapped[10] = (byte)0xff;
			mapped[11] = (byte)0xff;
			System.arraycopy(tmp, 0, mapped, 12, 4);
			tmp = mapped;
		}
		setRdata(tmp);
	}

	public void setFromRdata() {
		return;
	}

	/**
	*		Add this resource record to the byte buffer as described in RFC 1035.
	 **/
	public void toByteArray(ByteBuffer in) {
		byte [] r = rdata;
		if( r == null || r.length != 16 ) {
			throw new IllegalStateException("AAAA "+getName()+" has no 16 byte address");
		}
		//  (This used to set rdata to 16 zero bytes first, so every AAAA
		//  answer that was passed on went out as "::".)
		rdlength=16;
		super.toByteArray(in);
		in.setBytes(r);
	}

	/**
Convert to a human readable String (name/address)
	 **/
	public  String toString() { 
		return super.toString()+" Address: "+getAddressString();
	}
}
