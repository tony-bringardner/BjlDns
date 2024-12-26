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

import java.util.ArrayList;
import java.util.List;

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
		Get the host four byte array containing the address of this host
	 **/
	public byte []  getAddress() { 
		return super.getRdata();
	}

	/**
		Get the String representation of the host four byte array containing the address of this host (in dot notation as in 201:2db7::fa00:0040:6669)
	 **/
	public String getAddressString() {
		int sz2 = rdata.length/2;
		
		StringBuilder buf  = new StringBuilder();
		
		for (int idx = 0; idx < sz2; idx++) {
			if( idx > 0 ) {
				buf.append(":");
			}
			int ridx=idx*2;
			int i = Utility.makeShort(rdata[ridx], rdata[ridx+1]);
			if( i > 0) {
				buf.append(Integer.toHexString(i));
			}
		}
		String ret = buf.toString();
		while(ret.indexOf(":::") >=0) {
			ret = ret.replaceFirst(":::", "::");
		}
		return ret;
	}

	/**
		Convert to a human readable String (name/address)
	 **/
	public  String getRdataAsString(){ 
		return getAddressString();
	}



	/**
	 * Just count how many : are in a string
	 * @param str
	 * @return
	 */
	private int count(String str) {
		int ret = 0;
		byte [] data = str.getBytes();
		for (int idx = 0; idx < data.length; idx++) {
			if( data[idx] == (byte)':') {
				ret++;
			}
		}
		if( !str.endsWith(":") ) {
			ret++;
		}
		return ret;
	}
	
	/**
	 * Expand an ip6 address by filling in empty or missing fields (x:x:x:x:x becomes :::x:x:x:x:x)
	 * @param ip6Address
	 * @return
	 */
	private String expand(String ip6Address) {
		String ret = ip6Address;
		int idx1 = ip6Address.indexOf("::");		
		if(idx1>=0) {
			List<String> ll  = split(ip6Address);
			if( ll.size()==8) {
				return ip6Address;
			}
			String l = ip6Address.substring(0, idx1);
			String r = ip6Address.substring(idx1+2);
			int lc = count(l);
			int rc = count(r);
			while(rc+lc <= 8) {
				r = ":"+r;
				rc = count(r);
			}
			ret = l+r;
			List<String> list = split(ret);
			if( list.size()>8) {
				while(list.size()>8) {
					if( ret.endsWith(":")) {
						ret = ret.substring(0,ret.length()-1);
						list = split(ret);
					} else if( ret.startsWith(":") ) {
						ret = ret.substring(1);
						list = split(ret);
					} else {
						throw new RuntimeException("can't resolve Invalid IP6 address expantion str="+ip6Address+" ret="+ret);
					}					
				}				
			} else {
				throw new RuntimeException("Invalid IP6 address expantion str="+ip6Address+" ret="+ret+" size="+list.size());
			}
		}
		
		return ret;
	}
	
	/**
	 * String.split does ignores cases where there are baack-to-back separators
	 * @param ip
	 * @return
	 */
	private List<String> split(String ip) {
		List<String> ret = new ArrayList<>();
		char c = ':';
		
		int idx = ip.indexOf(c);
		while(idx >=0) {
			String left = ip.substring(0, idx);
			ret.add(left.trim());
			ip = ip.substring(idx+1);
			idx = ip.indexOf(c);
		}
		ret.add(ip);
		return ret;
	}
	
	/**
	IPv6 addresses are significantly longer than IPv4 variants (eight 16-bit blocks with groups of four symbols, often called hextets or quartets) 
	and are alphanumeric. Also, whereas IPv4 relies on periods for formatting, IPv6 uses colons, such as in this example:

				2001:0db8:0000:0001:0000:ff00:0032:7879

	The model omits leading zeros (like in IPv4), and you'll sometimes find IP addresses that have a double colon (::) that designate any number of 0 bits 
	(such as 1201:2db7::fa00:0040:6669, in which the third, fourth, and fifth hextets are 0000). 

	 */
	public void setAddress(String a) {
		a = a.trim();
		if( a.endsWith(":")) {
			throw new RuntimeException("invalid address (cannot end with : )");
		}
		int i1x = a.indexOf("::");
		int i2x = a.lastIndexOf("::");
		if( i1x != i2x ) {
			throw new RuntimeException("invalid address (multiple :: at "+i1x +" and "+i2x+")");
		}
		
		String address = expand(a);
		byte [] tmp =  new byte[16];
		List<String> parts = split(address);
		for (int idx = 0,sz=parts.size(); idx < sz; idx++) {			
			String str = parts.get(idx);
			if( str != null && !((str=str.trim()).isEmpty())) {
				int i1 = Integer.parseInt(str,16);					
				Utility.setShort(tmp, idx*2, i1);
				int i2 = Utility.makeShort(tmp[(idx*2)+0], tmp[(idx*2)+1]);
				//TODO:  Remove the when testing is complete
				if( i2 != i1 ) {
					throw new RuntimeException("did not convert value back it int correctly i1="+i1+" i2="+i2);
				}
			}
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
		rdata = new byte[16];
		rdlength=16;
		super.toByteArray(in);
		for (int idx = 0; idx < rdata.length; idx++) {
			in.setByte(rdata[idx]);	
		}

	}

	/**
Convert to a human readable String (name/address)
	 **/
	public  String toString() { 
		return super.toString()+" Address: "+getAddressString();
	}
}
