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
The RDATA for this resource record is a four byte integer array containing the IP address of the host.
 **/
public class A extends RR {

	/**
		Default constructor 
	 **/
	public A() {
		super();
		setType(A);
		setDnsClass(IN);
		isBase = false;
		dirty = true;
		rdata = new byte[4];
	}
	
	/**
		Construct an 'A' resource record for a given host name (class defaults to IN)
	 **/
	
	public A(String name) {
		super(name,A,IN);
		isBase = false;
		dirty = true;
		rdata = new byte[4];
	}
	
	/**
		Construct an 'A' resource record for a given host name and class
	 **/
	public A(String name, int dnsClass) {
		super(name,A,dnsClass);
		isBase = false;
		dirty = true;
		rdata = new byte[4];
	}
	/**
		Construct an 'A' Resource record from another resorce record (It sould be an 'A' record)
	 **/
	public A(RR rr) {
		super(rr);
	}
	
	/**
Set the address of this host from a String representation in dot notation (999.999.999.999)
	 **/
	public RR copy(){
		A ret = new A();
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
Get the String representation of the host four byte array containing the address of this host (in dot notation as in 999.999.999.999)
	 **/
	public String getAddressString() { 
		return ""+(rdata[0]&0xff)+"."+
				(rdata[1]&0xff)+"."+
				(rdata[2]&0xff)+"."+
				(rdata[3]&0xff);
	}
	
	/**
Convert to a human readable String (name/address)
	 **/
	public  String getRdataAsString(){ 
		return getAddressString();
	}
	
	/**
Set the address of this host from a String representation in dot notation (999.999.999.999)
	 **/
	public void setAddress(String c) {
		byte [] tmp =  new byte[4];
		String parts[] = c.split("[.]");
		for (int idx = 0; idx < parts.length; idx++) {
			int i = Integer.parseInt(parts[idx]);
			if( i<1 || i>255) {
				throw new RuntimeException("Invalid value for address at pos "+idx+" value="+parts[idx]);
			}
			tmp[idx] = (byte)i;
		}
		setRdata(tmp);
	}

	public void setFromRdata() {
		return;
	}
	/**
Add this resource record to the byte buffer as described in RFC 1035.
	 **/
	public void toByteArray(ByteBuffer in) {
		rdlength = 4;
		super.toByteArray(in);
		in.setByte(rdata[0]);
		in.setByte(rdata[1]);
		in.setByte(rdata[2]);
		in.setByte(rdata[3]);
	}
	
	/**
Convert to a human readable String (name/address)
	 **/
	public  String toString() { 
		return super.toString()+" Address: "+getAddressString();
	}
}
