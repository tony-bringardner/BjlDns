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
This class implements a DNS NS (Name Server) Resource Record
 **/
public class Ns extends RR {

	//  This is the rdata
	Name ns ;

	public Ns() {
		super();
		setType(NS);
		setDnsClass(IN);
		isBase = false;
		dirty = true;
	}

	public Ns(String name) {
		this(name,IN);
	}
	
	public Ns(String name, int dnsClass) {
		super(name,NS,dnsClass);
		isBase = false;
		dirty = true;
	}
	
	public Ns(RR rr) {
		super(rr);
		isBase = false;
	}
	
	/*
	Make a copy of the RR
	 */
	public RR copy() {
		Ns ret = new Ns();
		copy(ret);
		ret.ns = ns;

		return ret;
	}
	
	/**
	Get the Java String representation of the internal Name
	 **/
	public String getNs() { 
		return ns.toString(); 
	}
	
	/**
Convert to a Java STring
	 **/
	public  String getRdataAsString() { 
		String ret = ns.toString()+".";

		return ret;
	}
	/**
Set the internal NS value from the RDATA
	 **/
	public void setFromRdata() {
		ByteBuffer in = new ByteBuffer(rdata);
		if( source != null ) {
			in = new ByteBuffer(source.getBuf(),sourcePos);
		}
		ns = new Name(in);
	}
	
	/**
Set the internal value from a java String
	 **/
	public void setNs(String c) { 
		ns = new Name(c); 
		rdata = ns.toByteArray();
		rdlength = (short)rdata.length;
		dirty = false;
		source = null;
	}
	
	/**
	Add this NS resource record to the byte buffer as described in RFC 1035.
	 **/
	public void toByteArray(ByteBuffer in) {
		super.toByteArray(in);
		in.setName(ns);
		in.setRdLength();
	}
	
	/**
		Convert to a Java String
	 **/
	public  String toString() { 
		String ret = super.toString()+" "+ns.toString();
		return ret;
	}
	
}
