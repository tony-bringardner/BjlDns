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
This class implements a DNS PTR Resource Record as describied in RFC 1035
**/
public class Ptr extends RR {

		//  This is the rdata
		Name ptr ;

	/**
	Default Constructor
	**/
		public Ptr() {
				super();
				setType(PTR);
				setDnsClass(IN);
				isBase = false;
				dirty = true;
		}
	/**
	Construct a PTR and assign the RR.name from a parameter
	**/
public Ptr(String name) 
{
	super(name,PTR,IN);
	isBase = false;
	dirty = true;
}
/**
Construct a PTR and assign the RR.name and RR.dnsClass from a parameter
**/
public Ptr(String name, int dnsClass) 
{
	super(name,PTR,dnsClass);
	isBase = false;
	dirty = true;
}
	/**
	Construct a PTR from an RR
	**/
		public Ptr(RR rr) {
				super(rr);
				isBase = false;
				dirty = true;
				setFromRdata();
		}
/*
	Make a copy of the RR
*/
public RR copy()
{
	Ptr ret = new Ptr();
	copy(ret);
	ret.ptr = ptr;
	
	return ret;
}
	/**
	Get the String representaion of the PTR value
	**/
		public String getPtr() { return ptr.toString(); }
	/**
	Convert to a Java String
	**/
public  String getRdataAsString()
{
	return ptr.toString(); 
}
		public void setFromRdata() {
				ByteBuffer in = new ByteBuffer(getRdata());
				if( source != null) {
						in = new ByteBuffer(source.getBuf(),sourcePos);
				}
				ptr = new Name(in);
		
		}
/**
	Set the PTR value from a Java String 
**/
public void setPtr(String c) 
{ 
	ptr = new Name(c);
	rdata = ptr.toByteArray();
	rdlength = rdata.length;
	dirty = false;
	source = null;
}
public void toByteArray(ByteBuffer in) 
{
		super.toByteArray(in);
		in.setName(ptr);
		in.setRdLength();
}
	/**
	Convert to a Java String
	**/
		public  String toString() { 
						return super.toString()+" "+ptr.toString(); 
		}
}
