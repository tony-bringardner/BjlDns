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
This Class represents the DNS AFSDB (AFS Data Base location) Resource Record
As defined in RFC 1183

**/
public class Afsdb extends RR 
{

		//  ------ section ------ rdata
		//  owner ttl class AFSDB subtype hostname
		int subType=0;
		Name hostName = new Name("");
		boolean isBase = true;

		public Afsdb() {
				super();
				setType(MX);
				setDnsClass(IN);
				isBase = false;
				dirty = true;
		}
public Afsdb(String name) 
{
	super(name,MX,IN);
	isBase = false;
	dirty = true;
}
public Afsdb(String name, int dnsClass) 
{
	super(name,MX,dnsClass);
	isBase = false;
	dirty = true;
}
public Afsdb(String name, short dnsClass) 
{
	super(name,MX,dnsClass);
	isBase = false;
	dirty = true;
}
public Afsdb(RR rr) 
{
	super(rr);
	init(rr);
}
public RR copy()
{
	Afsdb ret = new Afsdb();
	super.copy(ret);
	ret.hostName = hostName;
	ret.isBase = isBase;
	ret.subType = subType;
	
	
	return ret;
}
/**
	Convert to a Java String
**/
public  String getRdataAsString()
{ 
	return subType+" "+hostName;
}
private void init(RR rr) 
{	
	setFromRdata();
	isBase = false;
}
/**
	Set the Internal Mail Exchange Name
**/
public void setExchange(String c) 
{ 
	hostName = new Name(c); 
	dirty = true;
}
public void setFromRdata() 
{
	ByteBuffer in = new ByteBuffer(rdata);
	if( source != null ) {
		in = new ByteBuffer(source.getBuf(),sourcePos);
	}
	subType = in.nextShort();
	hostName = new Name(in); 
	dirty = false;
}
/**
	Set the internal preferance value
**/
public void setSubType(short c) 
{
	subType = c; 
	dirty = true;
}
/**
	Add this MX resource record to the byte buffer as described in RFC 1035.
**/
public void toByteArray(ByteBuffer in) 
{
	super.toByteArray(in);	
	in.setShort(subType);
	in.setName(hostName);
	in.setRdLength();
}
/**
	Convert to a Java String
**/
public  String toString() 
{ 
	return super.toString()+" subType ="+subType+" hostName ="+hostName;
}
}
