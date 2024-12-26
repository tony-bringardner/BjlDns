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
Resource Record idetifies a canonicol name of an alias (the RDATA for this record is the alias name)
**/
public class Cname extends RR {

		//  This is the rdata
		Name cname ;

	/**
	Default constructor
	**/
		public Cname() {
				super();
				setType(CNAME);
				setDnsClass(IN);
				isBase = false;
				dirty = true;
		}
	/**
	Construct a 'Cname' resource record for this given name, class defaults to IN (Note: The 'name' here is ussed as the RR.name value, the alias must still be set using the setCname meathod.
	**/
public Cname(String name) 
{
	super(name,CNAME,IN);
	isBase = false;
	dirty = true;
}
	/**
	Construct a 'Cname' resource record for this given name and class (Note: The 'name' here is ussed as the RR.name value, the alias must still be set using the setCname meathod.
	**/
public Cname(String name, int dnsClass) 
{
	super(name,CNAME,dnsClass);
	isBase = false;
	dirty = true;
}
	/**
	Construct a 'Cname' record from an RR record (the RDATA should represent a JDns.Name of an alias)
	**/
		public Cname(RR rr) {
				super(rr);
				isBase = false;
		}
public RR copy()
{
	Cname ret = new Cname();
	super.copy(ret);
	ret.cname = cname;
	
	return ret;
}
	/**
	Get the 'alias' associated with the record
	**/
		public String getCname() { 
				return cname.toString(); 
		}
	/**
	Convert to a String in the form 'name alias'
	**/
public  String getRdataAsString()
{
	return cname.toString()+"."; 
}
/**
	Set the 'alias' associated with the record
**/
public void setCname(String cName) 
{ 
	this.cname = new Name(cName); 
	dirty = true;
}
		public void setFromRdata() {
				ByteBuffer in = new ByteBuffer(getRdata());
				if( source != null) {
						in = new ByteBuffer(source.getBuf(),sourcePos);
				}
				cname = new Name(in);
		}
/**	
Add this CNAME resource record to the byte buffer as described in RFC 1035.
**/
public void toByteArray(ByteBuffer in) 
{
		super.toByteArray(in);
		in.setName(cname);
		in.setRdLength();
}
	/**
	Convert to a String in the form 'name alias'
	**/
		public  String toString() { 
						return super.toString()+" "+cname.toString(); 
		}
}
