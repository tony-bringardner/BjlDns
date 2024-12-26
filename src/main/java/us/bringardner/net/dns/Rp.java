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
This Class represents the DNS RP (Responsible Person) Resource Record
As defined in RFC 1183
**/
public class Rp extends RR 
{
		// ---- Section ---- rdata
		//owner ttl class RP mbox-dname txt-dname

		Name mboxDname = new Name("");
		Name txtDname  = new Name("");
		
		boolean isBase = true;

		public Rp() {
				super();
				setType(MX);
				setDnsClass(IN);
				isBase = false;
				dirty = true;
		}
public Rp(String name) 
{
	super(name,MX,IN);
	isBase = false;
	dirty = true;
}
public Rp(String name, int dnsClass) 
{
	super(name,MX,dnsClass);
	isBase = false;
	dirty = true;
}
public Rp(String name, short dnsClass) 
{
	super(name,MX,dnsClass);
	isBase = false;
	dirty = true;
}
public Rp(RR rr) 
{
	super(rr);
	init(rr);
}
public RR copy()
{
	Rp ret = new Rp();
	super.copy(ret);
	ret.mboxDname = mboxDname;
	ret.txtDname = txtDname;
	

	ret.isBase = isBase;
	
	return ret;
}
/**
	Get teh internal Mail Exchange Name
**/
public String getMboxDname()
{ 
	return mboxDname.toString(); 
}
/**
	Convert to a Java String
**/
public  String getRdataAsString()
{
	return ""+mboxDname+" "+txtDname;
}
/**
	Get teh internal Mail Exchange Name
**/
public String getTxtDname()
{ 
	return txtDname.toString(); 
}
private void init(RR rr) 
{	
	setFromRdata();
	isBase = false;
}
public void setFromRdata() 
{
	ByteBuffer in = new ByteBuffer(rdata);
	if( source != null ) {
		in = new ByteBuffer(source.getBuf(),sourcePos);
	}
	mboxDname = new Name(in);
	txtDname = new Name(in); 	
	dirty = false;
}
/**
	Set the Internal Mail Exchange Name
**/
public void setMboxDname(String c) 
{ 
	mboxDname = new Name(c); 
	dirty = true;
}
/**
	Set the Internal Mail Exchange Name
**/
public void setTxtDname(String c) 
{ 
	txtDname = new Name(c); 
	dirty = true;
}
/**
	Add this MX resource record to the byte buffer as described in RFC 1035.
**/
public void toByteArray(ByteBuffer in) 
{
	super.toByteArray(in);	
	in.setName(mboxDname);
	in.setName(txtDname);
	in.setRdLength();
}
/**
	Convert to a Java String
**/
public  String toString() 
{
	return super.toString()+" mboxDname ="+mboxDname+" txtDname ="+txtDname;
}
}
