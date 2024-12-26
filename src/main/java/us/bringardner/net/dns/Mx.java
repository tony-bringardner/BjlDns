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
This Class represents the DNS MX Resource Record
 **/
public class Mx extends RR {

	//  This is the rdata
	int pref=0;
	Name exch = new Name("");
	boolean isBase = true;

	public Mx() {
		super();
		setType(MX);
		setDnsClass(IN);
		isBase = false;
		dirty = true;
	}
	public Mx(String name) 
	{
		super(name,MX,IN);
		isBase = false;
		dirty = true;
	}
	public Mx(String name, int dnsClass) 
	{
		super(name,MX,dnsClass);
		isBase = false;
		dirty = true;
	}
	public Mx(String name, short dnsClass) 
	{
		super(name,MX,dnsClass);
		isBase = false;
		dirty = true;
	}
	public Mx(RR rr) 
	{
		super(rr);
		init(rr);
	}
	public RR copy()
	{
		Mx ret = new Mx();
		super.copy(ret);
		ret.exch = exch;
		ret.isBase = isBase;
		ret.pref = pref;


		return ret;
	}
	/**
	Get teh internal Mail Exchange Name
	 **/
	public String getExchange() { return exch.toString(); }
	/**
	Get the internal preference
	 **/
	public int getPref() { return pref; }
	/**
	Convert to a Java String
	 **/
	public  String getRdataAsString()
	{
		return pref+" "+exch.toString()+".";

	}
	private void init(RR rr) 
	{	
		setFromRdata();
		isBase = false;
	}
	/**
	Set the Internal Mail Exchange Name
	 **/
	public void setExchange(String c) { 
		exch = new Name(c); 
		dirty = true;
	}
	public void setFromRdata() 
	{

		ByteBuffer in = new ByteBuffer(rdata);
		if( source != null ) {
			in = new ByteBuffer(source.getBuf(),sourcePos);
		}
		pref = in.nextShort();
		exch = new Name(in); 
		dirty = false;

	}
	/**
	Set the internal preferance value
	 **/
	public void setPref(short c) { 
		pref = c; 
		dirty = true;
	}
	/**
	Add this MX resource record to the byte buffer as described in RFC 1035.
	 **/
	public void toByteArray(ByteBuffer in) 
	{
		super.toByteArray(in);	
		in.setShort(pref);
		in.setName(exch);
		in.setRdLength();
	}
	/**
	Convert to a Java String
	 **/
	public  String toString() { 
		return super.toString()+" preference ="+pref+
		" mail exchanger ="+exch.toString();
	}
}
