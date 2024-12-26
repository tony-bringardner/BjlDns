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

/**
This class implements the DNS SOA (Start of Authority) Resource Record

**/
public class Soa extends RR 
{

		//  This is the rdata
	/** 
	The domain name of the name server that was the original source of data for this zone 
	**/
	private	Name mname = new Name("");

	/**
	A domain name which specifies the mailbox of the person responsible for this zone
	**/
	private	Name rname = new Name("");

	/**
	The unsigned 32 bit version number of the original copy of the zone.
	**/
	private	int serial ;

	/**
	A 32 bit time interval before zone should be refreashed
	**/
	private	int refreash ;

	/**
	A 32 bit time interval that should elapse before a failed refresh should be retried
	**/
	private	int retry ;

	/**
	A 32 bit time value that specified the upper limit on the time interval that can elapse before the zone is no longer Authoritative
	**/
	private	int expire ;

	/**
	The unsigned 32 bit minimum TTL field taht should be exported with any RR from this zone
	**/
	private int minimum;

		public Soa() {
				super();
				setType(SOA);
				setDnsClass(IN);
				isBase = false;
				dirty = true;
		}
		public Soa(String n) {
				super(n,SOA,IN);
				isBase = false;
				dirty = true;
		}
		public Soa(String n, int c) {
				super(n,SOA,c);
				isBase = false;
				dirty = true;
		}
		public Soa(RR in) {
				super(in);
				setFromRdata();
		}
public RR copy()
{
	Soa ret = new Soa();
	copy(ret);
	ret.expire = expire;
	ret.minimum = minimum;
	ret.mname = mname;
	ret.refreash = refreash;
	ret.retry=retry;
	ret.rname = rname;
	ret.serial = serial;
	
	
	return ret;
}	
		public int getExpire() { return expire; }
		public int getMinimum() { return minimum; }
		public String getMname() { return mname.toString(); }
public  String getRdataAsString()
{
		return 	mname.toString()+". "+
				rname.toString()+". (\n\t\t"+
				serial+" ;serial\n\t\t"+
				refreash+" ;refreash\n\t\t"+
				retry+" ;retry\n\t\t"+
				expire+" ;expire\n\t\t"+
				minimum+" ;minimum\n\t\t"+
				")";
}
		public int getRefreash() { return refreash; }
		public int getRetry() { return retry; }
		public String getRname() { return rname.toString(); }
		public int getSerial() { return serial; }
		public void setExpire(int c)   { 
				expire = c; 
				dirty = true;
		}
		public void setFromRdata()  {
				ByteBuffer in = new ByteBuffer(getRdata());
				if( source != null) {
						in = new ByteBuffer(source.getBuf(),sourcePos);
				}

				mname = new Name(in);
				rname = new Name(in);
				serial = in.nextInt();
				refreash = in.nextInt();
				retry = in.nextInt();
				expire = in.nextInt();
				minimum = in.nextInt();
		}
		public void setMinimum(int c)   { 
				minimum = c; 
				dirty = true;
		}
public void setMname(String c) 
{ 
	mname = new Name(c); 
	dirty = true;
	if( getName().equals("@") ) {
		setName(mname.getParent());
	}
}
		public void setRefreash(int c) { 
				refreash = c; 
				dirty = true;
		}
		public void setRetry(int c)    { 
				retry = c; 
				dirty = true;
		}
		public void setRname(String c) { 
				rname = new Name(c); 
				dirty = true;
		}
		public void setSerial(int c) { 
				serial = c; 
				dirty = true;
		}
/**	
Add this SOA resource record to the byte buffer as described in RFC 1035.
**/
public void toByteArray(ByteBuffer in) 
{
		super.toByteArray(in);
		in.setName(rname);
		in.setName(mname);
		in.setInt(serial);
		in.setInt(refreash);
		in.setInt(retry);
		in.setInt(expire);
		in.setInt(minimum);

		in.setRdLength();
}
public  String toString() { 
		return super.toString()+" "+
				mname.toString()+" "+
				rname.toString()+" (\n\t"+
				serial+" ;serial\n\t"+
				refreash+" ;refreash\n\t"+
				retry+" ;retry\n\t"+
				expire+" ;expire\n\t"+
				minimum+" ;minimum\n\t"+
				")";
}
}
