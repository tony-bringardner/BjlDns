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



public  class RR extends Section 
{
	//  Fields in this order
	int ttl=0;      // 32 bit == Time to live (0 == only this trans)
	int rdlength=0; // 16 bit == bytes in RDATA
	byte [] rdata;  //  Diff for each type
	//  Time this record was inited (this can be used to 
	//  determine if the record should be expired
	long initTime;	
	boolean isBase = true;
	boolean dirty = true;
	ByteBuffer source = null;
	int sourcePos = -1;

	public RR() {
	}
	
	public RR(String name, int type, int dnsClass) {
		super(name,type,dnsClass);
	}
	
	public RR(ByteBuffer in) {
		super(in);
		init(in);
	}
	
	public RR(RR sec) {
		super(sec.getName(),sec.getType(),sec.getDnsClass());
		init(sec);	
	}
	
	/**
 		Make a copy of this RR
	 **/
	public  RR copy() {
		throw new IllegalStateException("copy MUST be overridden! type "+getType());
	}
	
	/**
 		Make an 'exact' copy of this RR
	 **/
	public  void copy(RR newObj) {

		super.copy(newObj);
		newObj.dirty = dirty;
		newObj.initTime = initTime;
		newObj.isBase = isBase;
		newObj.rdata  = rdata;
		newObj.rdlength = rdlength;
		newObj.source = source;
		newObj.sourcePos = sourcePos;
		newObj.ttl = ttl;

	}
	
	/**
	 * Gets the initTime
	 * @return Returns a long
	 */
	public long getInitTime() {
		return initTime;
	}
	
	public byte [] getRdata() {
		return rdata;
	}
	
	public String getRdataAsString() {
		throw new IllegalStateException("call to getRDataAsString not valid for this object");
	}
	
	public int getRdLength() { 
		return rdlength;  
	}
	
	public int getTTL() { 
		return ttl; 
	}
	
	public boolean hasExpired() {
		boolean ret = false;
		long now = System.currentTimeMillis();
		long expTime = initTime+(ttl*1000);
		ret = (now > expTime);
		return ret;
	}
	
	private void init(ByteBuffer in) {
		ttl = in.nextInt();
		readRdata(in);  
	}
	
	private void init(RR sec) {	
		setTTL(sec.getTTL());
		setRdata(sec.getRdata());
		source = sec.source;
		sourcePos = sec.sourcePos;      
		setFromRdata();
		dirty = false;
	}
	
	static RR parseRR(ByteBuffer in) {
		RR sec = new RR(in);
		RR ret = null;
		int type = sec.getType();

		switch( sec.getType() ) {
		case A     : ret = new A(sec);break;
		case NS    : ret = new Ns(sec);break;
		case CNAME : ret = new Cname(sec);break;
		case SOA   : ret = new Soa(sec);break;
		case PTR   : ret = new Ptr(sec);break;
		case TXT   : ret = new Txt(sec);break;
		case HINFO : ret = new Hinfo(sec);break;
		case MX    : ret = new Mx(sec);break;
		case RP    : ret = new Rp(sec);break;
		case AFSDB    : ret = new Afsdb(sec);break;
		case AAAA:	ret = new AAAA(sec);break;

		//  This is to prevent the log file from filling with unsupported errors
		case OPT	: ret = new RR(sec);break;


		default:
			ret = new RR(sec);
			ret.logDebug("Un Supported type="+type +(type < DNS.TYPENAMES.length ? " ("+DNS.TYPENAMES[type]+")" : ""));
		}
		return ret;
	}
	
	//  Read all the bytes
	public  void readRdata(ByteBuffer in) {
		rdlength = in.nextShort();
		rdata = new byte [rdlength];
		source = in;
		sourcePos = in.getReadPos();
		for(int i = 0; i< rdlength; i++ ) {
			rdata[i] = (byte)in.next();
		}
		setFromRdata();
	}
	
	/**
 		Set the TYPE Specific data elements from the RDATA array, this method is intended to be implemented by a subclass,  It has no value a this level, however, we can't make it abstract becouse parseRR needs to be able to create an RR without knowing what type it is (I'm sure there is a better way to do this, but, it works).
	 **/
	public  void setFromRdata() {
		if( ! isBase ) {
			throw new IllegalStateException("setFromRdata MUST be overridden! type "+getType());
		}
	}
	
	/**
	 * Sets the initTime
	 * @param initTime The initTime to set
	 */
	public void setInitTime(long initTime) {
		this.initTime = initTime;
	}
	
	public  void setRdata(byte [] b) {
		rdata = b;
		rdlength = (short)b.length;
	}
	
	public void setTTL(int t) { 
		ttl = t; 
	}
	
	public int size() {
		// super + ttl(4)+ rdlen(2)
		return super.size()+6;
	}
	
	public  void toByteArray(ByteBuffer buf) {

		if( !dirty ) {
			try {
				setFromRdata();
			} catch(Exception ex) {
				ex.printStackTrace(System.err);
				throw new IllegalArgumentException(ex);
			}
		}

		super.toByteArray(buf); 

		buf.setInt(ttl);
		buf.markPos(rdlength);
	}
	
	public  String toString() { 
		return super.toString() +" ttl="+ttl+" rdlen="+rdlength+" ";
	}
	
}
