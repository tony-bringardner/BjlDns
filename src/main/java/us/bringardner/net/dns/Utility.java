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
This class implements a set of utility functions required for byte and bit manipulation 
 **/
public  class Utility extends DnsBaseClass implements DNS {

	static final int [] bitMask = { 
			1 ,  // bit 0
			2 , // bit 1
			4 , // bit 2
			8 , // bit 3
			16 , // bit 4
			32 , // bit 5
			64 , // bit 6
			128 ,// bit 7
			256, // bit 8
			512, // bit 9
			1024, // bit 10
			2048, // bit 11
			4096, // bit 12
			8192, // bit 13
			16384, // bit 14
			32768  // bit 15
	};

	/** Required to get rid of the high end bits that Jave likes to add when converting bytes to larger values **/
	public static final int MASK = 0x00FF; 


	public static final int MINUTE=60;
	public static final int HOUR=MINUTE*60;
	public static final int DAY=HOUR*24;
	public static final int WEEK=DAY*7;

	public static final int MONTH=WEEK*4;


	/** Shorthand for Integer.toBinaryString (yes, I'm that lazy) **/
	public static String bi(int i) 
	{
		return pad( Integer.toBinaryString(i & 0x0ffff),8);

	}
	/** Determine the DNS 'CLASS' based on a string (example "IN") **/
	public static short classOf(String t) 
	{ 
		short dnsClass = 0;
		for(int i=0 ; i< CLASSNAMES.length; i++) {
			if(CLASSNAMES[i].equalsIgnoreCase(t)) {
				dnsClass = (short)i;
				break;
			}
		}
		return dnsClass;
	}
	/** Clear the specified bit in a short value (set it to 0) **/
	public static short clearBit(short s, int b ) {
		return (short)(s & bitMask[b]);
	}
	/** 
	Check to see if the specified bit is set (==1)
	@param s A Java short
	@param b an int index to the specified bit
	@return true if the specified bit ==1 
	 **/
	public static boolean isSet(int s, int b) 
	{

		boolean ret =  (s&bitMask[b]) == bitMask[b];
		return ret;
	}
	public static int makeInt(int b1, int b2, int b3, int b4) {
		int s1 = makeShort(b1,b2);
		int s2 = makeShort(b3,b4);

		int ret = (((s1<<16)|s2));
		return ret;
	}	
	
	/** Build a Java short from two bytes **/
	public static int makeShort(int b1, int b2) {
		int i1 = (b1 & 0xff);
		int i2 = (b2 & 0xff);
		int ret = ((i1<<8)|i2)&0xffff;


		return ret;
	}

	/** Shorthand for Integer.toBinaryString (yes, I'm that lazy) **/
	public static String pad(String val, int len) 
	{
		String ret = "00000000"+ val;
		return ret.substring(ret.length()-len);
	}	
	
	/** Set the specified bit in a short value (set it to 1) **/
	public static int setBit(int s, int b ) {
		int ret = (s | bitMask[b]);
		return ret;
	}
	
	/**
	Convert a Java int into four bytes and place them into a byte array
	@param buf A byte array to Receive the bytes
	@param idx array index to place the bytes
	@param val a Java int 
	 **/
	public static void setInt(byte [] buf, int idx, int val) {
		short s = (short)(val >> 16);
		setShort(buf,idx,s);
		s = (short)val;
		setShort(buf,idx+2,s);
	}
	
	public static void setShort(byte [] buf, int idx, int s) {
		buf[idx] = (byte)(s >> 8);
		buf[idx+1] = (byte)s;
	}	
	
	/** Determine the DNS 'TYPE' based on a string (example "MX") **/
	/**
	Convert a Java short into two bytes and place them into a byte array
	@param buf A byte array to Receive the bytes
	@param idx array index to place the bytes
	@param val a Java short 
	 **/
	public static void setShort(byte [] buf, int idx, short s) {
		buf[idx] = (byte)(s >> 8);
		buf[idx+1] = (byte)s;
	}
	/**
	Calculate a number of seconds (1, 1d, 1h, 1m, 1w)
	 **/
	public static int toSeconds(String val)
	{

		if( val == null ) {
			return 0;
		}
		val = val.trim();
		if( val.length() == 0) {
			return 0;
		}

		int i=0;
		int sz = val.length();

		for(; i< sz; i++ ) {
			if( Character.isDigit(val.charAt(i)) == false) {
				break;
			}
		}
		if( i < 1 ) {
			return 0;
		}

		String num = val;
		String mul = "s";

		if( i != sz) {
			num = val.substring(0,i);
			mul = val.substring(i);
		}

		int unit = 1;
		if( mul.length() > 0 ) {
			switch(mul.charAt(0)) {
			case 's':
			case 'S':unit = 1;	break;
			case 'm':
			case 'M':unit = MINUTE;	break;
			case 'h':
			case 'H':unit = HOUR;	break;
			case 'd':
			case 'D':unit = DAY;	break;
			case 'w':
			case 'W':unit = WEEK;	break;

			}
		}

		int ret = Integer.parseInt(num);
		ret = ret * unit;

		return ret;

	}
	public static int typeOf(String t) 
	{

		int type = 0;
		for(int i=0 ; i< TYPENAMES.length; i++) {
			if(TYPENAMES[i].equalsIgnoreCase(t)) {
				type = i;
				break;
			}
		}

		if( type == 0 ) {
			if( t.equalsIgnoreCase("any") ) {
				type = DNS.QTYPE_ALL;
			}
		}

		return type;

	}
}
