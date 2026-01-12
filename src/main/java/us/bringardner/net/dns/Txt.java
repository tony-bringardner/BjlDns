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

import java.util.ArrayList;
import java.util.List;

/**
This class implements a DNS PTR Resource Record as described in RFC 1035
 **/
public class Txt extends RR {

	//  This is the rdata
	String text ;

	/**
		Default Constructor
	 **/
	public Txt() {
		super();
		setType(TXT);
		setDnsClass(IN);
		isBase = false;
		dirty = true;
	}

	/**
	Construct a PTR and assign the RR.name from a parameter
	 **/
	public Txt(String name) {
		super(name,TXT,IN);
		isBase = false;
		dirty = true;
	}

	/**
	Construct a TXT and assign the RR.name and RR.dnsClass from a parameter
	 **/
	public Txt(String name, int dnsClass) {
		super(name,TXT,dnsClass);
		isBase = false;
		dirty = true;
	}

	/**
	Construct a PTR from an RR
	 **/
	public Txt(RR rr) {
		super(rr);
		isBase = false;
		dirty = true;
		setFromRdata();
	}

	/*
	Make a copy of the RR
	 */
	public RR copy() {
		Txt ret = new Txt();
		copy(ret);
		ret.text = text;

		return ret;
	}

	/**
	Convert to a Java String
	 **/
	public  String getRdataAsString(){
		return text.toString(); 
	}

	/**
	Get the String representation of the PTR value
	 **/
	public String getText() { 
		return text.toString(); 
	}

	public void setFromRdata() {
		if( text == null ) {
			ByteBuffer in = new ByteBuffer(getRdata());
			if( source != null) {
				in = new ByteBuffer(source.getBuf(),sourcePos);
			}
			int sz = rdlength;
			int pos = 0;
			StringBuilder buf = new StringBuilder();
			while(pos<sz) {
				pos++;
				int chunkLen = in.next();
				for(int cnt=0; cnt < chunkLen; cnt ++) {
					buf.append((char)in.next());
					pos++;
				}
			}			
			text = buf.toString();
			dirty = false;
		}
	}

	/**
	Set the PTR value from a Java String 
	 **/
	public void setText(String text) { 
		this.text = (text);
		String tmp = text;
		
		List<String> chuncks = new ArrayList<>();
		while(tmp.length()> 200) {
			String val = tmp.substring(0,200);
			tmp = tmp.substring(200);
			chuncks.add(val);
		}
		if( !tmp.isEmpty()) {
			chuncks.add(tmp);
		}
		
		ByteBuffer buf = new ByteBuffer();
	
		for(String chunck : chuncks) {
			//TXT Length	1-byte Integer	Length of TXT string.
			buf.setByte((byte)chunck.length());
			//TXT	String	The character-string.
			buf.setBytes(chunck.getBytes());
		}
		
		rdata = buf.getByteArray();		
		rdlength = rdata.length;
		
		dirty = false;


	}

	public void toByteArray(ByteBuffer in) {
		super.toByteArray(in);
		if( dirty) {
			throw new RuntimeException("Txt is dirty");
		}
		in.setBytes(rdata);
	}

	/**
	Convert to a Java String
	 **/
	public  String toString() { 
		return super.toString()+" "+text.toString(); 
	}

}
