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

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A TXT record (RFC 1035 3.3.14): one or more character-strings of up to
 * 255 bytes each. The strings are kept apart: "a" "b" is two strings, as
 * it is on the wire and in a zone file (they used to be joined into one,
 * and a zone file line kept only the first). Text is UTF-8 on the wire.
 **/
public class Txt extends RR {

	/** The character-strings (no initializer: super(rr) sets them first) */
	List<String> strings;

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
	Construct a TXT and assign the RR.name from a parameter
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
	Construct a TXT from an RR
	 **/
	public Txt(RR rr) {
		super(rr);
		isBase = false;
		//  rdata holds the wire bytes, which are valid (and are what is sent on)
		strings = null;
		setFromRdata();
		dirty = false;
	}

	/*
	Make a copy of the RR
	 */
	public RR copy() {
		Txt ret = new Txt();
		copy(ret);
		ret.strings = strings;

		return ret;
	}

	/**
	The text: the strings joined (without separators)
	 **/
	public  String getRdataAsString(){
		return getText(); 
	}

	/**
	 * The text: the strings joined without separators (a long text split
	 * into 255 byte strings comes back whole).
	 */
	public String getText() { 
		return strings == null ? "" : String.join("", strings); 
	}

	/** The character-strings, in order. */
	public List<String> getStrings() {
		return strings == null ? new ArrayList<String>() : Collections.unmodifiableList(strings);
	}

	public void setFromRdata() {
		if( strings == null ) {
			byte [] data = getRdata();
			if( data == null && source == null ) {
				return;
			}
			ByteBuffer in = data != null ? new ByteBuffer(data) : new ByteBuffer(source.getBuf(),sourcePos);
			int sz = rdlength;
			int pos = 0;
			List<String> ret = new ArrayList<String>();
			while(pos<sz) {
				pos++;
				int chunkLen = in.next() & 0xff;
				byte [] b = new byte[Math.max(0, Math.min(chunkLen, sz-pos))];
				for(int cnt=0; cnt < b.length; cnt ++) {
					b[cnt] = (byte)in.next();
				}
				pos += chunkLen;
				ret.add(new String(b, StandardCharsets.UTF_8));
			}
			strings = ret;
			dirty = false;
		}
	}

	/**
	 * Set one text; one longer than 255 bytes is split into several strings.
	 */
	public void setText(String text) { 
		setStrings(Collections.singletonList(text == null ? "" : text));
	}

	/**
	 * Set the character-strings; one longer than 255 bytes (UTF-8) is split
	 * into several (between characters).
	 */
	public void setStrings(List<String> list) {
		List<String> chunks = new ArrayList<>();
		ByteBuffer buf = new ByteBuffer();
		for(String s : list) {
			if( s == null ) {
				s = "";
			}
			int start = 0;
			do {
				//  As many characters as fit in 255 bytes
				int end = start;
				int bytes = 0;
				while( end < s.length() ) {
					int cp = s.codePointAt(end);
					int n = new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8).length;
					if( bytes+n > 255 ) {
						break;
					}
					bytes += n;
					end += Character.charCount(cp);
				}
				String chunk = s.substring(start, end);
				byte [] b = chunk.getBytes(StandardCharsets.UTF_8);
				//TXT Length	1-byte Integer	Length of TXT string.
				buf.setByte((byte)b.length);
				//TXT	String	The character-string.
				buf.setBytes(b);
				chunks.add(chunk);
				start = end;
			} while( start < s.length() );
		}
		strings = chunks;
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
		return super.toString()+" "+getText(); 
	}

}
