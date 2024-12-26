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
This class represents a DNS String as described in RFC 1035 (a lable with a max length of 255, used in HINFO & MINFO)
**/
public class DnsString {

		String string="";

	/**
	Default constructor (create an empty String)
	**/
		public DnsString() {}
	/**
	Construct a DnsString from a Java String
	**/
		public DnsString(String n) { 
				setString(n);
		}
	/**
	Construct a DnsString from a ByteBuffer
	**/
		public DnsString(ByteBuffer in) {
				int cnt = in.next();
				StringBuffer sb = new StringBuffer(cnt);
				for(int i=0; i< cnt; i++) {
						sb.append((char)in.next());
				}
				string = sb.toString();
		}
	/**
	Set the DnsString value from a Java String value
	**/
		public void setString(String n) {
				string = n;
		}
/**
Size of the DnsString (including the size octet)
@return size of this DnsString 
**/
public int size() 
{
	return string.length()+1;
}
/**
	Write this DnsSting into a Byte Buffer
**/
public void  toByteArray(ByteBuffer in) 
{
	in.setByte((byte)string.length());
	in.setBytes(string.getBytes());
}
	/**
	Convert to a Java String
	**/
public String toString() 
{
	return string;
}
}
