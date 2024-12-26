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

/*
This class implements the HINFO DNS Resource Record
*/
public class Hinfo extends RR {

		//  This is the rdata
		DnsString cpu = new DnsString("");
		DnsString os  = new DnsString("");

		public Hinfo() {
				super();
				setType(HINFO);
				setDnsClass(IN);
				isBase = false;
				dirty = true;
		}
		public Hinfo(String n, int c) {
				super(n,HINFO,c);
				isBase = false;
				dirty = true;
		}
		public Hinfo(RR rr) {
				super(rr);
				isBase = false;
		}
public RR copy()
{
	Hinfo ret = new Hinfo();
	super.copy(ret);
	ret.cpu = cpu;
	ret.os = os;

	return ret;
}
		public String getCpu() { 
				return cpu.toString(); 
		}
		public String getOs()  { 
				return os.toString();  
		}
public  String getRdataAsString()
{
	return cpu+" "+os;
}
		public void setCpu(String c) { 
				cpu = new DnsString(c);
				dirty = true;
		}
		public void setFromRdata() {
				ByteBuffer in = new ByteBuffer(getRdata());
				if( source != null ) {
						in = new ByteBuffer(source.getBuf(),sourcePos);
				}
				cpu = new DnsString(in);
				os  = new DnsString(in);
		}
		public void setOs(String c) { 
				os  = new DnsString(c);
				dirty = true;
		}
public void toByteArray(ByteBuffer in) 
{
		super.toByteArray(in);
		cpu.toByteArray(in);
		os.toByteArray(in);
		in.setRdLength();
}
		public  String toString() { 
						return super.toString()+" "+cpu+" "+os;
		}
}
