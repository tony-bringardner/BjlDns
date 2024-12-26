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
package us.bringardner.net.dns.server;

/**
 * 
 * Creation date: (10/13/2001 10:03:45 AM)
 * @author: Tony Bringardner
 */
public class Pointer {
	private String name;
	private String ip;
	private String arpa;
	private us.bringardner.net.dns.Ptr ptr;

	/**
	 * Pointer constructor comment.
	 */
	public Pointer(String newip, String newname) {
		ip=newip;
		name=newname;


		StringBuffer buf = new StringBuffer();
		int idx = ip.lastIndexOf('.');
		int idx2=ip.length();
		while( idx > 0 ) {
			buf.append(ip.substring(idx+1,idx2));
			buf.append('.');
			idx2=idx;
			idx = ip.lastIndexOf('.',idx2-1);
		}
		buf.append(ip.substring(0,idx2));
		buf.append(".in-addr.arpa");
		arpa = buf.toString();

		ptr = new us.bringardner.net.dns.Ptr(arpa);
		ptr.setPtr(name);
	}

	/**
	 * Insert the method's description here.
	 * Creation date: (10/13/2001 10:10:58 AM)
	 * @return java.lang.String
	 */
	public java.lang.String getArpa() {
		return arpa;
	}

	/**
	 * Insert the method's description here.
	 * Creation date: (10/13/2001 10:10:59 AM)
	 * @return java.lang.String
	 */
	public java.lang.String getIp() {
		return ip;
	}

	/**
	 * Insert the method's description here.
	 * Creation date: (10/13/2001 10:10:59 AM)
	 * @return java.lang.String
	 */
	public java.lang.String getName() {
		return name;
	}

	/**
	 * Insert the method's description here.
	 * Creation date: (10/13/2001 10:10:59 AM)
	 * @return JDns.Ptr
	 */
	public us.bringardner.net.dns.Ptr getPtr() {
		return ptr;
	}
}
