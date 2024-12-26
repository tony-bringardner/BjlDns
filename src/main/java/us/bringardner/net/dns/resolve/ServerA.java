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
package us.bringardner.net.dns.resolve;

import java.net.*;

import us.bringardner.net.dns.*;

public class ServerA  extends DnsBaseClass
{
	//  One Hour
	public static long DEACTIVATE=(1*60*60*1000);  
	public static int MAX_TRIES=2;
	private int msgSent = 0;
	private int msgRec  = 0;
	//private int ave 	= 0;
	private int totResp = 0;
	private long lastReq = 0;
	private String name;
	private String addrStr;
	private InetAddress addr;
	private Message qm;
	private boolean active= true;
	private int tries=0;



	/**
	 * Constructor for ServerA
	 */
	public ServerA(String n, String addr) {
		setName(n);
		if( addr != null ) {
			setAddress(addr);
		} else {
			System.out.println("no adr for "+name);
			setAddress(n);
		}
	}
	
	/**
	 * Constructor for ServerA
	 */
	public ServerA(A rr)  {
		setName( rr.getName());
		setAddress(rr.getAddressString());
	}

	public int aveResponseTime() { 
		return totResp/msgSent; 
	}
	
	public int battingAve() { 
		return msgSent / msgRec; 
	}
	
	/**
	 * 
	 * Creation date: (10/21/2001 6:31:18 AM)
	 * @return boolean
	 */
	public boolean isActive() {

		if(!active ) {
			active = (lastReq+DEACTIVATE) < System.currentTimeMillis();
		}

		return active;
	}

	public Message query(Section q) {
		/**
		 * If the server is inactive return null unless the deactive time has expired
		 * if it has then try again.  IF that try does not
		 * succeed it will remain inactive for another hour
		 **/
		if( !active && (lastReq+DEACTIVATE) < System.currentTimeMillis()) {
			return null;
		}


		if ( addr == null ) {
			return null;

			//  Address was not set when created
			/*
		Message m = Resolver.resolve(new Section(name,DNS.A,DNS.IN));
		if( m != null && m.getResponseCode() == DNS.NOERROR && m.getAdditionalCount() > 0 ) {
			Iterator ii = m.answer();
			RR a = null;
			while( ii.hasNext() ) {
				a = (RR)ii.next();
				if( a instanceof A ) {
					setAddress(((A)a).getAddressString());
				}
			}
		} else {
			return null;
		}
			 */
		}

		Message ret = null;
		lastReq = System.currentTimeMillis();
		msgSent++;

		try {
			qm.setQuestion(q);
			qm.setTimeOut(2000);
			qm.setRetry(1);
			//System.out.println("Try Server "+name);
			ret = qm.query();
		} catch(Exception ex) {}

		totResp += (System.currentTimeMillis()-lastReq);

		if( ret != null ) {
			msgRec++;
			tries = 0;
		} else {
			if( ++tries > MAX_TRIES ) {
				active = false;
			}
		}

		return ret;
	}

	/**
	 * 
	 * Creation date: (10/21/2001 6:31:18 AM)
	 * @param newActive boolean
	 */
	public void setActive(boolean newActive) {
		active = newActive;
	}

	public final void setAddress(String ip) {
		try {
			addrStr = ip;
			addr = InetAddress.getByName(ip);
			qm = new Message();
			qm.setServer(addr);
		} catch(Exception ex) {
			//  This should never throw an exception since we're using the IP address			
			//  So I'll just assume for the moment that there is nothing to do here
			log("Error setting addr in SearverA ip = "+ip,ex);
		}
	}
	
	public final void setName(String n) { 
		name = n; 
	}
	
	public String toString() {
		return (name == null ? "" : name)+"("+addrStr+") ";
	}
	
}
