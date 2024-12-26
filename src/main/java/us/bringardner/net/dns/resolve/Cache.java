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

import java.util.*;

import us.bringardner.net.dns.*;


public class Cache extends DnsBaseClass
{
	private static long defaultMaxAge = 1000*60*30;

	private Map<String, Message> cache = new HashMap<String, Message>(50);


	public Cache() {
	}


	public Message get(Section question) {
		String key = getKey(question);

		Message ret = null;

		synchronized (cache) {
			ret = (Message)cache.get(key);
		}


		if( ret != null ) {
			//  Check to see if these RR's are still good
			removeExpired(ret);
			if( ret.getAnswerCount() == 0 ) {
				synchronized (cache) {
					cache.remove(key);	
				}			
				ret = null;
			} else {
				ret.setInitTime(System.currentTimeMillis());
			}
		} 

		return ret;
	}

	/**
	 * 
	 * Creation date: (10/13/2003 5:50:23 PM)
	 * @return long
	 */
	public static long getDefaultMaxAge() {
		return defaultMaxAge;
	}
	
	public static String getKey(Section question) {
		String key = (question.getName()+
				question.getType()+
				question.getDnsClass());
		return key;
	}
	
	//  Add this message to our cache
	public void put(Message msg) {

		if( msg == null || msg.getQuestionCount() == 0 ) {
			return;
		}

		msg.setInitTime(System.currentTimeMillis());
		String key = getKey(msg.getFirstQuestion());

		synchronized (cache) {
			cache.put(key,msg);	
		}

	}
	
	//Remove all expired RRs from this list
	private void removeExpired(List<RR> lst ){
		RR rr = null;

		int sz = lst.size();
		for(int i=sz-1; i>=0; i-- ) {
			rr = (RR)lst.get(i);
			if( rr.hasExpired() ) {
				lst.remove(i);
			}
		}
	}

	//  Remove all expired RRs from this message
	private void removeExpired(Message ret) {
		removeExpired(ret.getAnswer());
		removeExpired(ret.getAuthority());
		removeExpired(ret.getAdditional());
	}

	//  Remove any message older than this time

	public void removeOld() {
		removeOld(defaultMaxAge);	
	}

	//  Remove any message older than this time
	public void removeOld(long time) {

		Message msg = null;
		long now = System.currentTimeMillis();
		String key = null;


		synchronized (cache) {

			final Iterator<String> it = cache.keySet().iterator();

			while( it.hasNext()) {
				key = it.next().toString();
				msg = (Message)cache.get(key);
				if( msg != null ) {
					if( (now - msg.getInitTime() ) > time ) {
						it.remove();
						log("Removed "+key+" from cache becouse it's old");
						//System.out.println("Removed "+key+" from cache becouse it's old");
					}
				}
			}
		}
	}

	/**
	 * 
	 * Creation date: (10/13/2003 5:50:23 PM)
	 * @param newDefaultMaxAge long
	 */
	public static void setDefaultMaxAge(long newDefaultMaxAge) {
		defaultMaxAge = newDefaultMaxAge;
	}
	
	//  Add this message to our cache
	public int size() {
		int ret = -1;

		synchronized (cache) {
			ret = 	cache.size();
		}
		return ret;
	}
}
