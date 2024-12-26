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

import java.util.*;

import us.bringardner.net.dns.*;
import us.bringardner.net.dns.resolve.QueryData;
/**
 * 
 * Creation date: (8/26/2001 7:01:49 AM)
 * @author: Tony Bringardner
 */
public abstract class DnsRequestProcessor  extends DnsBaseClass implements DNS
{
	DnsServer server;
/**
 * Process an incoming request (Search for the query then call sendResponse).
 **/
 public void process(QueryData query) {

	int tryCnt = 0;
	boolean done = false;
	setState("Processing Message Begin");
	while ( !done ) {
		try {
			setState("Processing Message before query tryCnt="+tryCnt);
			String name = query.getQuestion().getName();
			setState("Processing Message before query tryCnt="+tryCnt+" with name="+name);
			List<Message> reply = server.query(query);
			if( reply != null ) {
				int sz = reply.size();
				setState("Processing Message after query sz="+sz);

				for(int i=0; i< sz ; i++ ) {
					setState("Processing Message before sendResponse i="+i);
					sendResponse((Message)reply.get(i));
					setState("Processing Message after sendResponse i="+i);
				}
			}
			done = true;
		} catch(OutOfMemoryError ex) {
			setState("Processing Message OutOfMEmory tryCnt="+tryCnt);			
			tryCnt++;
			switch(tryCnt) {
				case 1:	setState("Processing Message Before RemoveOld tryCnt="+tryCnt);
						us.bringardner.net.dns.resolve.Resolver.removeOld();
						setState("Processing Message After RemoveOld tryCnt="+tryCnt);
						break;
				case 2: setState("Processing Message Before RemoveOld tryCnt="+tryCnt);
						us.bringardner.net.dns.resolve.Resolver.removeOld();
						setState("Processing Message After RemoveOld tryCnt="+tryCnt);
						break;
				default:
						setState("Processing Message Calling Exit! tryCnt="+tryCnt);
						System.exit(1);
			}
		}
	}

	setState("Processing Message Complete");
			
	 
 }
/**
 * Insert the method's description here.
 * Creation date: (8/26/2001 7:03:38 AM)
 * @param msg JDns.Message
 */
public abstract void sendResponse(Message msg);
}
