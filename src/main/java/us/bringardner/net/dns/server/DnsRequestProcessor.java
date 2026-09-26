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
	//  EDNS of the request being processed (process() runs one at a time per processor)
	protected Edns.Request currentEdns = Edns.Request.NONE;
	//  TSIG of the request being processed (null if it was not signed): sendResponse signs with it
	protected volatile Tsig.Session currentTsig;
/**
 * Process an incoming request (Search for the query then call sendResponse).
 **/
 public void process(QueryData query) {
	//  No OutOfMemoryError handling here any more: the old code trimmed the
	//  cache, retried, and finally called System.exit(1) from this thread.
	//  Caches are bounded now; a JVM error propagates to FatalErrorHandler.
	setState("Processing Message begin");
	Edns.Request edns = query.getEdns();
	currentEdns = edns;
	currentTsig = null;
	Tsig.Session tsig;
	try {
		tsig = Tsig.Session.verifyRequest(server.getTsigKeys(), query.getWire());
	} catch(DnsFormatException ex) {
		//  A TSIG that is not the last record, or a malformed one
		sendResponse(Edns.formatError(query.getMessage()));
		return;
	}
	if( tsig != null ) {
		currentTsig = tsig;
		if( tsig.getError() != Tsig.NOERROR ) {
			//  RFC 8945 5.2: NOTAUTH, with the TSIG error in the (unsigned or,
			//  for BADTIME, signed) TSIG of the response
			final int err = tsig.getError();
			log(() -> "TSIG error "+err+" for a request from "+query.getClient());
			sendResponse(notAuth(query.getMessage()));
			currentTsig = null;
			return;
		}
		query.setTsigKey(tsig.getKey().getName());
	}
	try {
		answer(query, edns);
	} finally {
		currentTsig = null;
	}
	setState("Processing Message Complete");
 }

 /** A NOTAUTH response to a request (its question, no records). */
 static Message notAuth(Message req) {
	Message ret = new Message();
	Header h = req.getHeader().copy();
	ret.setHeader(h);
	ret.setMessageTypeResponse();
	for(Section s : req.getQuestion()) {
		ret.setQuestion(s);
	}
	ret.getHeader().setRCODE(Tsig.NOTAUTH);
	return ret;
 }

 private void answer(QueryData query, Edns.Request edns) {
	if( edns.isMalformed() ) {
		//  RFC 6891 6.1.1: more than one OPT (or a bad one) is FORMERR
		sendResponse(Edns.formatError(query.getMessage()));
	} else if( edns.isBadVersion() ) {
		sendResponse(Edns.badVersion(query.getMessage()));
	} else {
		List<Message> reply = server.query(query);
		if( reply != null ) {
			for(Message m : reply) {
				Edns.applyToResponse(m, edns);
				sendResponse(m);
			}
		}
	}
 }
/**
 * Insert the method's description here.
 * Creation date: (8/26/2001 7:03:38 AM)
 * @param msg JDns.Message
 */
public abstract void sendResponse(Message msg);
}
