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

import java.net.InetAddress;

import us.bringardner.net.dns.Edns;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.Section;

/**
 * 
 * Creation date: (10/15/2003 5:40:14 PM)
 * @author: Tony Bringardner
 */
public class QueryData 
{
		//  How to reply to the client;
	private InetAddress client;
	private int port;
	private Message msg;
	private Section question;
	private volatile Edns.Request edns;
	
/**
 * QueryData constructor comment.
 */
public QueryData() {
	super();
}
/**
 * QueryData constructor comment.
 */
public QueryData(InetAddress myClient, int myPort, Message myQuestion) 
{
	client = myClient;
	port = myPort;
	msg= myQuestion;
	question = (Section)msg.getQuestion().get(0);
	
	
}
/**
 * Insert the method's description here.
 * Creation date: (10/16/2003 7:29:26 AM)
 * @return java.net.InetAddress
 */
public Edns.Request getEdns() {
	Edns.Request ret = edns;
	if( ret == null ) {
		ret = Edns.parse(msg);
		edns = ret;
	}
	return ret;
}
/**
 * Insert the method's description here.
 * Creation date: (10/16/2003 7:29:26 AM)
 * @return java.net.InetAddress
 */
public java.net.InetAddress getClient() {
	return client;
}
public Message getMessage()
{
	return msg;
}
/**
 * Insert the method's description here.
 * Creation date: (10/16/2003 7:29:26 AM)
 * @return int
 */
public int getPort() {
	return port;
}
/**
 * Insert the method's description here.
 * Creation date: (10/16/2003 7:29:26 AM)
 * @return JDns.Section
 */
public us.bringardner.net.dns.Section getQuestion() {
	return question;
}
/**
 * Insert the method's description here.
 * Creation date: (10/16/2003 7:29:26 AM)
 * @return JDns.Section
 */
public void setQuestion(Section myQuestion) 
{
	question = myQuestion;
}

//  A CNAME in our zones pointed outside them: the name still to resolve,
//  and the answer built so far (the CNAME chain) to complete with it.
private volatile Section cnameTarget;
private volatile Message partialAnswer;

/** The out-of-zone name a local CNAME chain ended at, or null. */
public Section getCnameTarget() {
	return cnameTarget;
}

public void setCnameTarget(Section target) {
	cnameTarget = target;
}

/** The authoritative part of the answer (CNAME chain) waiting for the resolver, or null. */
public Message getPartialAnswer() {
	return partialAnswer;
}

public void setPartialAnswer(Message partial) {
	partialAnswer = partial;
}

/** What the resolver should look up: the pending CNAME target if there is one, else the question. */
public Section getResolveQuestion() {
	Section t = cnameTarget;
	return t != null ? t : question;
}

/** Maximum number of CNAMEs followed for one query (server and resolver). */
public static final int MAX_CNAME_CHAIN = 8;

//  Names already visited while following CNAMEs for this query (lower case)
private java.util.Set<String> cnameSeen;
private int cnameCount = 0;

/**
 * Record that we are about to follow a CNAME to 'target'.
 * 
 * @return false if following it would loop (target already visited, including
 * the original question name) or the chain is longer than MAX_CNAME_CHAIN.
 */
public synchronized boolean followCname(String target) {
	if( cnameSeen == null ) {
		cnameSeen = new java.util.HashSet<String>();
		if( question != null ) {
			cnameSeen.add(question.getName().toLowerCase());
		}
	}
	if( target == null || cnameCount >= MAX_CNAME_CHAIN ) {
		return false;
	}
	if( !cnameSeen.add(target.toLowerCase()) ) {
		return false;
	}
	cnameCount++;
	return true;
}

/** Number of CNAMEs followed so far. */
public synchronized int getCnameCount() {
	return cnameCount;
}
}
