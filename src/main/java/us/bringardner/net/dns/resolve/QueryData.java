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
}
