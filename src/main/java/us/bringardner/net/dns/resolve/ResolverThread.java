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

import java.io.IOException;
import java.net.*;

import us.bringardner.net.dns.*;

/**
 * These threads do recursive resolution and prevent the server from getting backed up.
 * Creation date: (10/15/2003 5:23:16 PM)
 * @author: Tony Bringardner
 */
public class ResolverThread extends us.bringardner.net.dns.DnsBaseClass implements Runnable 
{
	private static final String PROP_RESOLVER_BACKLOG = "Resolver.maxBacklog";
	private static SimpleObjectFIFO fifo;
	private Thread thread;
	private boolean running = false;


	private DatagramSocket sock;

	static {
		initResolverThread();
	}

	/**
	 * ResolverThread constructor comment.
	 */
	public ResolverThread() throws SocketException {
		super();
		sock = us.bringardner.net.dns.server.UDPProsessor.getSock();
	}
	
	public static void addQuery(QueryData query) {
		try {
			if( !fifo.isFull() ) {
				fifo.add(query);
			}
		} catch(Exception ex) {}
	}
	
	public static int backlog() {
		return fifo.getSize();
	}
	
	public static int getBacklog() {
		return fifo.getSize();
	}
	
	public static int getMaxBackLog() {
		return fifo.getCapacity();
	}
	
	private static void initResolverThread() {
		int maxBacklog = 20;

		String tmp = System.getProperty(PROP_RESOLVER_BACKLOG);

		if( tmp != null ) {
			try {
				maxBacklog = Integer.parseInt(tmp);
			} catch(Exception ex) {}
		}

		fifo = new SimpleObjectFIFO(maxBacklog);
	}
	
	public static void notifyThreads() {
		fifo.notifyAll();
	}
	
	/**
	 * When an object implementing interface <code>Runnable</code> is used 
	 * to create a thread, starting the thread causes the object's 
	 * <code>run</code> method to be called in that separately executing 
	 * thread. 
	 * <p>
	 * The general contract of the method <code>run</code> is that it may 
	 * take any action whatsoever.
	 *
	 * @see     java.lang.Thread#run()
	 */
	public void run() {

		running = true;

		while( running ) {
			try {
				setState("Waiting on fifo");
				QueryData question = (QueryData)fifo.remove();
				setState("Returned on fifo");
				if( running && question != null ) {
					setState("Call Resolver:"+question);
					us.bringardner.net.dns.Message msg = Resolver.resolve(question.getQuestion());
					setState("Returned from resolver");	
					if( msg != null ) {
						sendResponse(msg,question);
					}
				}
			} catch(Exception ex) {

				//  ignore them
			}
		}

		setState("Stopped");
		running = false;
	}
	
	/**
	 * 
	 * Creation date: (8/26/2001 10:41:48 AM)
	 * @param msg JDns.Message
	 */
	public void sendResponse(Message msg, QueryData query) {

		setState("SendResponse Begin");
		if( msg != null && query.getPort() != -1) {

			//  Just in case;
			msg.setID(query.getMessage().getID());

			byte [] data = msg.toByteArray();
			int dataSize = data.length;

			if( data.length > DNS.MAXUDPLEN ) {
				msg.truncateOn();
				data = msg.toByteArray();;
				dataSize = DNS.MAXUDPLEN;
			}

			setState("SendResponse getPacket");
			DatagramPacket pckt = new DatagramPacket(data,dataSize,query.getClient(),query.getPort());

			setState("SendResponse gotPacket");
			try {
				setState("SendResponse before sock.send");

				sock.send(pckt);
				setState("SendResponse after sock.send");	

			} catch(IOException ex) {
				log("IOException sending reply",ex);
				setState("SendResponse IOError");
			}
		}
		setState("SendResponse End");
	}
	
	public void start(String name) {
		if( !running ) {
			thread = new Thread(this);
			thread.setName(name);
			thread.start();
			setState("Started");
		}
	}
	
	public void stop() {
		running = false;
		thread.interrupt();
	}
	
}
