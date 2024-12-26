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

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

import us.bringardner.net.dns.ByteBuffer;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.Utility;
import us.bringardner.net.dns.resolve.QueryData;
/**
 * 
 * Creation date: (8/26/2001 10:41:48 AM)
 * @author: Tony Bringardner
 */
public class TCPProsessor extends DnsRequestProcessor implements Runnable {
	private static Object syncLok = new Object();
	//  Used for synchronization of the TCP Socket
	private static ServerSocket serverSocket;

	//  How to reply to the client;
	private InetAddress client;
	//private int port;

	//private int myNumber = 0;
	//private boolean running = false;
	public static boolean debug = false;

	
	private Socket clientSock;	

/**
 * 
 * Creation date: (8/26/2001 11:37:51 AM)
 * @param me int
 */
public TCPProsessor(DnsServer svr, int me) {
	server   = svr;
}

public synchronized static void initTCPProsessor(int bindPort,int backlog,InetAddress bindAddress, int timeout) throws IOException {
	
		serverSocket = new ServerSocket(bindPort,backlog,bindAddress);
		serverSocket.setSoTimeout(timeout);
	
}

/**
 * The UDP Server will sync on the lock object then
 * block on a UDP read.  All other UDPServers will block
 * on the sync until this guy is done.
 **/
public void run ()
{
	if( serverSocket == null ) {
		log("Can't run without init");
		setState("No socket, can't run");
		return;
	}

	setState("Running Enter");
	byte [] sz = new byte[2];	
	byte [] data = null;
	int len=0;
	ByteBuffer buf = null;
	
	//running = true;
	boolean doit = true;

	
	while( !DnsServer.isShutdown())  {
		setState("Running Begin");

		//  Make sure things are cleaned up from last run
		if( clientSock != null ) {
			try { clientSock.close(); } catch(Exception e) {}
			clientSock = null;
		}
		
		try {
			// Get control
			setState("Running before sync");
			synchronized (syncLok) {
				setState("Running after sync");
				
				// wait for a req
				if( !DnsServer.isShutdown() ) {
						doit = true;
						clientSock = serverSocket.accept();
				} else {
						doit = false;
				}
				
			}
		} catch(InterruptedIOException ex) {
			// Timed out
			doit = false;
			setState("Running Timed Out, doit="+doit);
		} catch(Exception ex) {
			log("Exception in TCP sock.accept()",ex);
			doit = false;
			setState("Running Exception?, doit="+doit);
		}

		setState("Running After Control Block, doit="+doit);
		if( doit ) {
			
			try {
				setState("Running Begin doit");
				log("New TCP Connection");
				//TODO:  Research and fix  Timeout set to 2 min as per RFC1035
				clientSock.setSoTimeout(2*60*1000);

				InputStream in = clientSock.getInputStream();
				//OutputStream out = clientSock.getOutputStream();
				client = clientSock.getInetAddress();

				boolean done = false;
			
			// Client may send multiple req	
			while (!done ) {
				try {
					// 16bit size comes in first
					Message.readArray(in,sz);	
					len = Utility.makeShort(sz[0], sz[1]);
					data = new byte[len];
					Message.readArray(in,data);		
					buf = new ByteBuffer(data);
				
					if ( debug ) {
						buf.dump();
					}
					Message msg = new Message(buf);
					QueryData query = new QueryData(client,-1,msg);
					process(query);
				} catch(IOException ex) {
					done=true;			
				}
			}
				
			} catch(Exception ex) {
				log("Unexpected exception in TCPProcessor.run",ex);
				setState("Running Exception go again");				
				if( buf != null ) {
					ex.printStackTrace(UDPProsessor.dumpBuf);
					UDPProsessor.dumpBuf.println("TCP Exception "+client);
					buf.dump(UDPProsessor.dumpBuf);
				}

			}
		}
		setState("Running End Loop");
	}
	setState("Running Exit");
}
/**
 * 
 * Creation date: (8/26/2001 10:41:48 AM)
 * @param msg JDns.Message
 */
public void sendResponse(Message msg) 
{
	setState("SendResponse Begin");

	if( msg != null ) {
		try {
			OutputStream out = clientSock.getOutputStream();
			byte [] data = msg.toByteArray();	
			byte [] sz = new byte[2];
			Utility.setShort(sz,0,data.length);

			//  16bit size goes out first
			out.write(sz);
			out.write(data);
			out.flush();

			if( UDPProsessor.dumpBuf != null ) {
				UDPProsessor.dumpBuf.println("TCP("+clientSock+")->"+msg.toSmallString());
			}
		} catch(IOException ex) {
			log("IOException sending reply",ex);
			setState("IOError");
		}
	}
	
	setState("SendResponse End");
}
}
