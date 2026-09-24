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

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.PrintStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

import us.bringardner.net.dns.ByteBuffer;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.DnsFormatException;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.resolve.QueryData;
/**
 * 
 * Creation date: (8/26/2001 10:41:48 AM)
 * @author: Tony Bringardner
 */
public class UDPProsessor extends DnsRequestProcessor implements Runnable
{
	private static final String PROP_UDP_DUMP_FILE = "JDns.dump.file";

	//  Used for syncronization of the UDP Socket
	private static DatagramSocket sock;

	//  How to reply to the client;
	private InetAddress client;
	private int port;

	//private int myNumber = 0;
	//private boolean running = false;
	private long timer=0;
	public static volatile boolean debug = false;
	public static PrintStream dumpBuf;
	
/**
 * Insert the method's description here.
 * Creation date: (8/26/2001 11:37:51 AM)
 * @param me int
 */
public UDPProsessor(DnsServer svr, int me) 
{
	//myNumber = me;
	server   = svr;
}
/**
 * Insert the method's description here.
 * Creation date: (10/16/2003 9:24:08 AM)
 * @return java.net.DatagramSocket
 */
public static java.net.DatagramSocket getSock() {
	return sock;
}

public synchronized static void initUDPProsessor(int bindPort,InetAddress bindAddress,int timeout) throws IOException
{
	
		sock = new DatagramSocket(bindPort,bindAddress);
		sock.setSoTimeout(timeout);

		String dumpFile = System.getProperty(PROP_UDP_DUMP_FILE);
		if( dumpFile != null && !dumpFile.equals("null")) {
			dumpBuf = new PrintStream(new FileOutputStream(dumpFile));
		}		
	
}
/**
 * The UDP Server will sync on the lock object then
 * block on a UDP read.  All other UDPServers will block
 * on the sync until this guy is done.
 **/
public void run ()
{
	if( sock == null ) {
		log("Can't run without init");
		setState("Can't run, no socket");
		return;
	}
	setState("Running Enter");
	
	byte [] data = null;
	DatagramPacket recPckt = null;
	
	//running = true;
	boolean doit = true;
	
	while( !DnsServer.isShutdown()) {
		setState("Running startLoop");
		
		try {

			data = new byte[MAXUDPLEN];
			recPckt = new DatagramPacket(data,data.length);

			// Get control
			setState("Running before sync");			
			synchronized (sock) {
				setState("Running after sync");			
				// wait for a req
				if( !DnsServer.isShutdown())  {
					doit = true;
					sock.receive(recPckt);
					timer = System.currentTimeMillis();
				} else {
					doit = false;
				}
				setState("Running after sock.rec doit="+doit);
			}
		} catch(InterruptedIOException ex) {
			//  Timed out
			doit = false;
			setState("Running Timeout doit="+doit);
		} catch(Exception ex) {
			//log("Exception in UDP sock.receive(recPckt)",ex);
			doit = false;
			setState("Running Error doit="+doit);
		}

		ByteBuffer buf = null;
		if( doit ) {
			try {
				setState("Running Begin processing doit="+doit);
				
				client = recPckt.getAddress();
				port = recPckt.getPort();
				
				buf = new ByteBuffer(recPckt.getData());
				if ( debug ) {
					buf.dump();
				}
				Message msg = new Message(buf);
				setState("Running before process");
				QueryData query = new QueryData(client,port,msg);
				if( msg.getQuestionCount()>0) {
					process(query);
				}
				setState("Running after process");
			} catch(DnsFormatException ex) {
				// Malformed packet (e.g. compression loop). Answer FORMERR and keep going.
				setState("Running format error");
				if( DnsServer.isDebug() ) {
					log("Malformed UDP packet from "+client+":"+port+" "+ex.getMessage());
				}
				sendFormatError(recPckt.getData(), recPckt.getLength());
			} catch(StackOverflowError ex) {
				// Never let a single packet kill this worker thread
				log("StackOverflowError processing UDP packet from "+client+":"+port);
				setState("Running StackOverflowError");
			} catch(Exception ex) {
				log("Unexpected exception in UDPPRocessor.run",ex);
				setState("Running error from process");
				if( buf != null && dumpBuf != null) {
					ex.printStackTrace(dumpBuf);
					dumpBuf.println("Packet length ="+recPckt.getLength());
					buf.dump(dumpBuf);
				}

			}
		}
	}
	
	setState("Running End");
}
/**
 * Reply FORMERR (RFC 1035 4.1.1, RCODE 1) to a request that could not be parsed.
 * Only the 12 byte header is echoed (ID, opcode and RD are preserved), with no question.
 * Nothing is sent if the packet is shorter than a header or is itself a response
 * (QR set), so we can't be used to bounce garbage back and forth.
 */
void sendFormatError(byte [] packet, int length) {
	byte [] reply = buildFormatError(packet, length);
	if( reply == null ) {
		return;
	}
	try {
		sock.send(new DatagramPacket(reply,reply.length,client,port));
	} catch(IOException ex) {
		log("IOException sending FORMERR",ex);
	}
}

/**
 * Build a FORMERR reply header for a malformed request, or null if none should be sent.
 */
public static byte [] buildFormatError(byte [] packet, int length) {
	if( packet == null || length < 12 || (packet[2] & 0x80) != 0 ) {
		return null;
	}
	byte [] reply = new byte[12];
	reply[0] = packet[0];                                // ID
	reply[1] = packet[1];
	reply[2] = (byte)(0x80 | (packet[2] & 0x79));        // QR=1, keep OPCODE and RD, clear AA/TC
	reply[3] = (byte)DNS.FORMAT_ERROR;                   // RA=0, Z=0, RCODE=1
	// QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT all zero
	return reply;
}

/**
 * Insert the method's description here.
 * Creation date: (8/26/2001 10:41:48 AM)
 * @param msg JDns.Message
 */
public void sendResponse(Message msg) 
{
	
	setState("SendResponse Begin");

	if( msg != null ) {
		byte [] data = msg.toByteArray();
		int dataSize = data.length;
	
		/*
		 TODO: What should happen here?
		if( data.length > MAXUDPLEN ) {
			msg.truncateOn();
			data = msg.toByteArray();;
			dataSize = MAXUDPLEN;
		}
		 */
		setState("SendResponse getPacket");
		DatagramPacket pckt = new DatagramPacket(data,dataSize,client,port);
	
		setState("SendResponse gotPacket");
		try {
			setState("SendResponse before sock.send");
			sock.send(pckt);
			setState("SendResponse after sock.send");
		
			if( DnsServer.isDebug() ) {
				log("Reply Sent ("+msg.getFirstQuestion()+") time="+(System.currentTimeMillis()-timer));
			}
		
			if( dumpBuf != null ) {
				dumpBuf.println("UDP("+client+":"+port+")->"+msg.toSmallString());
			}

		} catch(IOException ex) {
			log("IOException sending reply",ex);
			setState("SendResponse IOError");
		}
	}
	setState("SendResponse End");
		
}
}
