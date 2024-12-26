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
 * ~version~V000.01.02-V000.00.05-V000.00.00-
 */
package us.bringardner.net.dns;

/*
	Copyright Tony Bringardner 1999, 2000
 */
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import us.bringardner.core.BjlLogger;
import us.bringardner.core.ILogger;
import us.bringardner.core.ILogger.Level;

/**
	This class manages a DNS Message.
 **/
public class Message extends Utility {
	private long initTime;
	private boolean udp   = true;;
	private boolean defname   = false;
	private int qtype = A;
	private int dnsClass = IN;
	private int port = DNSPORT;
	private int retry = 4;
	private int timeOut = 3000;
	private String domain = "";



	private Header hdr = new Header();
	private List<Section> que = new ArrayList<Section>() ; // Question section (QD)
	private List<RR> ans = new ArrayList<RR>(); //  Answer Section (AN)
	private List<RR> ath = new ArrayList<RR>(); //  Authoritative (NS)
	private List<RR> add = new ArrayList<RR>(); //  Additional info (AR)
	private Map<String, List<RR>> all = null; //  All RRs
	private String server = "dns.minemall.com";
	//  For use in query (getaddress of server name)
	private InetAddress svrAddress;    
	//  Store the result of toByteArray so that size can function
	private byte [] data = null;      
	private int dataSize=0;

	public Message() {
		super();
	}

	public Message(ByteBuffer in) {
		buildMessage(in);
	}

	/**
	 * 
	 * @return a copy of this message with everything needed to do a query but no response data.
	 */
	public Message copy(){
		Message ret = new Message();
		ret.qtype = qtype;
		
		ret.dnsClass = dnsClass;
		ret.timeOut = timeOut;
		ret.udp = udp;
		ret.port = port;
		ret.retry = retry;
		ret.server = server;
		ret.svrAddress = svrAddress;
		ret.setLogger(getLogger());
		for(Section s: que) {
			ret.que.add(s);
		}
		
		return ret;
	}
	public final void addAdditional(RR rr){ 
		add.add(rr); 
	}

	public final void addAnswer(RR rr)    { 
		ans.add(rr); 
	}

	public final void addAuthority(RR rr) { 
		ath.add(rr); 
	}

	public final Iterator<RR> additional () {
		return add.iterator();
	}

	public final void addQuestion(String name) {
		addQuestion(new Section(name));
	}

	public final void addQuestion(String name, int type, int dnsClass) {
		addQuestion(new Section(name,type,dnsClass));
	}

	public final void addQuestion(String name, int type, String dnsClass) {
		addQuestion(new Section(name,type,dnsClass));
	}

	public final void addQuestion(String name, String type, int dnsClass) {
		addQuestion(new Section(name,type,dnsClass));
	}

	public final void addQuestion(String name, String type, String dnsClass) {
		addQuestion(new Section(name,type,dnsClass));
	}

	public final  void addQuestion(Section rr)  { 
		que.add(rr); 
	}

	private void addToAll(Iterator<RR> it)    {
		List<RR> lst = null;
		String key = null;
		RR rr = null;

		while(it.hasNext()) {
			rr = (RR)it.next();
			key = rr.getName().toLowerCase();	
			if( (lst=(List<RR>)all.get(key) ) == null ) {
				lst = new ArrayList<RR>();
				all.put(key,lst);
			}
			lst.add(rr);
		}
	}

	public final Iterator<List<RR>> allReacords () {
		Map<String, List<RR>> all = getAll();
		Iterator<List<RR>> ret = all.values().iterator();

		return ret;
	}


	public final Iterator<RR> answer () {
		return ans.iterator();
	}

	public final Iterator<RR> authority () {
		return ath.iterator();
	}

	/*
AA              Authoritative Answer - this bit is valid in responses,
                and specifies that the responding name server is an
                authority for the domain name in question section.

                Note that the contents of the answer section may have
                multiple owner names because of aliases.  The AA bit

                corresponds to the name which matches the query name, or
                the first owner name in the answer section.
	 */

	public final void authorityOff() { 
		hdr.setAA(false); 
	}

	/*
AA              Authoritative Answer - this bit is valid in responses,
                and specifies that the responding name server is an
                authority for the domain name in question section.

                Note that the contents of the answer section may have
                multiple owner names because of aliases.  The AA bit

                corresponds to the name which matches the query name, or
                the first owner name in the answer section.
	 */
	public final void authorityOn() { 
		hdr.setAA(true); 
	}

	private void buildMessage(ByteBuffer in) {
		hdr = new Header(in);

		int cnt = hdr.getQDCOUNT();
		for(int i=0; i< cnt; i++) {
			que.add(new Section(in));
		}
		cnt = hdr.getANCOUNT();
		for(int i=0; i< cnt; i++) {
			ans.add(RR.parseRR(in));
		}
		cnt = hdr.getNSCOUNT();
		for(int i=0; i< cnt; i++) {
			ath.add(RR.parseRR(in));
		}
		cnt = hdr.getARCOUNT();
		for(int i=0; i< cnt; i++) {
			add.add(RR.parseRR(in));
		}
	}

	/**
	 * Combine the answer, auth and add section from msg into this
	 **/
	public final void combine(Message msg){
		Iterator<RR> i = msg.answer();
		while(i.hasNext()) {
			ans.add(i.next());
		}
		i = msg.authority();
		ath = new ArrayList<RR>();
		while(i.hasNext()) {
			ath.add(i.next());
		}
		i = msg.additional();
		add = new ArrayList<RR>();
		while(i.hasNext()) {
			add.add(i.next());
		}

	}

	public final void debugOff() { 
		getLogger().setLevel(Level.INFO);
	}

	public final void debugOn() { 
		getLogger().setLevel(Level.DEBUG);
	}

	public final void defnameOff() { 
		defname = false; 
	}

	public final void defnameOn() {
		defname = true; 
	}

	
	
	
	public int getQtype() {
		return qtype;
	}

	public void setQtype(int qtype) {
		this.qtype = qtype;
	}

	public int getDnsClass() {
		return dnsClass;
	}

	public void setDnsClass(int dnsClass) {
		this.dnsClass = dnsClass;
	}

	public final List<RR> getAdditional() { 
		return add; 
	}

	/**
	How many additional records
	 **/
	public final int getAdditionalCount() { 
		return add.size(); 
	}

	/**
	getAddress  serach through this Message for an 'A' record giving the address specified by 'name'
	@param name Server name to search for
	@return 'A' record of the given host or null if no appropriate 'A' record
	exists in this Message.
	 **/
	public final A getAddress(String name) {
		if( all == null ) {
			getAll();
		}

		A ret = null;
		RR rr = null;
		name = name.toLowerCase();
		final List<RR> al = all.get(name);

		if( al != null ) {
			for(int idx=0,sz=al.size(); idx<sz; idx++ )       {
				rr=al.get(idx);
				if( rr instanceof A) {	
					ret = (A)rr;
				}
			}
		}
		return ret;
	}

	public final Map<String, List<RR>> getAll () {
		if( all == null ) {
			int ancnt = hdr.getANCOUNT();
			int nscnt = hdr.getNSCOUNT();
			int adcnt = hdr.getARCOUNT();

			all = new HashMap<String, List<RR>>(ancnt+nscnt+adcnt);
			addToAll(ans.iterator());
			addToAll(add.iterator());
			addToAll(ath.iterator());
		}


		return all;
	}

	public final List<RR> getAnswer() { 
		return ans; 
	}

	/**
		How many answers are in the message
	 **/
	public final int getAnswerCount() { return ans.size(); }

	public final List<RR> getAuthority() { 
		return ath; 
	}

	public final String getDomain() { 
		return domain; 
	}

	//  Return the first section in the question section
	//  (that's all ther usualy is)
	public final Section getFirstQuestion(){
		Section ret = null;

		if( que != null && que.size() > 0 ) {
			ret = (Section)que.get(0);
		}

		return ret;
	}

	public final Header getHeader() {
		return hdr;
	}

	/*
	ID          A 16 bit identifier assigned by the program that
                generates any kind of query.  This identifier is copied
                the corresponding reply and can be used by the requester
                to match up replies to outstanding queries.
	 */
	public final int getID() { 
		return hdr.getID(); 
	}

	/**
getAddress  serach through this MEssage for an 'A' record giving the address specified by 'name'
@param name Server name to search for
@return InetAddress of the given host or null if no appropriate 'A' record
exists in this Message.
	 **/
	public final InetAddress getInetAddress(String name) {

		InetAddress ret = null;
		name = name.toLowerCase();
		RR rr = null;
		Map<String, List<RR>> hs = getAll();
		List<RR> al = hs.get(name);
		if( al != null ) {
			for(Iterator<RR> e = al.iterator(); e.hasNext() && ret == null; ) {
				rr = (RR)e.next();
				if( rr instanceof A ) {
					try {
						ret = InetAddress.getByName(((A)rr).getAddressString());
					} catch(UnknownHostException ex) {
						log("Should never happen cause we're using the ip.  ret may be null.",ex);
					}
				}
			}
		}  

		return ret;
	}

	/**
	 * Gets the initTime
	 * @return Returns a long
	 */
	public final long getInitTime() {
		return initTime;
	}

	/**
QR              A one bit field that specifies whether this message is a
                query (0), or a response (1).

	 **/
	public final int getMessageType() { 
		if( hdr.getMessageType() ) 	{
			return RESPONSE;
		} else {
			return QUERY;
		} 
	}

	/**
	 * How many NS records.  These can be used to send new requests 
	 * for Authoritative answers
	 **/
	public final int getNSCount() { return ath.size(); }
	/**
	 *  
	OPCODE          A four bit field that specifies kind of query in this
                message.  This value is set by the originator of a query
                and copied into the response.  The values are:

                0               a standard query (QUERY)

                1               an inverse query (IQUERY)

                2               a server status request (STATUS)

                3-15            reserved for future use

	 **/
	public final int getOpCode() { 
		return hdr.getOPCODE()&0xff;
	}

	public final int getPort()       { 
		return port; 
	}

	public final int getQueryType() { 
		return hdr.getOPCODE(); 
	}

	public final List<Section> getQuestion() { 
		return que; 
	}

	/**
	 *	Question Count (How many questions in this message)
	 **/
	public final int getQuestionCount() { 
		return que.size(); 
	}

	/*
RCODE           Response code - this 4 bit field is set as part of
                responses.  The values have the following
                interpretation:

                0               No error condition

                1               Format error - The name server was
                                unable to interpret the query.

                2               Server failure - The name server was
                                unable to process this query due to a
                                problem with the name server.

                3               Name Error - Meaningful only for
                                responses from an authoritative name
                                server, this code signifies that the
                                domain name referenced in the query does
                                not exist.

                4               Not Implemented - The name server does
                                not support the requested kind of query.

                5               Refused - The name server refuses to
                                perform the specified operation for
                                policy reasons.  For example, a name
                                server may not wish to provide the
                                information to the particular requester,
                                or a name server may not wish to perform
                                a particular operation (e.g., zone

                                transfer) for particular data.

                6-15            Reserved for future use.
	 */
	public final int getResponseCode() { 
		return hdr.getRCODE()&0xff; 
	}

	public final int  getRetry() { return retry; }
	public final String getServer() {
		return (svrAddress == null ? null : svrAddress.toString());
	}

	public final String getServerName() {
		return svrAddress.getHostName();
	}

	public final int  getTimeOut() { return timeOut; }
	/*
AA              Authoritative Answer - this bit is valid in responses,
                and specifies that the responding name server is an
                authority for the domain name in question section.

                Note that the contents of the answer section may have
                multiple owner names because of aliases.  The AA bit

                corresponds to the name which matches the query name, or
                the first owner name in the answer section.
	 */

	public final boolean isAuthority() { 
		return hdr.getAA(); 
	}

	public final boolean isDebug() { 
		return isDebugEnabled(); 
	}
	
	public final boolean isDefname() { return defname; }

	/**
QR              A one bit field that specifies whether this message is a
                query (0), or a response (1).

	 **/
	public final boolean isQuery() { 
		return hdr.getMessageType() == false;
	}

	/**
	 * a messege is recursive if both RA and RD are true
	 **/
	public final boolean isRecursive() { 
		return hdr.getRD() && hdr.getRA(); 
	}

	public final boolean isRecursiveAvailable() { return hdr.getRA(); }

	/*
RD              Recursion Desired - this bit may be set in a query and
                is copied into the response.  If RD is set, it directs
                the name server to pursue the query recursively.
                Recursive query support is optional.
	 */

	public final boolean isRecursiveDesired() { 
		return hdr.getRD(); 
	}

	/**
QR              A one bit field that specifies whether this message is a
                query (0), or a response (1).

	 **/
	public final boolean isResponse() { 
		return hdr.getMessageType();
	}

	/*
RCODE           Response code - this 4 bit field is set as part of
                responses.  The values have the following
                interpretation:

                0               No error condition

                1               Format error - The name server was
                                unable to interpret the query.

                2               Server failure - The name server was
                                unable to process this query due to a
                                problem with the name server.

                3               Name Error - Meaningful only for
                                responses from an authoritative name
                                server, this code signifies that the
                                domain name referenced in the query does
                                not exist.

                4               Not Implemented - The name server does
                                not support the requested kind of query.

                5               Refused - The name server refuses to
                                perform the specified operation for
                                policy reasons.  For example, a name
                                server may not wish to provide the
                                information to the particular requester,
                                or a name server may not wish to perform
                                a particular operation (e.g., zone

                                transfer) for particular data.

                6-15            Reserved for future use.
	 */
	public final boolean isResponseCodeFormatError(){ 
		return getResponseCode()==DNS.FORMAT_ERROR;
	}

	/*
RCODE           Response code - this 4 bit field is set as part of
                responses.  The values have the following
                interpretation:

                0               No error condition

                1               Format error - The name server was
                                unable to interpret the query.

                2               Server failure - The name server was
                                unable to process this query due to a
                                problem with the name server.

                3               Name Error - Meaningful only for
                                responses from an authoritative name
                                server, this code signifies that the
                                domain name referenced in the query does
                                not exist.

                4               Not Implemented - The name server does
                                not support the requested kind of query.

                5               Refused - The name server refuses to
                                perform the specified operation for
                                policy reasons.  For example, a name
                                server may not wish to provide the
                                information to the particular requester,
                                or a name server may not wish to perform
                                a particular operation (e.g., zone

                                transfer) for particular data.

                6-15            Reserved for future use.
	 */
	public final boolean isResponseCodeNameError(){ 
		return getResponseCode()==DNS.NAME_ERROR;
	}

	/*
RCODE           Response code - this 4 bit field is set as part of
                responses.  The values have the following
                interpretation:

                0               No error condition

                1               Format error - The name server was
                                unable to interpret the query.

                2               Server failure - The name server was
                                unable to process this query due to a
                                problem with the name server.

                3               Name Error - Meaningful only for
                                responses from an authoritative name
                                server, this code signifies that the
                                domain name referenced in the query does
                                not exist.

                4               Not Implemented - The name server does
                                not support the requested kind of query.

                5               Refused - The name server refuses to
                                perform the specified operation for
                                policy reasons.  For example, a name
                                server may not wish to provide the
                                information to the particular requester,
                                or a name server may not wish to perform
                                a particular operation (e.g., zone

                                transfer) for particular data.

                6-15            Reserved for future use.
	 */
	public final boolean isResponseCodeNoError(){ 
		return getResponseCode()==DNS.NOERROR;
	}

	/*
RCODE           Response code - this 4 bit field is set as part of
                responses.  The values have the following
                interpretation:

                0               No error condition

                1               Format error - The name server was
                                unable to interpret the query.

                2               Server failure - The name server was
                                unable to process this query due to a
                                problem with the name server.

                3               Name Error - Meaningful only for
                                responses from an authoritative name
                                server, this code signifies that the
                                domain name referenced in the query does
                                not exist.

                4               Not Implemented - The name server does
                                not support the requested kind of query.

                5               Refused - The name server refuses to
                                perform the specified operation for
                                policy reasons.  For example, a name
                                server may not wish to provide the
                                information to the particular requester,
                                or a name server may not wish to perform
                                a particular operation (e.g., zone

                                transfer) for particular data.

                6-15            Reserved for future use.
	 */
	public final boolean isResponseCodeNotImplemented(){ 
		return getResponseCode()==DNS.NOT_IMPLEMENTED;
	}

	/*
RCODE           Response code - this 4 bit field is set as part of
                responses.  The values have the following
                interpretation:

                0               No error condition

                1               Format error - The name server was
                                unable to interpret the query.

                2               Server failure - The name server was
                                unable to process this query due to a
                                problem with the name server.

                3               Name Error - Meaningful only for
                                responses from an authoritative name
                                server, this code signifies that the
                                domain name referenced in the query does
                                not exist.

                4               Not Implemented - The name server does
                                not support the requested kind of query.

                5               Refused - The name server refuses to
                                perform the specified operation for
                                policy reasons.  For example, a name
                                server may not wish to provide the
                                information to the particular requester,
                                or a name server may not wish to perform
                                a particular operation (e.g., zone

                                transfer) for particular data.

                6-15            Reserved for future use.
	 */
	public final boolean isResponseCodeRefused(){ 
		return getResponseCode()==DNS.REFUSED;
	}

	/*
RCODE           Response code - this 4 bit field is set as part of
                responses.  The values have the following
                interpretation:

                0               No error condition

                1               Format error - The name server was
                                unable to interpret the query.

                2               Server failure - The name server was
                                unable to process this query due to a
                                problem with the name server.

                3               Name Error - Meaningful only for
                                responses from an authoritative name
                                server, this code signifies that the
                                domain name referenced in the query does
                                not exist.

                4               Not Implemented - The name server does
                                not support the requested kind of query.

                5               Refused - The name server refuses to
                                perform the specified operation for
                                policy reasons.  For example, a name
                                server may not wish to provide the
                                information to the particular requester,
                                or a name server may not wish to perform
                                a particular operation (e.g., zone

                                transfer) for particular data.

                6-15            Reserved for future use.
	 */
	public final boolean isResponseCodeServerFalure(){ 
		return getResponseCode()==DNS.SERVER_ERROR;
	}

	public final boolean isTCP() { return !udp; }
	/*
TC              TrunCation - specifies that this message was truncated
                due to length greater than that permitted on the
                transmission channel.
	 */
	public boolean isTruncated(){
		return hdr.getTC();
	}

	public final boolean isUDP() { return udp; }
	/**
	 * Insert the method's description here.
	 * Creation date: (5/29/2003 6:48:20 AM)
	 * @param args java.lang.String[]
	 */
	public static void main(String[] args)throws Exception{
		Message msg = new Message();
		msg.debugOn();
		msg.query("2.0.0.127.relays.ordb.org",DNS.TXT,DNS.IN);
	}

	/**
	 * This method will send the message to a server, get a response and return it
	 * @return Dns.Message
	 */
	public Message query() throws InterruptedIOException , UnknownHostException,IOException , SocketException {
		if( svrAddress == null && server != null ) {
			setServer(server);
		}

		Message ret = null;
		if( udp ) {
			ret = queryUDP();
		} else {
			ret =  queryTCP();
		}

	

		return ret;
	}


	public Message query(String name) throws InterruptedIOException ,UnknownHostException,IOException ,SocketException{
		setQuestion(name);
		return this.query();
	}

	public Message query(String name,int tp, int cls) throws InterruptedIOException ,	 UnknownHostException,IOException ,	SocketException{
		setQuestion(name,tp,cls);
		return this.query();
	}

	public Message queryTCP() throws IOException {
		return queryTCP(svrAddress);
	}

	public Message queryTCP(InetAddress svr) throws IOException , InterruptedIOException {
		//boolean done = false;
		byte [] data = toByteArray();

		for(int i=0; i< retry; i++ ) {
			try {

				byte [] sz = new byte[2];
				setShort(sz,0,(short)data.length);
				Socket sock = new Socket(svr,port);
				try {
					sock.setSoTimeout(timeOut);
					OutputStream out = sock.getOutputStream();
					InputStream  in  = sock.getInputStream();

					out.write(sz);
					out.write(data);
					out.flush();

					readArray(in,sz);

					int len = makeShort(sz[0], sz[1]);

					data = new byte[len];

					readArray(in,data);

				}finally {
					sock.close();
				}
				return new Message(new ByteBuffer(data));
			} catch(InterruptedIOException ex) {}
		}
		throw new InterruptedIOException("Timed out "+retry+" times");
	}

	public Message queryUDP() throws InterruptedIOException , UnknownHostException,IOException , SocketException {
		return queryUDP(svrAddress);
	}

	public Message queryUDP(String server) throws InterruptedIOException , UnknownHostException,IOException , SocketException {
		return queryUDP(svrAddress);
	}

	public Message queryUDP(InetAddress server) throws InterruptedIOException , UnknownHostException,IOException , SocketException {
		byte [] data = toByteArray();
		if( data.length > MAXUDPLEN ) {
			truncateOn();
			//  Re-write the buffer
			ByteBuffer b = new ByteBuffer(data,0);
			hdr.toByteArray(b);
			dataSize = MAXUDPLEN;
		}

		DatagramPacket pckt = new DatagramPacket(data,dataSize,server, port);
		byte [] buf = new byte[MAXUDPLEN];
		DatagramPacket recPckt = null;
		boolean done = false;
		DatagramSocket sock = new DatagramSocket();
		try {
			sock.setSoTimeout(timeOut);

			for(int i=0; i<retry && !done; i++ ) {
				try {
					sock.send(pckt);
					recPckt = new DatagramPacket(buf,buf.length);
					sock.receive(recPckt);
					done = true;
				} catch(InterruptedIOException ex) {
				}
			}
		} finally {
			sock.close();
		}
		if( !done ) {
			throw new InterruptedIOException("Received Time Out "+retry+" times");
		}
		if( isDebugEnabled() ) {
			logDebug("\nReceive Buffer Debug info:");
			byte [] d = recPckt.getData();
			logDebug("Data length="+d.length);
			ByteBuffer b = new ByteBuffer(d);
			ILogger logger = getLogger();
			if (logger instanceof BjlLogger	) {
				BjlLogger l = (BjlLogger) logger;
				b.dump(l.getOut());
			} else {
				b.dump();
			}
			
			Message tm = new Message(b);
			logDebug("msg = "+tm);
			logDebug("End Receive Buffer Debug info:\n");
		}
		return new Message(new ByteBuffer(recPckt.getData()));
	}

	public Iterator<Section> question () {
		return que.iterator();
	}

	public static void readArray(InputStream in, byte [] ba) throws IOException {
		int pos = 0;
		int cnt = 0;

		while( cnt != -1 && pos < ba.length) {
			cnt = in.read(ba,pos,(ba.length-pos));
			if( cnt != -1 ) {
				pos+=cnt;
			}
		}
		if( cnt == -1 ) {
			throw new IOException("Unexpected EOF in Message.readArray");
		}
	}

	/*
RA              Recursion Available - this be is set or cleared in a
                response, and denotes whether recursive query support is
                available in the name server.
	 */
	public final void recursiveAvailable(boolean b) { 
		hdr.setRA(b); 
	}

	/*
RA              Recursion Available - this be is set or cleared in a
                response, and denotes whether recursive query support is
                available in the name server.
	 */
	public final void recursiveAvailableOff() { 
		hdr.setRA(false); 
	}

	/*
RA              Recursion Available - this be is set or cleared in a
                response, and denotes whether recursive query support is
                available in the name server.
	 */
	public final void recursiveAvailableOn() { 
		hdr.setRA(true); 
	}

	/*
RD              Recursion Desired - this bit may be set in a query and
                is copied into the response.  If RD is set, it directs
                the name server to pursue the query recursively.
                Recursive query support is optional.
	 */

	public final void recursiveDesired(boolean b) { 
		hdr.setRD(b); 
	}

	/*
RD              Recursion Desired - this bit may be set in a query and
                is copied into the response.  If RD is set, it directs
                the name server to pursue the query recursively.
                Recursive query support is optional.
	 */

	public final void recursiveDesiredOff() { 
		hdr.setRD(false); 
	}

	/*
RD              Recursion Desired - this bit may be set in a query and
                is copied into the response.  If RD is set, it directs
                the name server to pursue the query recursively.
                Recursive query support is optional.
	 */

	public final void recursiveDesiredOn() { 
		hdr.setRD(true); 
	}

	public final void setAnswer(RR rr) {
		if( ans.size() > 0 ) {
			ans = new ArrayList<RR>();
		}
		addAnswer(rr);
	}

	/**
	 * Set the values in the header
	 **/
	public final void setAuthority(){
		hdr.setAA(true);
	}

	/**
	 * Set the values in the header
	 **/
	public final void setAuthorityAnswer(boolean b){
		hdr.setAA(b);
	}

	/**
	 * Set the values in the header
	 **/
	public final void setAuthorityAnswerOff() {
		hdr.setAA(false);
	}

	/**
	 * Set the values in the header
	 **/
	public final void setAuthorityAnswerOn(){
		hdr.setAA(true);
	}

	public final void setDomain(String dom ) {
		if( dom == null ) {
			dom = "";
		} else {
			domain = dom.trim();
		}
	}

	public final void setHeader(Header h) { 
		hdr = h; 
	}

	/*
	ID          A 16 bit identifier assigned by the program that
                generates any kind of query.  This identifier is copied
                the corresponding reply and can be used by the requester
                to match up replies to outstanding queries.
	 */
	public final void setID(int id) {
		hdr.setID(id);
	}

	/**
	 * Sets the initTime
	 * @param initTime The initTime to set
	 */
	public final void setInitTime(long initTime) {
		this.initTime = initTime;
		//  Set the same time on all RRs in the message
		setInitTime(ans);
		setInitTime(ath);
		setInitTime(add);
	}

	//  Set the init time of the list of RRs to the initTime
	//  of this message
	private void setInitTime(List<RR> lst) {
		//RR rr = null;
		Iterator<RR> it = lst.iterator();
		while( it.hasNext() ) {
			((RR)it.next()).setInitTime(this.initTime);
		}
	}

	/**
QR              A one bit field that specifies whether this message is a
                query (0), or a response (1).

	 */
	public final void setMessageType(int t) { 
		hdr.setMessageType(t); 
	}

	/**
QR              A one bit field that specifies whether this message is a
                query (0), or a response (1).

	 */
	public final void setMessageTypeQuery() { 
		hdr.setMessageType(DNS.QUERY); 
	}

	/**
QR              A one bit field that specifies whether this message is a
                query (0), or a response (1).

	 */
	public final void setMessageTypeResponse() { 
		hdr.setMessageType(DNS.RESPONSE); 
	}

	/**

	OPCODE          A four bit field that specifies kind of query in this
                message.  This value is set by the originator of a query
                and copied into the response.  The values are:

                0               a standard query (QUERY)

                1               an inverse query (IQUERY)

                2               a server status request (STATUS)

                3-15            reserved for future use

	 **/

	public final void setOpCode(int val) { 
		hdr.setOPCODE(val);
	}

	public final void setPort(int p) { 
		port = p; 
	}

	/**
		Set the type of QUERY (QUERY, IQUERY or STATUS) QUERY is the default
	 */
	public final void setQueryType(int id) { 
		hdr.setOPCODE(id); 
	}

	public final void setQuestion(String name) {
		if( name.length() > 0 	&& Character.isDigit(name.charAt(0)) ) {
			setQuestion(name,PTR,IN);
		} else {
			setQuestion(name,A,IN);
		}
	}

	public final void setQuestion(String name, int type, int dnsClass) {
		que = new ArrayList<Section>();
		ans = new ArrayList<RR>();
		ath = new ArrayList<RR>();
		add = new ArrayList<RR>();
		addQuestion(name,type,dnsClass);
	}

	public final void setQuestion(String name, int type, String dnsClass) {
		setQuestion(name,type,classOf(dnsClass));
	}

	public final void setQuestion(String name, String type, int dnsClass) {
		setQuestion(name,typeOf(type),dnsClass);
	}

	public final void setQuestion(String name, String type, String dnsClass) {
		setQuestion(name,typeOf(type),classOf(dnsClass));
	}

	public final void setQuestion(Section rr)  { 
		que = new ArrayList<Section>();
		addQuestion(rr);
	}

	/*
RA              Recursion Available - this be is set or cleared in a
                response, and denotes whether recursive query support is
                available in the name server.
	 */
	public final void setRecursiveAvailable(boolean b) { 
		recursiveAvailable(b);
	}

	/*
RA              Recursion Available - this be is set or cleared in a
                response, and denotes whether recursive query support is
                available in the name server.
	 */
	public final void setRecursiveAvailableOff() { 
		recursiveAvailableOff();
	}

	/*
RA              Recursion Available - this be is set or cleared in a
                response, and denotes whether recursive query support is
                available in the name server.
	 */
	public final void setRecursiveAvailableOn() { 
		recursiveAvailableOn();
	}

	/*
RCODE           Response code - this 4 bit field is set as part of
                responses.  The values have the following
                interpretation:

                0               No error condition

                1               Format error - The name server was
                                unable to interpret the query.

                2               Server failure - The name server was
                                unable to process this query due to a
                                problem with the name server.

                3               Name Error - Meaningful only for
                                responses from an authoritative name
                                server, this code signifies that the
                                domain name referenced in the query does
                                not exist.

                4               Not Implemented - The name server does
                                not support the requested kind of query.

                5               Refused - The name server refuses to
                                perform the specified operation for
                                policy reasons.  For example, a name
                                server may not wish to provide the
                                information to the particular requester,
                                or a name server may not wish to perform
                                a particular operation (e.g., zone

                                transfer) for particular data.

                6-15            Reserved for future use.
	 */
	public final void setResponseCode(int code){ 
		hdr.setRCODE(code); 
	}

	/*
RCODE           Response code - this 4 bit field is set as part of
                responses.  The values have the following
                interpretation:

                0               No error condition

                1               Format error - The name server was
                                unable to interpret the query.

                2               Server failure - The name server was
                                unable to process this query due to a
                                problem with the name server.

                3               Name Error - Meaningful only for
                                responses from an authoritative name
                                server, this code signifies that the
                                domain name referenced in the query does
                                not exist.

                4               Not Implemented - The name server does
                                not support the requested kind of query.

                5               Refused - The name server refuses to
                                perform the specified operation for
                                policy reasons.  For example, a name
                                server may not wish to provide the
                                information to the particular requester,
                                or a name server may not wish to perform
                                a particular operation (e.g., zone

                                transfer) for particular data.

                6-15            Reserved for future use.
	 */
	public final void setResponseCodeFormatError(){ 
		setResponseCode(DNS.FORMAT_ERROR); 
	}

	/*
RCODE           Response code - this 4 bit field is set as part of
                responses.  The values have the following
                interpretation:

                0               No error condition

                1               Format error - The name server was
                                unable to interpret the query.

                2               Server failure - The name server was
                                unable to process this query due to a
                                problem with the name server.

                3               Name Error - Meaningful only for
                                responses from an authoritative name
                                server, this code signifies that the
                                domain name referenced in the query does
                                not exist.

                4               Not Implemented - The name server does
                                not support the requested kind of query.

                5               Refused - The name server refuses to
                                perform the specified operation for
                                policy reasons.  For example, a name
                                server may not wish to provide the
                                information to the particular requester,
                                or a name server may not wish to perform
                                a particular operation (e.g., zone

                                transfer) for particular data.

                6-15            Reserved for future use.
	 */
	public final void setResponseCodeNameError(){ 
		setResponseCode(DNS.NAME_ERROR);
	}

	/*
RCODE           Response code - this 4 bit field is set as part of
                responses.  The values have the following
                interpretation:

                0               No error condition

                1               Format error - The name server was
                                unable to interpret the query.

                2               Server failure - The name server was
                                unable to process this query due to a
                                problem with the name server.

                3               Name Error - Meaningful only for
                                responses from an authoritative name
                                server, this code signifies that the
                                domain name referenced in the query does
                                not exist.

                4               Not Implemented - The name server does
                                not support the requested kind of query.

                5               Refused - The name server refuses to
                                perform the specified operation for
                                policy reasons.  For example, a name
                                server may not wish to provide the
                                information to the particular requester,
                                or a name server may not wish to perform
                                a particular operation (e.g., zone

                                transfer) for particular data.

                6-15            Reserved for future use.
	 */
	public final void setResponseCodeNoError(){ 
		setResponseCode(DNS.NOERROR); 
	}

	/*
RCODE           Response code - this 4 bit field is set as part of
                responses.  The values have the following
                interpretation:

                0               No error condition

                1               Format error - The name server was
                                unable to interpret the query.

                2               Server failure - The name server was
                                unable to process this query due to a
                                problem with the name server.

                3               Name Error - Meaningful only for
                                responses from an authoritative name
                                server, this code signifies that the
                                domain name referenced in the query does
                                not exist.

                4               Not Implemented - The name server does
                                not support the requested kind of query.

                5               Refused - The name server refuses to
                                perform the specified operation for
                                policy reasons.  For example, a name
                                server may not wish to provide the
                                information to the particular requester,
                                or a name server may not wish to perform
                                a particular operation (e.g., zone

                                transfer) for particular data.

                6-15            Reserved for future use.
	 */
	public final void setResponseCodeNotImplemented(){ 
		setResponseCode(DNS.NOT_IMPLEMENTED);
	}

	/*
RCODE           Response code - this 4 bit field is set as part of
                responses.  The values have the following
                interpretation:

                0               No error condition

                1               Format error - The name server was
                                unable to interpret the query.

                2               Server failure - The name server was
                                unable to process this query due to a
                                problem with the name server.

                3               Name Error - Meaningful only for
                                responses from an authoritative name
                                server, this code signifies that the
                                domain name referenced in the query does
                                not exist.

                4               Not Implemented - The name server does
                                not support the requested kind of query.

                5               Refused - The name server refuses to
                                perform the specified operation for
                                policy reasons.  For example, a name
                                server may not wish to provide the
                                information to the particular requester,
                                or a name server may not wish to perform
                                a particular operation (e.g., zone

                                transfer) for particular data.

                6-15            Reserved for future use.
	 */
	public final void setResponseCodeRefused(){ 
		setResponseCode(DNS.REFUSED);
	}

	/*
RCODE           Response code - this 4 bit field is set as part of
                responses.  The values have the following
                interpretation:

                0               No error condition

                1               Format error - The name server was
                                unable to interpret the query.

                2               Server failure - The name server was
                                unable to process this query due to a
                                problem with the name server.

                3               Name Error - Meaningful only for
                                responses from an authoritative name
                                server, this code signifies that the
                                domain name referenced in the query does
                                not exist.

                4               Not Implemented - The name server does
                                not support the requested kind of query.

                5               Refused - The name server refuses to
                                perform the specified operation for
                                policy reasons.  For example, a name
                                server may not wish to provide the
                                information to the particular requester,
                                or a name server may not wish to perform
                                a particular operation (e.g., zone

                                transfer) for particular data.

                6-15            Reserved for future use.
	 */
	public final void setResponseCodeServerFailure(){ 
		setResponseCode(DNS.SERVER_ERROR);
	}

	public final void setRetry(int i) { 
		retry = i; 
	}

	public final void setServer(String svr) throws UnknownHostException {
		svrAddress = InetAddress.getByName(svr);
		server = svr;
	}

	public final void setServer(InetAddress svr) {
		svrAddress = svr;

	}

	public final void setTimeOut(int to) { 
		timeOut = to; 
	}

	/*
TC              TrunCation - specifies that this message was truncated
                due to length greater than that permitted on the
                transmission channel.
	 */
	public final void setTruncated(boolean b){
		hdr.setTC(b);
	}

	/*
TC              TrunCation - specifies that this message was truncated
                due to length greater than that permitted on the
                transmission channel.
	 */
	public final void setTruncatedOff(){
		hdr.setTC(false);
	}

	/*
TC              TrunCation - specifies that this message was truncated
                due to length greater than that permitted on the
                transmission channel.
	 */
	public final void setTruncatedOn(){
		hdr.setTC(true);
	}

	public final int size() {
		if( data == null ) {
			data = toByteArray();
		}
		return dataSize;
	}

	public final void TCPOff() { udp = true; }
	public final void TCPOn() { udp = false; }

	public final byte [] toByteArray() {
		ByteBuffer rd = new ByteBuffer();
		hdr.setQDCOUNT(que.size());
		hdr.setANCOUNT(ans.size());
		hdr.setNSCOUNT(ath.size());
		hdr.setARCOUNT(add.size());

		hdr.toByteArray(rd);



		int cnt = hdr.getQDCOUNT();
		for(int i=0; i< cnt; i++) {
			Section sec = (Section)que.get(i);
			sec.toByteArray(rd);    
		}


		cnt = hdr.getANCOUNT();
		for(int i=0; i< cnt; i++) {
			RR sec = (RR)ans.get(i);
			sec.toByteArray(rd);    
		}


		cnt = hdr.getNSCOUNT();
		for(int i=0; i< cnt; i++) {
			RR sec = (RR)ath.get(i);
			sec.toByteArray(rd);    
		}

		cnt = hdr.getARCOUNT();
		for(int i=0; i< cnt; i++) {
			RR sec = (RR)add.get(i);
			sec.toByteArray(rd);    
		}
		data =  rd.getByteArray();
		dataSize = data.length;
		return data;
	}

	public String toSmallString(){

		StringBuffer ret = new StringBuffer();

		ret.append("Q(");
		for(Iterator<Section> e=question(); e.hasNext(); ) {
			ret.append("{"+e.next().toString()+"}");
		}
		ret.append(") A(");
		for(Iterator<RR> e=answer(); e.hasNext(); ) {
			ret.append("{"+e.next().toString()+"}");

		}
		ret.append(')');

		return ret.toString();

	}

	public String toString(){
		hdr.setQDCOUNT(que.size());
		hdr.setANCOUNT(ans.size());
		hdr.setNSCOUNT(ath.size());
		hdr.setARCOUNT(add.size());

		StringBuffer ret = new StringBuffer();
		ret.append("Header \n");
		ret.append(hdr.toString());
		ret.append('\n');
		ret.append("Qtype = "+qtype);
		if( qtype < TYPENAMES.length ) {
			ret.append("("+TYPENAMES[qtype]+")");
		}
		ret.append('\n');

		ret.append("DnsClass = "+dnsClass);
		if( dnsClass < CLASSNAMES.length ) {
			ret.append("("+CLASSNAMES[dnsClass]+")");
		}
		ret.append('\n');

		ret.append("Question \n");
		for(Iterator<Section> e=question(); e.hasNext(); ) {
			ret.append("\t"+e.next().toString());
			ret.append('\n');
		}
		ret.append("Answer \n");
		for(Iterator<RR> e=answer(); e.hasNext(); ) {
			ret.append("\t"+e.next().toString());
			ret.append('\n');
		}
		ret.append("Autority \n");
		for(Iterator<RR> e=authority(); e.hasNext(); ) {
			ret.append("\t"+e.next().toString());
			ret.append('\n');
		}
		ret.append("Additional \n");
		for(Iterator<RR> e=additional(); e.hasNext(); ) {
			ret.append("\t"+e.next().toString());
			ret.append('\n');
		}

		return ret.toString();

	}

	public final void truncateOff() { hdr.setTC(false); }

	/**
Is the message truncated due to transport limitation
	 */
	public final void truncateOn() { 
		hdr.setTC(true); 
	}
	public final void UDPOff() { udp = false; }
	public final void UDPOn() { udp = true; }
}
