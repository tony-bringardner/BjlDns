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
package us.bringardner.net.dns;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.Map;
/**
This class manages the creation and parsing of the DNS message format (it's main purpose is to implement message compression as described in RFC 1035)
 **/
public  class ByteBuffer {

	/**
		Inner class used to manage message compression
	 **/
	class ptr {
		short idx=-1;
		String name;
	}

	byte [] buf;
	int rpos; // Read position
	int wpos; // Write Position
	int inc = DNS.MAXUDPLEN;
	Map<String, ptr> lables;

	int rdlengthPos = 0;



	/**
	Default constructor (creates a ByteBuffer with the initial size set to DNS.MAXUDPLEN
	 **/
	public ByteBuffer() {
		this(new byte [DNS.MAXUDPLEN],0);
	}
	
	/**
	Create a ByteBuffer from a byte array (used mainly for receiving messages)
	 **/
	public ByteBuffer(byte [] b) {
		this(b,0);
	}
	
	/**
	Create a ByteBuffer from a byte array setting the current position (used mainly to manage message compression in recieving messages)
	 **/
	public ByteBuffer(byte [] b, int i) {
		buf = b;
		rpos = i;
		wpos = 0;
		lables = new HashMap<String, ptr>();
	}

	/**
		Check to see if there is a pointer at the current position (a pointer is described in RFC 1035)
		@return A ByteBuffer representing the current position with pointers dereferenced
	 **/
	public ByteBuffer chkPointer() {

		/*
			If we are currently pointed at a pointer
			create a new buffer pointing to the real
			string, and return it, otherwise return null.
		 */
		if( rpos>=buf.length || (buf[rpos]&DNS.POINTER) == 0 ) {
			return this;
		}

		short newPos = (short)nextShort();
		ByteBuffer ret = new ByteBuffer(buf,(newPos&0x3FFF));
		ret.wpos = wpos;
		return ret;
	}
	
	/**
	Dump the ByteBuffer showing the position, hex value, binary value and character of each byte (use to debug)
	 **/
	public void dump () {
		dump(System.out);
	}
	
	/**
		Dump the ByteBuffer showing the position, hex value, binary value and character of each byte (use to debug)
	 **/
	public void dump (PrintStream out) {
		int cnt = buf.length-1;

		for(cnt=buf.length-1; cnt > 0 ; cnt-- ) {
			if( buf[cnt] != 0 ) {
				break;
			}
		}
		out.println("ByteBuffer Dump rpos="+rpos+" wpos = "+wpos+" length="+buf.length);
		out.println("cnt="+cnt);

		//  Just to make sure I save it all.
		if( cnt < buf.length ) {
			cnt++;
		}

		if( cnt < buf.length ) {
			cnt++;
		}

		int val = 0;
		char c = ' ';

		for(int i = 0; i< cnt; i++) {
			val = (buf[i]&0xff);
			if( val > 30 && val < 128 ) {
				c = (char)val;
			} else {
				c = ' ';
			}

			out.println("buf["+Utility.pad(""+i,3)+"] = "+
					" "+Utility.pad(Integer.toString(val),3)+
					" , "+Utility.pad(Integer.toHexString(val),2)+
					" , "+Utility.bi(val)+
					" , raw("+buf[i]+")"+
					" , "+c
					);
		}
		// show format rfc1035 4.1.1
		/*
                                1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		 */
		/*
		 * ID  A 16 bit identifier assigned by the program that
                generates any kind of query.  This identifier is copied
                the corresponding reply and can be used by the requester
                to match up replies to outstanding queries.
		 */
		out.println("\tID\t"+Utility.makeShort(buf[0], buf[1]));
		/*
		 
			QR  A one bit field that specifies whether this message is a
                query (0), or a response (1).
		 */
		String tmp = toBinaryString(buf[2]);
		out.println("\tQR\t"+tmp.charAt(0));
		
		/*
		 OPCODE          A four bit field that specifies kind of query in this
                message.  This value is set by the originator of a query
                and copied into the response.  The values are:

                0               a standard query (QUERY)

                1               an inverse query (IQUERY)

                2               a server status request (STATUS)

                3-15            reserved for future use
		 */
		String t2 = tmp.substring(1,5);
		int v = Integer.parseUnsignedInt(t2, 2);
		
		out.print("\tOPCODE\t"+t2+" = "+v);
		switch (v) {
		case 0: out.println(" a standard query (QUERY)"); break;
		case 1: out.println(" an inverse query (IQUERY)"); break;
		case 2: out.println(" a server status request (STATUS)"); break;
		
		default:
			out.println(" reserved for future use"); break;
			
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
		out.println("\tAA\t"+tmp.charAt(5));
		
		/*
TC              TrunCation - specifies that this message was truncated
                due to length greater than that permitted on the
                transmission channel.
		 */
		out.println("\tTC\t"+tmp.charAt(6));
		
		/*
RD              Recursion Desired - this bit may be set in a query and
                is copied into the response.  If RD is set, it directs
                the name server to pursue the query recursively.
                Recursive query support is optional.
		 */
		out.println("\tRD\t"+tmp.charAt(7));
		
/*
 RA              Recursion Available - this be is set or cleared in a
                response, and denotes whether recursive query support is
                available in the name server.
 
 */
		tmp = toBinaryString(buf[3]);
		

		out.println("\tRA\t"+tmp.charAt(0));
/*
Z               Reserved for future use.  Must be zero in all queries
                and responses.
 */
		out.println("\tZ\t"+tmp.substring(1, 4)+"\tReserved for future use.  Must be zero in all queries and responses.");
		
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
		t2 = tmp.substring(4);
		v = Integer.parseUnsignedInt(t2, 2);
		out.print("\tRCODE\t"+t2+" = "+v);
		switch (v) {
		case 0: out.println(" No error condition"); break;
		case 1: out.println(" Format error - The name server was unable to interpret the query."); break;
		case 2: out.println(" Server failure - The name server was\n"
				+ "                                unable to process this query due to a\n"
				+ "                                problem with the name server."); break;
		case 3: out.println(" Name Error - Meaningful only for\n"
				+ "                                responses from an authoritative name\n"
				+ "                                server, this code signifies that the\n"
				+ "                                domain name referenced in the query does\n"
				+ "                                not exist."); break;
		case 4: out.println(" Not Implemented - The name server does\n"
				+ "                                not support the requested kind of query."); break;
		case 5: out.println(" Refused - The name server refuses to\n"
				+ "                                perform the specified operation for\n"
				+ "                                policy reasons.  For example, a name\n"
				+ "                                server may not wish to provide the\n"
				+ "                                information to the particular requester,\n"
				+ "                                or a name server may not wish to perform\n"
				+ "                                a particular operation (e.g., zone\n"
				+ "                                transfer) for particular data."); break;
		
		
		default:
			out.println(" reserved for future use"); break;
			
		}
		
/*
QDCOUNT         an unsigned 16 bit integer specifying the number of
                entries in the question section.
*/
		out.println("\tQDCOUNT\t"+Utility.makeShort(buf[4], buf[5]));
/*		
ANCOUNT         an unsigned 16 bit integer specifying the number of
                resource records in the answer section.
*/
		out.println("\tANCOUNT\t"+Utility.makeShort(buf[6], buf[7]));
/*		
NSCOUNT         an unsigned 16 bit integer specifying the number of name
                server resource records in the authority records
                section.
*/
		out.println("\tNSCOUNT\t"+Utility.makeShort(buf[8], buf[9]));
/*
ARCOUNT         an unsigned 16 bit integer specifying the number of
                resource records in the additional records section.		
 */
		out.println("\tARCOUNT\t"+Utility.makeShort(buf[10], buf[11]));
	
	}
	
	private String toBinaryString(byte b) {
		String ret = Integer.toBinaryString(b);
		while(ret.length()<8) {
			ret = "0"+ret;
		}
		if( ret.length()>8) {
			ret = ret.substring(ret.length()-8);
		}
		return ret;
	}

	/**
		Get the internal byte array
	 **/
	public byte [] getBuf() {
		return buf;
	}
	
	/**
		Get the internal byte array (the array 'may' be trimmed to the size of the data actually in the array)
	 **/
	public byte [] getByteArray() {
		if(wpos < buf.length) {
			byte [] tmp = new byte[wpos];
			System.arraycopy(buf,0,tmp,0,wpos);
			return tmp;
		} else {
			return buf;
		}
	}
	
	/**
		Get the increment (the number of bytes added to the size of the internal array if the current size is not sufficient)
	 **/
	public int getInc() { 
		return inc;
	}
	
	/**
		Get the posistion of the read pointer
	 **/
	public int getReadPos() {
		return rpos;
	}
	
	/**
		Get the position of the write pointer
	 **/
	public int getWritePos() {
		return wpos;
	}
	
	/**
	 * 
	 * Creation date: (9/30/2001 10:21:44 AM)
	 * @param args java.lang.String[]
	 */
	public static ByteBuffer loadFromFile(String file)
			throws Exception
	{

		BufferedReader in = new BufferedReader(new FileReader(file));
		String line = in.readLine();
		line = in.readLine();
		line = in.readLine();
		line = in.readLine();
		line = in.readLine();
		int cnt = Integer.parseInt(line)+1;	
		int idx = 0;
		byte [] data = new byte[512];

		for(int i=0; i< cnt; i++ ) {
			line = in.readLine();
			idx = line.indexOf('=');
			line = line.substring(idx+1).trim();
			idx = line.indexOf(',');
			line = line.substring(0,idx).trim();
			data[i]=(byte)Integer.parseInt(line);	
		}

		in.close();
		ByteBuffer buf = new ByteBuffer(data);

		return buf;

	}
	/**
	 * 
	 * Creation date: (9/30/2001 10:21:44 AM)
	 * @param args java.lang.String[]
	 */
	public static String fn = "/Users/tony/test.txt";
	
	public static void main(String[] args)
			throws Exception
	{
		

		if( args.length > 0 ) {
			fn = args[0];
		}

		BufferedReader in = new BufferedReader(new FileReader(fn));
		String line = in.readLine();
		line = in.readLine();
		line = in.readLine();
		line = in.readLine();
		line = in.readLine();
		int cnt = Integer.parseInt(line)+1;	
		int idx = 0;
		byte [] data = new byte[512];

		for(int i=0; i< cnt; i++ ) {
			line = in.readLine();
			idx = line.indexOf('=');
			line = line.substring(idx+1).trim();
			idx = line.indexOf(',');
			line = line.substring(0,idx).trim();
			data[i]=(byte)Integer.parseInt(line);	
			System.out.println(line);
		}

		in.close();
		ByteBuffer buf = new ByteBuffer(data);
		//buf.dump();	
		Message msg = new Message(buf);
		System.out.println("Message = "+msg);
	}
	
	public void markPos(int s){
		rdlengthPos = wpos;
		setShort(s);
	}
	
	/**
		Get the next 8 bit byte from the ByteBuffer, incrementing the read position
	 **/
	public int next() {
		int ret = buf[rpos++]&0xff;

		return ret;
	}	
	
	/**
		Get a 32 bit int from the buffer
		@return int representation of the next four bytes in the ByteBuffer, incrementing the readPosition accordingly
	 **/
	public int nextInt() {
		return Utility.makeInt( next(), next(),	next(), next());
	}
	/**
		Get a 16 bit int from the buffer
		@return short representation of the next two bytes in the ByteBuffer, incrementing the readPosition accordingly
	 **/

	public int nextShort() {
		return Utility.makeShort( next(), next());
	}	
	
	//  Setters
	/**
		Add a 8 bit byte to the byte array , incrementing the write position
	 */
	public void setByte(byte b) {
		if( wpos == buf.length) {
			byte [] tmp = new byte[buf.length+inc];
			System.arraycopy(buf,0,tmp,0,buf.length);
			buf = tmp;
		}
		buf[wpos++] = b;
	}
	
	/**
		Copy a byte array into the internal buffer at the current position
	 **/
	public void setBytes(byte [] b) {
		for(int i=0; i < b.length; i++ ) {
			setByte(b[i]);
		}
	}
	
	/**
		Set the increment (the number of bytes added to the size of the internal array if the current size is not sufficiant)
	 **/
	public void setInc(int i) {
		inc = i;
	}
	
	/**
		Add a 32 bit integer to the byte array in Big Endian order (incrementing the write pointer accordingly)
	 **/
	public void setInt(int val) {
		int s = (val >> 16);
		setShort(s);
		s = val&0xffff;
		setShort(s);
	}
	
	/**
		Add a name to this buffer and implement compression
		as described in RFC 1035.
	 **/
	public void setName(String name) {
		if( name == null ) {
			setByte((byte)0);
			return ;
		}

		ptr p = (ptr)lables.get(name);
		if( p != null ) {
			setShort((short)(p.idx|(DNS.POINTER<<8))); //  ptr.idx is already made into a pointer
			return;
		}

		/*
			If we made it to here, at lease part of the name will be new in the label list
		 */
		if( name.length() > 3 ) {
			//  But only do it if there is a savings of 2 or more bytes
			p = new ptr();
			p.idx = (short)wpos;
			p.name = name;
			lables.put(name,p);
		}

		//  Now, break the name apart and check each segment
		int idx = name.indexOf(".");
		String tmp = null;
		if( idx > 0 ) {
			tmp  = name.substring(idx+1);
			name = name.substring(0,idx);
		}
		setByte((byte)name.length());
		setBytes(name.getBytes());	
		setName(tmp);
	}
	
	/**
		Add a name to this buffer and implement compression
		as described in RFC 1035.
	 **/
	public void setName(Name name) {
		setName(name.toString());
	}
	
	/**
		Write the rdlength into the marked location
		rdlength is calculated from the mark to the current pos
	 **/
	public void setRdLength() {
		int hld = wpos;
		int rdlength = wpos-rdlengthPos-2;
		wpos = rdlengthPos;
		setShort((short)rdlength);
		wpos = hld;
	}
	
	public void setShort(int s) {
		setByte((byte)(s >> 8));
		setByte((byte)s);
	}
	
}
