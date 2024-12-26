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
 * ~version~V000.00.05-V000.00.01-V000.00.00-
 */
package us.bringardner.net.dns;

/*
	Copyright Tony Bringardner 1999, 2021
*/
/**
	DNS interface defines all of the protocol specific constants
**/
public interface DNS {

		/*
		Java Type Sizes (just a reminder for me)
		byte  =  8 bits
		short = 16 bits
		int   = 32 bits
		long  = 64 bits
		*/

		//  Size limits
	/**
	Maximum name segment length (63)
	**/
		static final int MAXLABLELEN = 63;
	/**
	Maximum host name length (255)
	**/
		static final int MAXNAMELEN  = 255;
	/**
	Maximum UDP Packet length (512)  Larger messages must be TCP
	**/
		static final int MAXUDPLEN   = 1024*2;// 512;

		//  TYPE values appear in the RR Records (these are also QTYPEs)
	/** QTYPE (Question Type) Values (Host Record) **/
		static final int A     =  1; //  Host record
	/** QTYPE (Question Type) Values (Authoritative Name Server Record) **/
		static final int NS    =  2; //  Authoritative Name Server 
	/** QTYPE (Question Type) Values (Obsolete, use MX) **/
		static final int MD    =  3; //  Obsolete, use MX
	/** QTYPE (Question Type) Values (Obsolete , Use MX) **/
		static final int MF    =  4; //  Obsolete, use MX
	/** QTYPE (Question Type) Values (Canonical name for alias) **/
		static final int CNAME =  5; //  Canonical name for alias
	/** QTYPE (Question Type) Values (Start Of Authority ) **/
		static final int SOA   =  6; //  Start of authority
	/** QTYPE (Question Type) Values (Mailbox Domain (Experimental) ) **/
		static final int MB    =  7; // Mailbox domain (Experimental)
	/** QTYPE (Question Type) Values (Mailbox Group Member (Experimental) ) **/
		static final int MG    =  8; // Mailbox group member (Experimental)
	/** QTYPE (Question Type) Values (Mailbox Rename (Experimental) ) **/
		static final int MR    =  9; // mail rename (Exp)
	/** QTYPE (Question Type) Values (NULL (Experimental) ) **/
		static final int NULL  = 10; // null (Experimental)
	/** QTYPE (Question Type) Values (Well Known Services ) **/
		static final int WKS   = 11; // WKS well known services
	/** QTYPE (Question Type) Values (Domain Name ) **/
		static final int PTR   = 12; // Domain name poshort
	/** QTYPE (Question Type) Values (Host Information ) **/
		static final int HINFO = 13; // Host Information
	/** QTYPE (Question Type) Values (Mailbox Information ) **/
		static final int MINFO = 14; // Mailbox information
	/** QTYPE (Question Type) Values (Mail Exchange Record) **/
		static final int MX    = 15; //  Mail Exchange Record
	/** QTYPE (Question Type) Values (Text String ) **/
		static final int TXT   = 16; // Text String (Comment)

	/** QTYPE (Question Type) Values (AFS Data Base location  Same structure as MX RFC1183) **/
		static final int AFSDB   = 18; 

	/**
	TYPE names (TYPENAMES[MX] == "MX")
	**/
		static final String [] TYPENAMES = {
			"UnKnown", "A", "NS", "MD", "MF",
								"CNAME", "SOA", "MB", "MG", "MR",
								"NULL", "WKS", "PTR", "HINFO", "MINFO",
								"MX", "TXT",
								"RP","AFSDB","X25","ISDN","RT","NSAP","NSAP-PTR","SIG","KEY", "PX", 
								"GPOS","AAAA","LOC","NXT","EID","NIMLOC","SRV","ATMA","NAPTR",
								"KX","CERT","A6","DNAME",
								"SINK","OPT","APL","43","44","45","46","47","48","49",
								"50","51","52","53","54","55","56","57","58","59",
								"60","61","62","63","64","65","66","67","68","69",
								"70","71","72","73","74","75","76","77","78","79",
								"80","81","82","83","84","85","86","87","88","89",
								"90","91","92","93","94","95","96","97","98","SPF",
								"UINFO","UID","GID","UNSPEC","104","105","106","107","108","109",
								"110","111","112","113","114","115","116","117","118","119",
								"120","121","122","123","124","125","126","127","128","129",
								"130","131","132","133","134","135","136","137","138","139",
								"140","141","142","143","144","145","146","147","148","149",
								"150","151","152","153","154","155","156","157","158","159",
								"160","161","162","163","164","165","166","167","168","169",
								"170","171","172","173","174","175","176","177","178","179",
								"180","181","182","183","184","185","186","187","188","189",
								"190","191","192","193","194","195","196","197","198","199",
								"200","201","202","203","204","205","206","207","208","209",
								"210","211","212","213","214","215","216","217","218","219",
								"220","221","222","223","224","225","226","227","228","229",
								"230","231","232","233","234","235","236","237","238","239",
								"240","241","242","243","244","245","246","247","248","TKEY",
								"TSIG","IXFR","AXFR","MAILB","MAILA","*","256","257","258","259",
								"260","261","262","263","264","265","266","267","268","269"
								
								};


		// RFC 1035
		static final int AXFR  = 252; // Request to transfer entire zone
		static final int MAILB = 253; // Mailbox related records (MB,MG,MR)
		static final int MAILA = 254; // Mail agent records (Obsolete)
		static final int QTYPE_ALL = 255; //  A request for all records
		
		//  RFC 4408 Sender Policy Framework
		static final int SPF = 99;


		//  CLASS values used in RR Records (These are also QCLASSs)
	/** CLASS Value **/
		static final int IN =  1; // The Internet
	/** CLASS Value **/
		static final int CS =  2; // CSNET (Obsolete)
	/** CLASS Value **/
		static final int CH =  3; // CHAOS Class
	/** CLASS Value **/
		static final int HS =  4; // Hesiod [Dyer 87]
	/** 
	CLASS Value Names  (CLASSNAME[IN] == "IN")
	**/
		static final String [] CLASSNAMES = {"UnKnown","IN","CS","CH","HS" };

		/**  QCLASS wildcard **/
		static final int QCLASS_ALL = 255;


		//  Some usefull defines
	/** Message Types **/
		static final int QUERY = 0;
	/** Message Types **/
		static final int RESPONSE = 1;
	/** Message Types Names (QUERYNAMES[RESPONSE] == "RESPONSE" **/
		static final String [] QUERYNAMES = {"QUERY","RESPONSE" };

		// OPCODE values (include QUERY also) (type of Query)
	/**
	OPCODE Value (Inverse Query, not recomended see RFC 1035)
		QUERY is defined as both type an message type both =- 0
	**/
		static final int IQUERY =  1;
		static final int STATUS =  2;
	/** OPCODE Value Names */
		static final String [] OPCODENAMES = {"QUERY","IQUERY","STATUS","Reserved","Notify","Update",
			"6","7","8","9","10","11","12","13","14","15"
			};

		/*
		This info stored at www.iana.org
		RCODE   Name                                          References
 -----   ----                                          ----------
	 0   NoError     No Error                           [RFC1035]
	 1   FormErr     Format Error                       [RFC1035]
	 2   ServFail    Server Failure                     [RFC1035]
	 3   NXDomain    Non-Existent Domain                [RFC1035]
	 4   NotImp      Not Implemented                    [RFC1035]
	 5   Refused     Query Refused                      [RFC1035]
	 6   YXDomain    Name Exists when it should not     [RFC2136]
	 7   YXRRSet     RR Set Exists when it should not   [RFC2136]
	 8   NXRRSet     RR Set that should exist does not  [RFC2136]
	 9   NotAuth     Server Not Authoritative for zone  [RFC2136]
	10   NotZone     Name not contained in zone         [RFC2136]
 11-15               available for assignment
	16   BADVERS     Bad OPT Version                    [RFC2671]
	16   BADSIG      TSIG Signature Failure             [RFC2845]
	17   BADKEY      Key not recognized                 [RFC2845]
	18   BADTIME     Signature out of time window       [RFC2845]
	19   BADMODE     Bad TKEY Mode                      [RFC2930]
	20   BADNAME     Duplicate key name                 [RFC2930]
	21   BADALG      Algorithm not supported            [RFC2930]
	*/

		// RCODE values (Response codes)
	/** RCODE Value **/
	// RFC1035
		static final int NOERROR =  0; //  No error
		static final int FORMAT_ERROR =  1;
		static final int SERVER_ERROR =  2;
		static final int NAME_ERROR   =  3;
		static final int NOT_IMPLEMENTED =  4;
		static final int REFUSED      =  5;
		/** RCODE Value Names **/
		static final String [] ERRORNAMES = {
								"NoError",
								"FormErr",
								"Server error",
								"NXDOMAIN Name error (does not exist)",
								"Not implemented" ,
								"Refused" ,
								"YXDomain", "YXRRSet", "NXRRSet", "NotAuth",
								"NotZone", 
								"11", "12", "13","14", "15", 
								"BADVERS or BADSIG","BADKEY","BADTIME",
								"BADMODE","BADNAME","BADALG"
										};


/**
	Message compression see RFC 1035 for details 
	(first two bits set means this is a pointer) 
	The rest of the bites point to the offset of the label 
	within the message.
**/
		static final int POINTER = (int)0xC0;


	/**
	Standard DNS port (well known port == 53)
	**/
		static final int DNSPORT = 53;



		// RFC2874
		static final int A6		=38;		// Thomson
		static final int AAAA	= 28; // IP6 Address		

		// RFC3223
		static final int APL	=42;		// Dobrowski
		static final int ATMA	= 34; // ATM Address		
		static final int  BADALG    =21;		
		static final int  BADKEY    =17;		
		static final int  BADMODE   =19;		
		static final int  BADNAME   =20;		
		static final int  BADSIG    =16;		
		static final int  BADTIME   =18;	  	
		static final int  BADVERS   =16;		
		//RFC2538
		static final int CERT	=37; // CERT		
		// RFC2672
		static final int DNAME	=39;		// Patton
		static final int EID 	= 31; //  Endpoint Identifier		
		static final int GID	=102;		//  RFC1712
		static final int GPOS   = 27; // Geographical Position;		
		static final int ISDN  = 20; // ISND Address		//RFC1995
		static final int IXFR	=251; //  Incrimental Transfer		
		// RFC2230
		static final int KX		=36; // Key Exchaner		// Vixie
		static final int LOC	= 29; //  Location Information		// RFC2168, RFC2915
		static final int NAPTR = 35; // URN Naming Authority??		
		static final int NIMLOC	= 32; // Nimrod Locator		
		static final int  NotAuth	=9;		//  4 reserved by IANA
		static final int NOTIFY = 4;		
		static final int  NotZone	=10;		// RFC1706
		static final int NSAP   = 22; //  Security signature		
		static final int NSAP_PTR= 23; // security key		
		static final int  NXRRSet	=8;		// RFC2535
		static final int NXT	= 30; // Next Domain		//RFC2671
		static final int OPT	=41;		//  RFC2163
		static final int PX  	 = 26; //  Mapping Information ??		//  RFC1183
		static final int RP    = 17; // Responsible Person		
		static final int RT    = 21; // Route Through		//EastLake
		static final int SINK	=40;		// RFC2782		
		static final int SRV   = 33; //  Server Selection??		//RFC2930
		static final int TKEY	=249; // Transaction KEy		// RFC2845
		static final int TSIG	=250; // Transation Signature		
		static final int UID	=101;		//IANA-Reserved
		static final int UINFO	=100;		
		static final int UNSPEC	=103;		
		static final int UPDATE = 5;		
		static final int X25   = 19; // X.25 PSDN Address		
		// RFC2136
		static final int YXDomain = 6;		
		static final int  YXRRSet    =7;



}
