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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import us.bringardner.net.dns.A;
import us.bringardner.net.dns.Cname;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Hinfo;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.Mx;
import us.bringardner.net.dns.Name;
import us.bringardner.net.dns.Ns;
import us.bringardner.net.dns.Ptr;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.Soa;
import us.bringardner.net.dns.Spf;
import us.bringardner.net.dns.Txt;
import us.bringardner.net.dns.Utility;
/**
 * 
 * Creation date: (8/23/01 9:03:07 AM)
 * @author: Tony Bringardner
 */
public class Zone implements DNS {


	// This is the name of the file that contained the data
	private String fileName;

	private long lastModified;

	//Name represents the 'zone' name.  In most cases will be the last two labels (i.e. minemall.com)
	private String name;

	//  soa is the start of authority.  It has default values for all RRs
	private Soa soa;

	/*
	 * These are the RRs defined in this zone.  
	 * Holds a HashMap of rrs for each name
	 */
	private List<Name> names;
	private List<List<RR>> rrs;

	// List of name servers
	//private ArrayList authority = null;

	//  A records for name servers
	//private ArrayList  authAddress = null;

	//  This is used for parsing the file
	private transient String currentName;

	private String [] lables;

	private File masterFile;

	public List<Name> getNames() {
		return names;
	}

	public void setNames(List<Name> names) {
		this.names = names;
	}

	public List<List<RR>> getRrs() {
		return rrs;
	}

	public void setRrs(List<List<RR>> rrs) {
		this.rrs = rrs;
	}

	public long getLastModified() {
		return lastModified;
	}

	/**
	 * Zone constructor comment.
	 */
	public Zone() {

	}

	/**
	 * Zone constructor comment.
	 */

	public Zone(File masterFile) throws IOException {
		this();
		this.masterFile = masterFile;
		readZoneInfo();
	}

	/**
	 * Add a resource record based on the info in this list.
	 * the list represents a line from a master file
	 **/
	private void addRR(List<String> list){
		//  See if the dnsClass is specified, it must be the same, then remove it
		String tmp = (String)list.get(2);


		short dnsClass = Utility.classOf(tmp);
		if( dnsClass != 0 ) {
			//  A class is specified
			if( dnsClass != soa.getDnsClass() ) {
				throw new IllegalArgumentException("dnsClass must match SOA dnsClass");
			}
			list.remove(2);
		} else {
			dnsClass = (short)soa.getDnsClass();
		}

		/*
	"UnKnown", "A", "NS", "MD", "MF",
								"CNAME", "SOA", "MB", "MG", "MR",
								"NULL", "WKS", "PTR", "HINFO", "MINFO",
								"MX", "TXT"};
		 */
		// Now the format should be name, ttl, type, rdata


		int type = Utility.typeOf((String)list.get(2));

		RR rr = null;
		String rrName = fixName((String)list.get(0));


		switch ( type ) {
		case  A:  	rr = new A(rrName,dnsClass);
		((A)rr).setAddress((String)list.get(3));
		break;
		case NS:	rr = new Ns(rrName,dnsClass);
		((Ns)rr).setNs(fixName((String)list.get(3)));
		break;
		case CNAME:	rr = new Cname(rrName,dnsClass);
		((Cname)rr).setCname(fixName((String)list.get(3)));
		break;
		case PTR:	rr = new Ptr(rrName,dnsClass);
		((Ptr)rr).setPtr(fixName((String)list.get(3)));
		break;
		case MX:	rr = new Mx(rrName,dnsClass);
		if( list.size() > 4 ) {
			((Mx)rr).setPref((short)Integer.parseInt((String)list.get(3)));
			((Mx)rr).setExchange(fixName((String)list.get(4)));
		} else {
			//  Some 'asshole' ignored the preference!
			((Mx)rr).setExchange(fixName((String)list.get(3)));
		}
		break;


		case SOA: throw new IllegalArgumentException("SOA records can only be at the start of a file");
		case HINFO: Hinfo hi = new Hinfo(rrName,dnsClass);
		rr = hi;
		hi.setCpu((String)list.get(3));
		hi.setOs((String)list.get(4));
		break;


		case TXT:
			Txt txt = new Txt(rrName,dnsClass);
			rr = txt;
			txt.setText((String)list.get(3));
			break;

		case SPF: Spf spf = new Spf(rrName,dnsClass);
		rr = spf;
		spf.setText((String)list.get(3));
		break;

		case MD:
		case MF:
		case MB:
		case MG:
		case MR:
		case NULL:
		case WKS:
		case MINFO:

		default : throw new IllegalArgumentException("Invalid or unsupported type "+type+" from '"+(String)list.get(2));
		}

		int ttl = Utility.toSeconds((String)list.get(1));
		if( ttl < soa.getTTL() ) {
			ttl = soa.getTTL();
		}

		rr.setTTL(ttl);

		addRR(rr);	

	}
	/**
	 * Add a resource record based on the info in this ArrayList.
	 * the ArrayList represents a line from a master file
	 **/
	public void addRR(RR rr){

		Name name = rr.getNameAsName();
		name.setDoWildCard(false);

		List<RR> v = getMatchingRRs(name);
		if( v == null ) {
			v = new ArrayList<RR>();
			names.add(name);		
			rrs.add(names.indexOf(name),v);
		}

		v.add(rr);


	}

	/**
	 * Convert to an absolute name if required
	 **/
	private String fixName(String nm){
		String ret = nm;
		if( ret.equals("@") ) {
			ret = currentName;
		}else if( ret != null && !ret.endsWith(".") ) {
			ret = ret+"."+soa.getName();
		}


		return ret;
	}


	public String [] getLables(){
		if( lables == null && name != null) {
			lables = name.split("[.]");
		}

		return lables;
	}

	private int getMatchingIndex(Name name){
		int ret = -1;
		int wild = -1;
		Name n = null;

		for(int i=0,sz=names.size(); i< sz && ret == -1; i++ ) {
			n = (Name)names.get(i);
			if( n.equals(name) ) {
				if( n.hasWildCard() ) {
					wild = i;
				} else {
					ret = i;
				}
			}
		}

		if( ret == -1 ) {
			ret = wild;
		}

		return ret;
	}

	public RR getMatchingRR(String name, int type){
		RR ret = null;
		List<RR> list = getMatchingRRs(name);

		if( list != null ) {
			for(int i=0,sz=list.size(); i< sz; i++ ) {
				RR rr = (RR)list.get(i);
				if( rr.getType() == type ) {
					ret = rr;
					break;
				}
			}
		}


		return ret;
	}

	public List<RR> getMatchingRRs(String name){
		Name n = new Name(name.toLowerCase());
		List<RR> ret = getMatchingRRs(n);

		return ret;
	}

	public List<RR> getMatchingRRs(Name name){
		int idx = getMatchingIndex(name);

		List<RR> ret = null;
		if( idx >= 0 ) {
			ret = rrs.get(idx);
		}

		return ret;
	}

	/**
	 * Insert the method's description here.
	 * Creation date: (6/17/2003 8:42:12 AM)
	 * @return java.lang.String
	 */
	public java.lang.String getName() {
		return name;
	}

	/**
	 * Insert the method's description here.
	 * Creation date: (6/17/2003 8:42:12 AM)
	 * @return JDns.Soa
	 */
	public us.bringardner.net.dns.Soa getSoa() {
		return soa;
	}

	/**
	 * Insert the method's description here.
	 * Creation date: (8/23/01 1:15:38 PM)
	 * @param args java.lang.String[]
	 */
	public static void main(String[] args)  throws IOException {
		String dir = "C:/temp/DNSFiles";

		if( args.length > 0 ) {
			dir = args[0];
		}

		File f = new File(dir);
		String [] list = f.list();
		if( list == null || list.length == 0 ) {
			System.out.println("No files to load in "+f);
			System.exit(0);
		}

	}

	/**
	 * Parse a line into elements.  I
	 * if the line starts with whitespace set the first element to 'name'
	 */
	private List<String> parseLine(String name, String line) {
		List<String> ret = new ArrayList<String>();
		if( line != null && line.length() > 0 ) {
			byte [] b = line.getBytes();

			if( Character.isWhitespace((char)b[0]) ) {
				ret.add(name);
			}

			int pos = 0;
			StringBuffer buf = new StringBuffer();

			while(pos < b.length ) {
				if( !Character.isWhitespace((char)b[pos]) ) {
					buf.setLength(0);

					while(pos<b.length && !Character.isWhitespace((char)b[pos]) ) {
						if( (char)b[pos] == '"') {
							//  Read everything between quotes
							while(++pos < b.length && (char)b[pos] != '"') {
								buf.append((char)b[pos]);
							}
							++pos;

						} else {
							buf.append((char)b[pos++]);
						}
					}
					ret.add(buf.toString());
				} else {
					pos ++;
				}
			}
		}

		// This is to hanlde those assholes that want to put space in front of every line!!!!!!!
		while( ret.size() > 0 && ret.get(0) == null ) {
			ret.remove(0);
		}

		if( ret.size() > 0 ) {

			String tmp = (String)ret.get(0);
			short dnsClass = Utility.classOf(tmp);
			if( dnsClass > 0 ) {
				//  This line started with a DNS Class
				ret.add(0,name);
			}
		}

		return ret;
	}

	private void populateNs() {
		Message msg = new Message();
		List<RR> list = getMatchingRRs(name);

		if( list != null ) {
			for(int i=0,sz=list.size(); i<sz; i++ ) {
				RR rr  = (RR)list.get(i);
				if( rr.getType() == DNS.NS) {
					msg.addAuthority(rr);
					Ns ns = (Ns)rr;
					RR aa = getMatchingRR(ns.getNs(),DNS.A);
					if( aa != null ) {
						msg.addAdditional(aa);
					}
				}
			}
		}


		//authority = msg.getAuthority();
		//authAddress = msg.getAdditional();

	}


	/**
	 * Read a zone
	 **/

	private String readLine(BufferedReader in) throws IOException {
		String tmp = "";
		StringBuffer ret = new StringBuffer();
		boolean done = true;
		int idx = 0;

		// Read past empty lines
		do {
			if( (tmp = in.readLine()) == null ) {
				if( ret.length() == 0 ) {
					return null;
				} else {
					done = true;
				}
			} else {
				//  string quoted strings
				if(tmp.length() > 0 && tmp.charAt(0) == '#' ) {
					tmp = "";
				} else if( (idx = tmp.indexOf(";")) >= 0 ) {
					int s1 = tmp.indexOf('"');
					if( s1 <0 ) {
						tmp = tmp.substring(0,idx);
					} else {
						int s2 = tmp.indexOf(s1,'"');
						if( idx < s2 ) {
							tmp = tmp.substring(0,idx);
						}
					}
				}
				if( (idx = tmp.indexOf('(')) >= 0 ) {
					tmp = tmp.substring(0,idx);
					done = false;
				} else if( (idx = tmp.indexOf(')')) >= 0 ) {
					tmp = tmp.substring(0,idx);
					done = true;
				}
				ret.append(tmp);
			}
		} while( !done );

		return ret.toString();
	}

	/**
	 * Read a zone
	 **/

	private void readZoneInfo(BufferedReader in)	throws IOException {


		String tmpName = null;
		String line = null;
		String tmp = null;
		List<String> list = null;
		rrs = new ArrayList<List<RR>>();
		names = new ArrayList<Name>();
		//int defTTL = -1;

		int lineNumber=0;
		try {
			while( (line=readLine(in)) != null ) {
				lineNumber++;
				if( line.length() > 0 ) {
					//  Parse the line into values, deleting whitespace
					list = parseLine(tmpName,line);
					if( list.size() < 2 ) {
						//  An invalid line
						continue;
					}
					tmp = (String)list.get(1);
					//  TTL is not specified
					if( !Character.isDigit(tmp.charAt(0)) ) {
						list.add(1,"0");
					}

					tmpName = (String)list.get(0);

					if( tmpName.equals("$TTL") ) {
						try {
							//defTTL = Integer.parseInt(tmp);
						} catch (Exception ex) {}
						continue;
					}


					if( soa == null ) {
						//  This must be an tmpSoa
						Soa tmpSoa = null;

						if( !((String)list.get(3)).equalsIgnoreCase("SOA"))  {
							throw new IOException("tmpSoa must be the first record in the file");
						}

						short sh = us.bringardner.net.dns.Utility.classOf((String)list.get(2));
						if( sh == 0 ) {
							throw new IOException("Invalid dnsClass in tmpSoa record");
						}


						if(!tmpName.equals("@") ) {
							setName(tmpName);
						}
						tmpSoa = new Soa(name,sh);
						tmpSoa.setTTL(us.bringardner.net.dns.Utility.toSeconds((String)list.get(1)));

						tmpSoa.setMname((String)list.get(5));
						tmpSoa.setRname((String)list.get(4));
						tmpSoa.setSerial(us.bringardner.net.dns.Utility.toSeconds((String)list.get(6)));
						tmpSoa.setRefreash(us.bringardner.net.dns.Utility.toSeconds((String)list.get(7)));
						tmpSoa.setRetry(us.bringardner.net.dns.Utility.toSeconds((String)list.get(8)));
						tmpSoa.setExpire(us.bringardner.net.dns.Utility.toSeconds((String)list.get(9)));
						tmpSoa.setMinimum(us.bringardner.net.dns.Utility.toSeconds((String)list.get(10)));

						if( tmpSoa.getTTL() < tmpSoa.getMinimum() ) {
							tmpSoa.setTTL(tmpSoa.getMinimum()) ;
						}

						setSoa(tmpSoa);
						currentName = getName();
					} else {
						addRR(list);
					}


				}
			}
		} catch(Throwable e) {
			throw new IOException("Error near line "+lineNumber,e);
		}
		setWildCards(true);
		populateNs();
	}

	/**
	 * Read a zone
	 **/

	private void readZoneInfo() throws IOException {
		lastModified = masterFile.lastModified();
		fileName = masterFile.getName();
		int idx = fileName.lastIndexOf('.');
		if( idx >0) {
			name = fileName.substring(0,idx);
		}
		idx = name.lastIndexOf('/') ;
		if( idx == -1 ) {
			idx = name.lastIndexOf('\\') ;
		}
		if( idx != -1 ) {
			name = name.substring(idx+1);
		}

		BufferedReader in = new BufferedReader(new FileReader(masterFile));
		try {
			readZoneInfo(in);
		} finally {
			in.close();	
		}

	}

	/**
	 * Add helpful local info
	 * This is basically the NS records for the domain 
	 * and their A records if available.
	 **/
	public void setLocalInfo(Message ret) {

		if( ret.getAnswerCount() == 0 && ret.getNSCount()==0) {
			ret.addAuthority(soa);
		}
	}

	/**
	 * Insert the method's description here.
	 * Creation date: (6/17/2003 8:42:12 AM)
	 * @param newName java.lang.String
	 */
	public void setName(java.lang.String newName) {
		name = newName;
		lables = null;
	}

	/**
	 * Insert the method's description here.
	 * Creation date: (6/17/2003 8:42:12 AM)
	 * @param newSoa JDns.Soa
	 */
	public void setSoa(us.bringardner.net.dns.Soa newSoa)  {

		soa = newSoa;
		if( name.equals("@") ) {
			//  Get the primary dns server name
			String tmp = soa.getName();
			setName(tmp);
		}
	}

	public void setWildCards(boolean b) {

		for(int i=0,sz=names.size(); i<sz; i++ ) {
			Name name = (Name)names.get(i);
			name.setDoWildCard(b);
		}
	}

	public String toString() {
		StringBuffer ret = new StringBuffer( "Zone:"+name+"\r\n"+soa);


		for(int ix=0,szx=rrs.size(); ix < szx; ix++ ) {
			List<RR> list = rrs.get(ix);
			for(int i=0,sz=list.size(); i<sz; i++ ) {
				ret.append("\r\n");
				ret.append(list.get(i).toString());
			}
		}
		return ret.toString();
	}

	public String toString(boolean fileFormat) {
		StringBuffer ret = new StringBuffer();

		if( fileFormat ) {
			/*
			@	IN	SOA	dns.minEmall.com. postmaster.minEmall.com. (
			2003100900      ; serial
                        3600    ; refresh (1 hour)
                        1800    ; retry (30 mins)
                        604800  ; expire (7 days)
                        3600 )  ; minimum (1 hour)

			 */
			ret.append(name);
			ret.append("\t");
			ret.append(Utility.CLASSNAMES[soa.getDnsClass()]);
			ret.append("\t");
			ret.append("SOA\t");
			ret.append(soa.getRdataAsString());
			ret.append('\n');
			//int c = 0;


			for(int ix=0,szx=rrs.size(); ix < szx; ix++ ) {
				List<RR> list = rrs.get(ix);
				String tmp = "";
				//String tmp1 = "";
				for(int i=0,sz=list.size(); i<sz; i++ ) {
					ret.append("\n");
					RR rr = (RR)list.get(i);
					tmp = rr.getName();
					if( i > 0 ) {
						// same name
						tmp = "";
					} else {
						tmp+=".";
					}

					ret.append(tmp);
					ret.append('\t');

					ret.append(Utility.CLASSNAMES[rr.getDnsClass()]);
					ret.append('\t');
					ret.append(Utility.TYPENAMES[rr.getType()]);
					ret.append('\t');
					ret.append(rr.getRdataAsString());
				}
			}



		} else {
			ret.append( "Zone:"+name+"\r\n"+soa);


			for(int ix=0,szx=rrs.size(); ix < szx; ix++ ) {
				List<RR> list = rrs.get(ix);
				for(int i=0,sz=list.size(); i<sz; i++ ) {
					ret.append("\r\n");
					ret.append(list.get(i).toString());
				}
			}
		}

		return ret.toString();
	}

	public File getMasterFile() {
		return masterFile;
	}
}
