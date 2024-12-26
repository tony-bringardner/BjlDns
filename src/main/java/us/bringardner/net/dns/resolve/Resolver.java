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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import us.bringardner.net.dns.Cname;
import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.DnsBaseClass;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.Section;
import us.bringardner.net.dns.server.DnsServer;

public class Resolver  extends DnsBaseClass
{
	private static final String PROP_MAX_DNS_CACHE_AGE = "JDns.maxCacheAge";

	private static final String PROP_RESOLVER_COUNT = "JDns.resolvers";

	private static Cache cache = new Cache();

	//  This is created ahead of time in case we're out of memory & want to reset things
	private static Cache safty = new Cache();

	private static List<RemoteServer> sbelt = new ArrayList<RemoteServer>();
	//  this is used to 'round robin' the starting server	
	//  so that we don't always use the same one (spread the load)
	//private static int current=0;
	//private static int sbeltSize;
	private static Map<String,List<RemoteServer>> servers = new HashMap<String, List<RemoteServer>>();
	private static ResolverThread [] resolvers;
	private static int started = 0;
	private static int completed = 0;
	private static int min = 9999999;
	private static int max = 0;
	private static int ave = 0;
	private static double timeAccum = 0.0;

	private static void addServer(RemoteServer svr) {
		if( svr != null ) {
			List<RemoteServer> al = (List<RemoteServer>)servers.get(svr.getName());
			if( al == null ) {
				al = new ArrayList<RemoteServer>();
				servers.put(svr.getName(),al);
			}
			al.add(svr);
		}
	}
	
	public static int cacheSize() {
		int ret = cache.size();
		return ret;
	}
	
	public static int getAve() {
		return ave;
	}
	
	public static int getCompleted() {
		return completed;
	}

	/*
	private synchronized static int getCurrent() {

		if( ++current >= sbeltSize ) {
			current = 0;
		}	
		return current;
	}	
	 */

	public static int getMax()	{
		return max;
	}

	public static int getMin()	{
		return min;
	}

	/**
	 * 
	 * Creation date: (10/16/2003 9:53:14 AM)
	 * @return JDns.resolve.ResolverThread[]
	 */
	public static us.bringardner.net.dns.resolve.ResolverThread[] getResolvers() {
		return resolvers;
	}

	//	Find cached servers closest to this name
	private static List<RemoteServer> getServers(Section nm) {
		String key = nm.getName().toLowerCase();
		List<RemoteServer> ret = servers.get(key);
		if( ret != null ) {
			//  Make sure it has an active server
			Iterator<RemoteServer> it = ret.iterator();
			boolean useit = false;
			while(it.hasNext()) {
				if( ((RemoteServer)it.next()).isActive())  {
					useit = true;
					break;
				}
			}

			if( !useit ) {
				ret = null;
			}
		}

		//  If no active server exists, search for one 'further'
		// from the question.
		if( ret == null ) {
			String parent = nm.getParentName();
			if( parent == null || parent.length() == 0 ) {
				ret = sbelt;
			} else {
				ret = getServers(new Section(parent,DNS.NS,nm.getDnsClass()));
			}
		}

		return ret;
	}

	public static int getStarted()	{
		return started;
	}

	public static String getStats()	{
		String ret =

				"Resolver Cache size="+cacheSize()+" RemoteServer size="+servers.size()+
				"\n Resolver capacity="+us.bringardner.net.dns.resolve.ResolverThread.getMaxBackLog()+
				"  current="+us.bringardner.net.dns.resolve.ResolverThread.getBacklog()+
				"\nResolver Stats: inflight="+(started-completed)+
				" completed="+completed+
				" min="+min+
				" max="+max+
				" ave="+ave
				;

		return ret;
	}

	protected static synchronized void incComplted(int time, Section question) {
		completed++;
		if( min > time ) {
			min = time;
		}
		if( max < time ) {
			max = time;
		}
		timeAccum+= time;

		ave = (int)(timeAccum / (double)completed);

		if( time > 5000 ) {
			Resolver logger = new Resolver();
			logger.logDebug("Long search time="+time+" que="+question);
		}	
	}

	protected static synchronized void incStart() {
		started++;
	}

	public static void initResolver() throws IOException	{
		//  Assume that this has been populated by the Server
		Properties prop = System.getProperties();
		String dnsDir = null;


		if( (dnsDir=prop.getProperty(DnsServer.PROP_DNS_DIR)) == null ) {
			dnsDir = DnsServer.DEFAULT_DNS_DIR;
		}


		java.io.File f = new File(dnsDir,"sbelt.prop");


		//  First load the properties from the file
		Properties p = new Properties();
		if( f.exists() ) {
			InputStream in = new FileInputStream(f);
			try {
				p.load(in);
			} finally {
				try {
					in.close();
				} catch (Exception e) {
				}
			} 
		}

		Iterator<Object> it = p.keySet().iterator();

		while( it.hasNext() ) {
			String key = (String)it.next();
			RemoteServer svr = new RemoteServer(key);
			String val = p.getProperty(key);
			// format hostname=ip4,ip6,org name
			String parts[] = val.split(",");
			String ip4 = parts[0];
			svr.addAddress(key,ip4);
			sbelt.add(svr);
		}
		//sbeltSize = sbelt.size();

		String tmp = null;

		if( (tmp=prop.getProperty(PROP_MAX_DNS_CACHE_AGE)) != null ) {
			try {
				Cache.setDefaultMaxAge(Long.parseLong(tmp));
			} catch(Exception ex) {
				Resolver logger = new Resolver();
				logger.logError("Error setting maxCacheAge",ex);
			}
		}

		int resolverCount = 10;

		if( (tmp=prop.getProperty(PROP_RESOLVER_COUNT)) != null ) {
			try {
				resolverCount = Integer.parseInt(tmp);
			} catch(Exception ex){}
		}

		resolvers = new ResolverThread[resolverCount];

		for(int i=0; i<resolverCount; i++ ) {
			resolvers[i] = new ResolverThread();
			resolvers[i].start("ResolverThread"+i);
		}


	}

	public static void initResolver(String[] args) throws IOException {
		for(int i=0; i< args.length; i++ ) {
			System.setProperty(args[i],args[++i]);
		}
		initResolver();
	}
	
	public static void main(String[] args) throws IOException {
		initResolver(args);

		String que = null;
		boolean done = false;
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));

		Message ans = null;

		while( !done ) {
			if( (que=in.readLine()) == null || que.equalsIgnoreCase("exit")) {
				done = true;
				continue;
			}
			if( que.endsWith("arpa") ) {
				ans = resolve(que,DNS.PTR,DNS.IN);
			} else {
				ans = resolve(que);
			}
			if ( ans == null ) {
				System.out.println("No answer availible fo r"+que);
			} else {
				System.out.println(ans.toString());
			}
		}

	}
	
	public static void removeOld() {
		cache.removeOld();
	}
	
	public static void reset() {
		cache = safty;
		System.gc();
		safty = new Cache();
		servers = new HashMap<String,List<RemoteServer>>();
	}
	/**
	 * Attempt to get an answer to a question
	 **/
	public static Message resolve(String name) {
		return resolve(name,DNS.A,DNS.IN);
	}
	
	/**
	 * Attempt to get an answer to a question
	 **/
	public static Message resolve(String name, int type, int dnsClass)  {
		return resolve(new Section(name,type,dnsClass));
	}
	
	public static Message resolve(Section question) {
		Message ret = null;

		incStart();
		long time = System.currentTimeMillis();

		if( (ret=cache.get(question)) == null ) {
			//  Nothing in cache, search for it
			if( (ret=resolve(question, getServers(question))) != null ) {
				cache.put(ret);						
			}
		}



		//  If this is the first time for a CNAME, AnswerCount should be 1
		//  If it's grater than that, it's already been combined
		if( ret != null && ret.getAnswerCount() == 1 ) {
			//  Check for CNAME
			RR rr = (RR)ret.getAnswer().get(0);
			if( rr.getType() == DNS.CNAME && question.getType() != DNS.CNAME ) {
				Message ret2 = resolve(new Section(((Cname)rr).getCname(),question.getType(),question.getDnsClass()));
				if( ret2 == null ) {
					ret = ret2;
				} else {
					//  Combine the results
					ret.combine(ret2);
					//  Need to do this so that expirte will work correctly
					cache.put(ret);

				}
			}
		}


		incComplted((int)(System.currentTimeMillis()-time),question);

		return ret;
	}

	private static Message resolve(Section question, List<RemoteServer> slist) {

		Message ret = null;
		//  OK Loop through each server in the slist until we get a response
		RemoteServer svr = null;

		long maxTime = System.currentTimeMillis()+4000;
		for(int idx=0,sz=slist.size(); idx < sz; idx++ ) {
			svr = slist.get(idx);
			if( svr.isActive() ) {
				if( (ret = svr.resolve(question,maxTime)) != null) {
					if( ret.isRecursive() ) {
						//The server did the work so we're done
						break;
					}

					//  Got something.  It could be an answer or a delegation
					if( ret.getResponseCode() != DNS.NOERROR || ret.getAnswerCount() > 0 ) {
						//  Got it
						break;
					}
					//  Check for a delegation here
					if( ret.getNSCount() > 0 ) {
						//  a delegation
						RemoteServer svr2 = new RemoteServer(ret);

						if( svr2 != null && svr.matchCount(question) < svr2.matchCount(question) ) {
							//  This set of servers is 'closer' to the
							//  answer, so cache it 
							addServer(svr2);
							// and use them instead.
							slist = new ArrayList<RemoteServer>(1);
							slist.add(svr2);
							//TODO:  Major testing here
							return resolve(question,slist);
						}

					}
				}
			}
		}

		return ret;
	}
	
	public static void shutDown() {
		for(int i=0; i< resolvers.length; i++ ) {
			resolvers[i].stop();
		}
		//ResolverThread.notifyThreads();
	}
}
