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
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

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
	public static final String PROP_MAX_CACHE_ENTRIES = "JDns.maxCacheEntries";
	public static final String PROP_CACHE_SWEEP_SECONDS = "JDns.cacheSweepSeconds";
	//  Periodically removes expired cache entries
	private static java.util.concurrent.ScheduledExecutorService cacheSweeper;

	private static volatile Cache cache = new Cache();

	//  This is created ahead of time in case we're out of memory & want to reset things
	private static volatile Cache safty = new Cache();

	private static final List<RemoteServer> sbelt = new CopyOnWriteArrayList<RemoteServer>();
	//  this is used to 'round robin' the starting server	
	//  so that we don't always use the same one (spread the load)
	//private static int current=0;
	//private static int sbeltSize;
	public static final String PROP_MAX_DELEGATIONS = "JDns.maxDelegations";
	public static final String PROP_DELEGATION_MAX_AGE = "JDns.delegationMaxAge";

	/** A zone's name servers learned from a referral. */
	private static final class Delegation {
		final RemoteServer server;
		final long learnedAt;
		Delegation(RemoteServer server, long learnedAt) {
			this.server = server;
			this.learnedAt = learnedAt;
		}
	}

	private static volatile int maxDelegations = 10000;
	//  How long a learned delegation is used before it is replaced by a fresh referral (ms)
	private static volatile long delegationMaxAge = 60*60*1000L;

	/**
	 * Delegations learned while resolving: lower case zone name -> ONE
	 * RemoteServer per zone (later referrals merge their addresses into it).
	 * LRU bounded by maxDelegations. Guarded by synchronized(servers); it is
	 * used by every ResolverThread.
	 */
	private static final Map<String,Delegation> servers = new LinkedHashMap<String,Delegation>(64, 0.75f, true) {
		private static final long serialVersionUID = 1L;
		@Override
		protected boolean removeEldestEntry(Map.Entry<String,Delegation> eldest) {
			return size() > maxDelegations;
		}
	};
	private static ResolverThread [] resolvers;
	private static int started = 0;
	private static int completed = 0;
	private static int min = 9999999;
	private static int max = 0;
	private static int ave = 0;
	private static double timeAccum = 0.0;

	/**
	 * Remember the name servers from a referral.
	 * <p>
	 * There is one RemoteServer per zone. If a fresh one is already known,
	 * the new addresses are merged into it (so each address keeps its
	 * statistics and deactivation state) and the known instance is returned.
	 * The old code appended a new RemoteServer on every referral, so the list
	 * grew forever and a dead server was queried again with a clean slate.
	 * 
	 * @return the RemoteServer to use for this zone
	 */
	static RemoteServer addServer(RemoteServer svr) {
		//  getName() is null when the referral had no NS records
		if( svr == null || svr.getName() == null ) {
			return svr;
		}
		//  Keys are lower case: getServers() looks up the lower case question name
		String key = svr.getName().toLowerCase();
		long now = System.currentTimeMillis();
		synchronized (servers) {
			Delegation d = servers.get(key);
			if( d != null && (now - d.learnedAt) < delegationMaxAge ) {
				d.server.mergeAddresses(svr);
				return d.server;
			}
			servers.put(key, new Delegation(svr, now));
			return svr;
		}
	}

	/** @return the known, fresh delegation for this exact zone name, or null */
	static RemoteServer getDelegation(String zone) {
		String key = zone.toLowerCase();
		synchronized (servers) {
			Delegation d = servers.get(key);
			if( d == null ) {
				return null;
			}
			if( (System.currentTimeMillis() - d.learnedAt) >= delegationMaxAge ) {
				servers.remove(key);
				return null;
			}
			return d.server;
		}
	}

	public static int delegationCount() {
		synchronized (servers) {
			return servers.size();
		}
	}

	public static void setMaxDelegations(int max) {
		synchronized (servers) {
			maxDelegations = max > 0 ? max : 1;
			Iterator<String> it = servers.keySet().iterator();
			while( servers.size() > maxDelegations && it.hasNext() ) {
				it.next();
				it.remove();
			}
		}
	}

	/** @param ms how long a learned delegation is used before a fresh referral replaces it */
	public static void setDelegationMaxAge(long ms) {
		delegationMaxAge = ms;
	}
	
	public static int cacheSize() {
		int ret = cache.size();
		return ret;
	}
	
	public static synchronized int getAve() {
		return ave;
	}
	
	public static synchronized int getCompleted() {
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

	public static synchronized int getMax()	{
		return max;
	}

	public static synchronized int getMin()	{
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
		List<RemoteServer> ret = null;
		RemoteServer known = getDelegation(nm.getName());
		//  Only use it if it has an active server
		if( known != null && known.isActive() ) {
			ret = Collections.singletonList(known);
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

	public static synchronized int getStarted()	{
		return started;
	}

	public static String getStats()	{
		String ret =

				"Resolver Cache size="+cacheSize()+"/"+cache.getMaxEntries()+" Delegations="+delegationCount()+"/"+maxDelegations+
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

		if( (tmp=prop.getProperty(PROP_MAX_CACHE_ENTRIES)) != null ) {
			try {
				int max = Integer.parseInt(tmp.trim());
				Cache.setDefaultMaxEntries(max);
				cache.setMaxEntries(max);
				safty.setMaxEntries(max);
			} catch(Exception ex) {
				Resolver logger = new Resolver();
				logger.logError("Error setting "+PROP_MAX_CACHE_ENTRIES,ex);
			}
		}
		startCacheSweeper(prop);

		if( (tmp=prop.getProperty(PROP_MAX_DELEGATIONS)) != null ) {
			try {
				setMaxDelegations(Integer.parseInt(tmp.trim()));
			} catch(Exception ex) {
				new Resolver().logError("Error setting "+PROP_MAX_DELEGATIONS,ex);
			}
		}
		if( (tmp=prop.getProperty(PROP_DELEGATION_MAX_AGE)) != null ) {
			try {
				setDelegationMaxAge(Long.parseLong(tmp.trim())*1000L);
			} catch(Exception ex) {
				new Resolver().logError("Error setting "+PROP_DELEGATION_MAX_AGE,ex);
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

	/** Remove expired entries from the cache. @return number removed */
	public static int removeExpired() {
		return cache.removeExpired();
	}

	private static synchronized void startCacheSweeper(Properties prop) {
		if( cacheSweeper != null ) {
			return;
		}
		long seconds = 60;
		String tmp = prop.getProperty(PROP_CACHE_SWEEP_SECONDS);
		if( tmp != null ) {
			try {
				seconds = Math.max(1, Long.parseLong(tmp.trim()));
			} catch(Exception ex) {}
		}
		cacheSweeper = java.util.concurrent.Executors.newSingleThreadScheduledExecutor(r -> {
			Thread t = new Thread(r,"ResolverCacheSweeper");
			t.setDaemon(true);
			return t;
		});
		cacheSweeper.scheduleWithFixedDelay(() -> {
			try {
				removeExpired();
			} catch(Throwable ex) {
				new Resolver().logError("Cache sweep failed",ex);
			}
		}, seconds, seconds, java.util.concurrent.TimeUnit.SECONDS);
	}

	private static synchronized void stopCacheSweeper() {
		if( cacheSweeper != null ) {
			cacheSweeper.shutdownNow();
			cacheSweeper = null;
		}
	}
	
	public static void reset() {
		cache = safty;
		System.gc();
		safty = new Cache();
		synchronized (servers) {
			servers.clear();
		}
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
		incStart();
		long time = System.currentTimeMillis();

		Message ret = resolveChain(question, new HashSet<String>(), 0);

		incComplted((int)(System.currentTimeMillis()-time),question);

		return ret;
	}

	/**
	 * Resolve 'question', following a CNAME answer to its target.
	 * <p>
	 * The chain is limited to QueryData.MAX_CNAME_CHAIN hops and a name is
	 * never followed twice, so a loop (a -> b -> a) ends with the chain found
	 * so far instead of recursing until StackOverflowError.
	 * 
	 * @param seen lower case names already visited in this chain
	 * @param depth number of CNAMEs followed so far
	 */
	private static Message resolveChain(Section question, Set<String> seen, int depth) {
		seen.add(question.getName().toLowerCase());

		Message ret = cache.get(question);
		if( ret == null ) {
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
				String target = ((Cname)rr).getCname();
				if( depth >= QueryData.MAX_CNAME_CHAIN || seen.contains(target.toLowerCase()) ) {
					new Resolver().logError("CNAME loop or chain too long at "+question.getName()+" -> "+target
							+" (followed "+depth+"), returning the chain so far");
					return ret;
				}
				Message ret2 = resolveChain(new Section(target,question.getType(),question.getDnsClass()), seen, depth+1);
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

		return ret;
	}

	/** For tests: the live cache. */
	static Cache getCache() {
		return cache;
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
							//  (the zone's known RemoteServer, with these addresses merged in)
							RemoteServer use = addServer(svr2);
							// and use them instead.
							slist = Collections.singletonList(use);
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
		stopCacheSweeper();
		for(int i=0; resolvers != null && i< resolvers.length; i++ ) {
			resolvers[i].stop();
		}
		//ResolverThread.notifyThreads();
	}
}
