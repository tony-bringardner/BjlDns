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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.LongSupplier;

import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.DnsBaseClass;
import us.bringardner.net.dns.Header;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.RR;
import us.bringardner.net.dns.Section;

/**
 * Resolver cache.
 * <p>
 * Thread-safety / immutability: a cached response is stored as a private
 * {@link Entry} holding deep copies of the header, question and RRs. The
 * stored objects are never handed out. Every {@link #get(Section)} builds a
 * brand new {@link Message} with fresh RR copies, so callers may freely
 * set the ID, set TC, combine, or serialize the result without affecting
 * the cache or other threads.
 * <p>
 * Expiry: an entry lives until the smallest answer TTL runs out (capped by
 * {@link #getDefaultMaxAge()}). TTLs in returned messages are the time
 * remaining, as RFC 1035 requires of a caching server. Authority and
 * additional records whose own TTL has run out are dropped from the result.
 * <p>
 * Size: the cache is an LRU bounded by {@link #getMaxEntries()}; the least
 * recently used entry is evicted when full. {@link #removeExpired()} sweeps
 * expired entries and is called periodically by the Resolver.
 * <p>
 * Keys are case-insensitive (RFC 4343).
 * 
 * @author: Tony Bringardner
 */
public class Cache extends DnsBaseClass
{
	/** Absolute cap on how long anything is cached (ms), regardless of TTL. */
	private static volatile long defaultMaxAge = 1000*60*30;
	private static volatile int defaultMaxEntries = 10000;

	/**
	 * Immutable snapshot of one response. Lists are unmodifiable and the
	 * objects inside are private copies that never leave this class.
	 */
	static final class Entry {
		final Header header;
		final Section question;
		final List<RR> answer;
		final List<RR> authority;
		final List<RR> additional;
		/** when stored (ms) */
		final long storedAt;
		/** when the entry must no longer be served (ms) */
		final long expiresAt;

		Entry(Header header, Section question, List<RR> answer, List<RR> authority, List<RR> additional,
				long storedAt, long expiresAt) {
			this.header = header;
			this.question = question;
			this.answer = answer;
			this.authority = authority;
			this.additional = additional;
			this.storedAt = storedAt;
			this.expiresAt = expiresAt;
		}

		boolean isExpired(long now) {
			return now >= expiresAt;
		}
	}

	private volatile int maxEntries;
	//  Source of 'now' in ms (replaceable for tests)
	private final LongSupplier clock;

	//  access-order LinkedHashMap == LRU. Guarded by 'this'.
	private final LinkedHashMap<String, Entry> cache = new LinkedHashMap<String, Entry>(64, 0.75f, true) {
		private static final long serialVersionUID = 1L;
		@Override
		protected boolean removeEldestEntry(Map.Entry<String, Entry> eldest) {
			return size() > maxEntries;
		}
	};

	public Cache() {
		this(defaultMaxEntries);
	}

	public Cache(int maxEntries) {
		this(maxEntries, System::currentTimeMillis);
	}

	/** For tests: supply the clock (ms). */
	Cache(int maxEntries, LongSupplier clock) {
		this.maxEntries = maxEntries > 0 ? maxEntries : 1;
		this.clock = clock;
	}

	/**
	 * Get a cached response for this question.
	 * 
	 * @return a NEW Message owned by the caller (safe to modify), or null
	 *  if nothing usable is cached.
	 */
	public Message get(Section question) {
		if( question == null ) {
			return null;
		}
		String key = getKey(question);
		long now = clock.getAsLong();
		Entry e;
		synchronized (this) {
			e = cache.get(key);
			if( e != null && e.isExpired(now) ) {
				cache.remove(key);
				e = null;
			}
		}
		return e == null ? null : toMessage(e, now);
	}

	/**
	 * Cache this response. The message is deep-copied; later changes to
	 * msg by the caller do not affect the cache.
	 * <p>
	 * Not cached: null, no question, no answers (negative caching is not
	 * done yet), or any answer with a TTL of 0 (RFC 1035: do not cache).
	 */
	public void put(Message msg) {
		if( msg == null || msg.getQuestionCount() == 0 || msg.getAnswerCount() == 0 ) {
			return;
		}

		long minTtl = Long.MAX_VALUE;
		for(RR rr : msg.getAnswer()) {
			minTtl = Math.min(minTtl, ttlOf(rr));
		}
		if( minTtl <= 0 ) {
			return;
		}

		long now = clock.getAsLong();
		long life = Math.min(minTtl * 1000L, defaultMaxAge);
		if( life <= 0 ) {
			return;
		}

		Entry e = new Entry(
				msg.getHeader().copy(),
				new Section(msg.getFirstQuestion()),
				copyAll(msg.getAnswer()),
				copyAll(msg.getAuthority()),
				copyAll(msg.getAdditional()),
				now,
				now + life);

		String key = getKey(msg.getFirstQuestion());
		synchronized (this) {
			cache.put(key,e);
		}
	}

	/** Build a fresh Message from an entry with TTLs adjusted to the time remaining. */
	private static Message toMessage(Entry e, long now) {
		long elapsedSec = (now - e.storedAt) / 1000L;
		Message ret = new Message();
		ret.setHeader(e.header.copy());
		ret.setQuestion(new Section(e.question));
		for(RR rr : e.answer) {
			RR c = copyWithRemainingTtl(rr, elapsedSec, now);
			if( c != null ) {
				ret.addAnswer(c);
			}
		}
		for(RR rr : e.authority) {
			RR c = copyWithRemainingTtl(rr, elapsedSec, now);
			if( c != null ) {
				ret.addAuthority(c);
			}
		}
		for(RR rr : e.additional) {
			RR c = copyWithRemainingTtl(rr, elapsedSec, now);
			if( c != null ) {
				ret.addAdditional(c);
			}
		}
		return ret;
	}

	/** @return a copy with TTL reduced by elapsedSec, or null if that record has expired. */
	private static RR copyWithRemainingTtl(RR rr, long elapsedSec, long now) {
		long remaining = ttlOf(rr) - elapsedSec;
		if( remaining <= 0 ) {
			return null;
		}
		RR c = rr.copy();
		c.setTTL((int)remaining);
		c.setInitTime(now);
		return c;
	}

	/** TTL is an unsigned 32 bit value on the wire (RFC 2181 8: values above 2^31-1 are treated as 0). */
	private static long ttlOf(RR rr) {
		int ttl = rr.getTTL();
		return ttl < 0 ? 0 : ttl;
	}

	private static List<RR> copyAll(List<RR> list) {
		if( list == null || list.isEmpty() ) {
			return Collections.emptyList();
		}
		List<RR> ret = new ArrayList<RR>(list.size());
		for(RR rr : list) {
			// OPT (EDNS) is per-hop metadata; its TTL field holds flags. Never cache it (RFC 6891 6.1.1).
			if( rr.getType() != DNS.OPT ) {
				ret.add(rr.copy());
			}
		}
		return Collections.unmodifiableList(ret);
	}

	public static long getDefaultMaxAge() {
		return defaultMaxAge;
	}

	public static void setDefaultMaxAge(long newDefaultMaxAge) {
		defaultMaxAge = newDefaultMaxAge;
	}

	public static int getDefaultMaxEntries() {
		return defaultMaxEntries;
	}

	/** Size limit used by caches created after this call. */
	public static void setDefaultMaxEntries(int max) {
		defaultMaxEntries = max > 0 ? max : 1;
	}

	public int getMaxEntries() {
		return maxEntries;
	}

	/** Change this cache's size limit, evicting least recently used entries if needed. */
	public void setMaxEntries(int max) {
		synchronized (this) {
			maxEntries = max > 0 ? max : 1;
			Iterator<String> it = cache.keySet().iterator();
			while( cache.size() > maxEntries && it.hasNext() ) {
				it.next();
				it.remove();
			}
		}
	}

	/**
	 * Case-insensitive key. The separator prevents collisions such as
	 * name "x1" type 1 vs name "x" type 11.
	 */
	public static String getKey(Section question) {
		return question.getName().toLowerCase()+'|'+question.getType()+'|'+question.getDnsClass();
	}

	/** Remove all entries whose TTL has run out. @return number removed */
	public int removeExpired() {
		long now = clock.getAsLong();
		int cnt = 0;
		synchronized (this) {
			Iterator<Entry> it = cache.values().iterator();
			while( it.hasNext() ) {
				if( it.next().isExpired(now) ) {
					it.remove();
					cnt++;
				}
			}
		}
		return cnt;
	}

	/** Remove any entry stored longer ago than defaultMaxAge (and anything expired). */
	public void removeOld() {
		removeOld(defaultMaxAge);	
	}

	/** Remove any entry stored more than 'time' ms ago (and anything expired). */
	public void removeOld(long time) {
		long now = clock.getAsLong();
		synchronized (this) {
			Iterator<Entry> it = cache.values().iterator();
			while( it.hasNext() ) {
				Entry e = it.next();
				if( (now - e.storedAt) > time || e.isExpired(now) ) {
					it.remove();
				}
			}
		}
	}

	public int size() {
		synchronized (this) {
			return cache.size();
		}
	}

	/** Remove everything. */
	public void clear() {
		synchronized (this) {
			cache.clear();
		}
	}
}
