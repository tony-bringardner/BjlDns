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
 */
package us.bringardner.net.dns.resolve;

import java.util.Collections;
import java.util.List;

import us.bringardner.net.dns.DNS;
import us.bringardner.net.dns.Message;

/**
 * The outcome of a {@link Lookup}: a status and, when the status is
 * {@link Status#OK}, the records found.
 * <p>
 * The statuses are the distinctions SPF (RFC 7208 5), DKIM (RFC 6376 6.1.2)
 * and DMARC (RFC 7489 6.6.3) make: no such name, a name without records of
 * the type, or a temporary failure that should be retried later.
 *
 * @param <T> the record value type (String for TXT, InetAddress for A...)
 */
public final class LookupResult<T> {

	public enum Status {
		/** Records of the type were found. */
		OK,
		/** The name does not exist (RCODE 3, NXDOMAIN). */
		NXDOMAIN,
		/** The name exists but has no records of the type (NOERROR, empty answer). */
		NODATA,
		/**
		 * No usable answer: timeout, no server reachable, or an error RCODE
		 * other than NXDOMAIN (SERVFAIL, REFUSED...). Retrying later may work.
		 */
		TEMPFAIL
	}

	private final String name;
	private final int type;
	private final Status status;
	private final List<T> values;
	private final int rcode;
	private final Message message;

	LookupResult(String name, int type, Status status, List<T> values, int rcode, Message message) {
		this.name = name;
		this.type = type;
		this.status = status;
		this.values = values == null ? Collections.<T>emptyList() : Collections.unmodifiableList(values);
		this.rcode = rcode;
		this.message = message;
	}

	/** The name asked. */
	public String getName() {
		return name;
	}

	/** The record type asked (DNS.TXT...). */
	public int getType() {
		return type;
	}

	public Status getStatus() {
		return status;
	}

	/** The values found, in answer order (MX sorted by preference); empty unless OK. */
	public List<T> getValues() {
		return values;
	}

	/** The first value, or null if there is none. */
	public T getFirst() {
		return values.isEmpty() ? null : values.get(0);
	}

	/** The response RCODE, or -1 if there was no response. */
	public int getRcode() {
		return rcode;
	}

	/** The response the result came from (null if there was none), for TTLs, DNSSEC flags... */
	public Message getMessage() {
		return message;
	}

	public boolean isOk() {
		return status == Status.OK;
	}

	/** True for NXDOMAIN and NODATA: an answer that there is nothing to find. */
	public boolean isNotFound() {
		return status == Status.NXDOMAIN || status == Status.NODATA;
	}

	public boolean isTempFail() {
		return status == Status.TEMPFAIL;
	}

	@Override
	public String toString() {
		return name+" "+typeName(type)+" "+status+(status == Status.OK ? " "+values : "");
	}

	static String typeName(int t) {
		return t >= 0 && t < DNS.TYPENAMES.length && !DNS.TYPENAMES[t].isEmpty() ? DNS.TYPENAMES[t] : "TYPE"+t;
	}
}
