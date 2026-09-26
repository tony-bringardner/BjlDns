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
 */
package us.bringardner.net.dns;

/**
 * The HTTPS resource record (RFC 9460): an SVCB record for HTTPS origins.
 */
public class Https extends Svcb {

	public Https() {
		super("", HTTPS, IN);
	}

	public Https(String name) {
		super(name, HTTPS, IN);
	}

	public Https(String name, int dnsClass) {
		super(name, HTTPS, dnsClass);
	}

	/** A record from a generic record read from the wire. */
	public Https(RR rr) {
		super(rr);
	}

	@Override
	public RR copy() {
		Https ret = new Https();
		copyTo(ret);
		return ret;
	}
}
