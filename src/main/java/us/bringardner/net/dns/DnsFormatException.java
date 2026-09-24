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
package us.bringardner.net.dns;

/**
 * Thrown when a DNS message on the wire is malformed (RFC 1035 FORMERR),
 * for example a compression pointer loop, an over-long name or a name
 * that runs past the end of the message.
 * 
 * Unchecked so it can propagate out of the existing RR / Message constructors
 * without changing their signatures.
 */
public class DnsFormatException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public DnsFormatException(String message) {
		super(message);
	}
}
