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
/**
 * SPF RR as defined in RFC 4408 is basically a TXT
 * 
 * @author E015887
 *
 */
public class Spf extends Txt {

	public Spf() {
		super();
		setType(SPF);
	}

	public Spf(String name) {
		super(name);
		setType(SPF);
	}

	public Spf(String name, int dnsClass) {
		super(name, dnsClass);
		setType(SPF);
	}

	public Spf(RR rr) {
		super(rr);
	}

}
