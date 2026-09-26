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

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Reads a system property that was renamed: the new name wins; the old name
 * still works but logs (once) that it is deprecated. All BjlDns properties
 * are named JDns.*; a few used to have other names.
 */
public final class RenamedProperty extends DnsBaseClass {

	private static final RenamedProperty LOG = new RenamedProperty();
	private static final Set<String> warned = ConcurrentHashMap.newKeySet();

	private RenamedProperty() {
	}

	/**
	 * @return the value of name, else of oldName (logging that it is
	 * deprecated), else null
	 */
	public static String get(String name, String oldName) {
		String v = System.getProperty(name);
		if( v != null ) {
			return v;
		}
		v = System.getProperty(oldName);
		if( v != null && warned.add(oldName) ) {
			LOG.logError("Property "+oldName+" is deprecated: use "+name);
		}
		return v;
	}

	/** Like get(name, oldName), with a default. */
	public static String get(String name, String oldName, String def) {
		String v = get(name, oldName);
		return v == null ? def : v;
	}
}
