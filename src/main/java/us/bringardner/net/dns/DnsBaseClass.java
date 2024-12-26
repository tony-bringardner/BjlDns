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
 * ~version~V000.01.02-V000.00.05-V000.00.00-
 */
package us.bringardner.net.dns;

import us.bringardner.core.BaseObject;

/**
 * 
 * Creation date: (4/23/2003 9:38:50 AM)
 * @author: Tony Bringardner
 * 
 */
public class DnsBaseClass extends BaseObject {
	
	private String state = "Not Started";
/**
 * FtpBaseClass constructor comment.
 */
public DnsBaseClass() 
{
	super();
}

public void log(String msg) {
	logDebug(msg);
}

public void log(String msg, Throwable e1) {
	logError(msg,e1);
}
public void log(Exception ex,String msg) {
	logError(msg,ex);
}

/**
 * 
 * Creation date: (10/14/2003 7:46:22 AM)
 * @return java.lang.String
 */
public java.lang.String getState() {
	return state;
}


/**
 * 
 * Creation date: (10/14/2003 7:46:22 AM)
 * @param newState java.lang.String
 */
public void setState(java.lang.String newState) 
{
	state = newState+" "+(new java.util.Date());
}
}
