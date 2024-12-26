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
 * 
 * Creation date: (6/18/2003 10:41:56 AM)
 * @author: Tony Bringardner
 */
public class Label extends DnsBaseClass 
{
	public static final String WILD_CARD="*";
	private String label;
	private boolean isWildCard = false;
/**
 * Label constructor comment.
 */
public Label() {
	super();
}
/**
 * Label constructor comment.
 */
public Label(String label) 
{
	this.label = label;
	isWildCard = WILD_CARD.equals(label);
}
/**
 * Label constructor comment.
 */
public Label(Label label) 
{
	this.label = new String(label.label);
	isWildCard = WILD_CARD.equals(this.label);
}
/**
 * Compares two objects for equality. Returns a boolean that indicates
 * whether this object is equivalent to the specified object. This method
 * is used when an object is stored in a hashtable.
 * @param obj the Object to compare with
 * @return true if these Objects are equal; false otherwise.
 * @see java.util.Hashtable
 */
public boolean equals(Object obj) 
{
	boolean ret = false;

	if( obj instanceof Label ) {
		ret = equals((Label)obj,true);
	}
	
	return ret;
}
/**
 * Compares two objects for equality. Returns a boolean that indicates
 * whether this object is equivalent to the specified object. This method
 * is used when an object is stored in a hashtable.
 * @param obj the Object to compare with
 * @return true if these Objects are equal; false otherwise.
 * @see java.util.Hashtable
 */
public boolean equals(Label other, boolean doWildCard) 
{
	boolean ret = false;

	if( doWildCard ) {
		if( !(ret= (isWildCard || other.isWildCard)) ) {
			ret = label.equalsIgnoreCase(other.label);
		}
	} else {
			ret = label.equalsIgnoreCase(other.label);
	}
	
	return ret;
}

/**
 * Generates a hash code for the receiver.
 * This method is supported primarily for
 * hash tables, such as those provided in java.util.
 * @return an integer hash code for the receiver
 * @see java.util.Hashtable
 */
public int hashCode() 
{
	return label.hashCode();
}
public boolean isWildCard()
{
	return isWildCard;
}
/**
 * Returns a String that represents the value of this object.
 * @return a string representation of the receiver
 */
public String toString() 
{
	return label;
}
}
