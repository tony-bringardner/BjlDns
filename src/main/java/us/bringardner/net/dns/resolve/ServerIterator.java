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

import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

/**
 * 
 * Creation date: (10/19/2001 4:22:46 AM)
 * @author: Tony Bringardner
 */
public class ServerIterator implements Iterator<ServerA> 
{
	private int start;
	private int cur;
	private int sz;
	private int seen;
	private List<ServerA> list;
	
/**
 * ServerIterator constructor comment.
 */
public ServerIterator(List<ServerA> vec, int startLoc) 
{
	start=startLoc;
	list = vec;
	cur=start;
	sz = list.size();
	if( cur >= sz ) {
		cur = start = 0;
	}
	
}
	/**
	 * Returns <tt>true</tt> if the iteration has more elements. (In other
	 * words, returns <tt>true</tt> if <tt>next</tt> would return an element
	 * rather than throwing an exception.)
	 *
	 * @return <tt>true</tt> if the iterator has more elements.
	 */
public boolean hasNext() 
{
	boolean ret = (sz > 0 && seen < sz ) ;
	return ret;
}
	/**
	 * Returns the next element in the interation.
	 *
	 * @returns the next element in the interation.
	 * @exception NoSuchElementException iteration has no more elements.
	 */
public ServerA next() 
{
	ServerA ret = list.get(cur);
	seen ++;
	if( ++ cur >= sz ) {
		cur = 0;
	}
	
	return ret;
}
	/**
	 * 
	 * Removes from the underlying collection the last element returned by the
	 * iterator (optional operation).  This method can be called only once per
	 * call to <tt>next</tt>.  The behavior of an iterator is unspecified if
	 * the underlying collection is modified while the iteration is in
	 * progress in any way other than by calling this method.
	 *
	 * @exception UnsupportedOperationException if the <tt>remove</tt>
	 *		  operation is not supported by this Iterator.
	 
	 * @exception IllegalStateException if the <tt>next</tt> method has not
	 *		  yet been called, or the <tt>remove</tt> method has already
	 *		  been called after the last call to the <tt>next</tt>
	 *		  method.
	 */
public void remove() 
{
	throw new IllegalStateException("Never call this function!!!");
		
}
}
