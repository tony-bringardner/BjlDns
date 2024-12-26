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

public class SimpleObjectFIFO extends Object {
	private Object[] queue;
	private int capacity;
	private int size;
	private int head;
	private int tail;

public SimpleObjectFIFO(int cap) 
{
		capacity = ( cap > 0 ) ? cap : 1; // at least 1
		queue = new Object[capacity];
		head = 0;
		tail = 0;
		size = 0;
}
public synchronized void add(Object obj) throws InterruptedException 
{

	//  This is used for high speed transactions.  If the que is full
		//  Then let's just drop it.
	if ( !isFull() ) {
		queue[head] = obj;
		head = ( head + 1 ) % capacity;
		size++;
		notifyAll(); // let any waiting threads know about change
	}
}
public synchronized int getCapacity() 
{
	return capacity;
}
	public synchronized int getSize() {
		return size;
	}
	public synchronized boolean isFull() {
		return ( size == capacity );
	}
	public synchronized void printState() {
		StringBuffer sb = new StringBuffer();

		sb.append("SimpleObjectFIFO:\n");
		sb.append("       capacity=" + capacity + "\n");

		sb.append("           size=" + size);
		if ( isFull() ) {
			sb.append(" - FULL");
		} else if ( size == 0 ) {
			sb.append(" - EMPTY");
		}
		sb.append("\n");

		sb.append("           head=" + head + "\n");
		sb.append("           tail=" + tail + "\n");

		for ( int i = 0; i < queue.length; i++ ) {
			sb.append("       queue[" + i + "]=" + queue[i] + "\n");
		}

		System.out.print(sb);
	}
public synchronized Object remove() throws InterruptedException 
{
	Object ret = null;
	
	if ( size == 0 ) {
		wait(2000);
	}

	if ( size > 0 ) {
		
		ret = queue[tail];
		queue[tail] = null; // don't block GC by keeping unnecessary reference
		tail = ( tail + 1 ) % capacity;
		size--;

		notifyAll(); // let any waiting threads know about change
	}

	return ret;
}
}
