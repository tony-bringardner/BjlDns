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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

/**
 * setState is on the per-query path, so it must not build strings;
 * getState still shows the same information.
 */
public class TestState {

	@Test
	public void plainStateIsShown() {
		DnsBaseClass b = new DnsBaseClass();
		assertTrue(b.getState().startsWith("Not Started "));
		b.setState("Waiting on fifo");
		assertTrue(b.getState().startsWith("Waiting on fifo "), b.getState());
	}

	@Test
	public void detailIsOnlyFormattedWhenShown() {
		AtomicInteger calls = new AtomicInteger();
		Object detail = new Object() {
			public String toString() {
				calls.incrementAndGet();
				return "www.foo.com A";
			}
		};
		DnsBaseClass b = new DnsBaseClass();
		for(int i=0; i < 1000; i++ ) {
			b.setState("Call Resolver", detail);
		}
		assertEquals(0, calls.get(), "no formatting on setState");
		String shown = b.getState();
		assertTrue(shown.startsWith("Call Resolver:www.foo.com A "), shown);
		assertEquals(1, calls.get());
	}

	@Test
	public void setStateIsCheap() {
		DnsBaseClass b = new DnsBaseClass();
		int n = 1_000_000;
		for(int w=0; w < 2; w++ ) {
			long t0 = System.nanoTime();
			for(int i=0; i < n; i++ ) {
				b.setState("Running after sync");
			}
			long t1 = System.nanoTime();
			String old = null;
			for(int i=0; i < n; i++ ) {
				old = "Running after sync"+" "+(new java.util.Date());
			}
			long t2 = System.nanoTime();
			if( w == 1 ) {
				System.out.println("1M setState: "+(t1-t0)/1_000_000+" ms, old string building: "+(t2-t1)/1_000_000+" ms "+old.length());
				assertTrue(t1-t0 < t2-t1, "cheaper than building the string");
			}
		}
	}
}
