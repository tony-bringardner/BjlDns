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

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import us.bringardner.core.BjlLogger;
import us.bringardner.core.ILogger.Level;

/**
 * log(Supplier) only builds the message when debug logging is enabled (rec #33).
 */
public class TestLazyLogging {

	private static BjlLogger logger(Level level, ByteArrayOutputStream sink) {
		BjlLogger ret = new BjlLogger();
		ret.init("TestLazyLogging");
		ret.setLevel(level);
		PrintStream ps = new PrintStream(sink, true);
		ret.setOut(ps);
		ret.setErr(ps);
		return ret;
	}

	@Test
	public void messageNotBuiltWhenDebugIsOff() {
		ByteArrayOutputStream sink = new ByteArrayOutputStream();
		DnsBaseClass obj = new DnsBaseClass();
		obj.setLogger(logger(Level.ERROR, sink));
		AtomicInteger built = new AtomicInteger();
		for(int i=0; i < 100; i++ ) {
			obj.log(() -> "built "+built.incrementAndGet());
		}
		assertEquals(0, built.get(), "supplier must not run with debug off");
		assertEquals(0, sink.size(), "nothing logged");
	}

	@Test
	public void messageBuiltAndLoggedWhenDebugIsOn() {
		ByteArrayOutputStream sink = new ByteArrayOutputStream();
		DnsBaseClass obj = new DnsBaseClass();
		obj.setLogger(logger(Level.DEBUG, sink));
		AtomicInteger built = new AtomicInteger();
		obj.log(() -> "built "+built.incrementAndGet());
		assertEquals(1, built.get());
		assertTrue(sink.toString().contains("built 1"), sink.toString());
	}
}
