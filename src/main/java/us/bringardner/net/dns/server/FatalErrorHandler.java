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
package us.bringardner.net.dns.server;

import java.util.concurrent.atomic.AtomicLong;
import java.util.function.IntConsumer;

import us.bringardner.net.dns.DnsBaseClass;

/**
 * Handles errors that escape a thread (the thread is about to die).
 * <p>
 * Every such error is logged, so a dead UDP/TCP/resolver/admin thread is
 * visible instead of silently reducing capacity. A JVM error
 * ({@link VirtualMachineError}, e.g. OutOfMemoryError) leaves the process in
 * an unknown state, so when halting is enabled the process is stopped at once
 * with exit code 1 and a supervisor (systemd, launchd...) starts a clean one.
 * Runtime.halt() is used rather than System.exit(), which runs shutdown
 * hooks and can hang when memory is exhausted.
 * <p>
 * DnsServer.main() installs this as the default handler with halting on
 * (JDns.exitOnFatalError=false to turn it off). Applications that embed the
 * server can call {@link #install(boolean)} themselves. Running the JVM with
 * -XX:+ExitOnOutOfMemoryError gives the same protection for OutOfMemoryError.
 * <p>
 * This replaces catching OutOfMemoryError in request processing, trimming the
 * cache, retrying, and finally calling System.exit(1) from a request thread.
 */
public final class FatalErrorHandler extends DnsBaseClass implements Thread.UncaughtExceptionHandler {

	public static final String PROP_EXIT_ON_FATAL_ERROR = "JDns.exitOnFatalError";

	private static final FatalErrorHandler INSTANCE = new FatalErrorHandler();
	private static volatile boolean haltOnFatal = false;
	//  Replaceable for tests
	private static volatile IntConsumer halter = code -> Runtime.getRuntime().halt(code);
	private static final AtomicLong deaths = new AtomicLong();

	private FatalErrorHandler() {
	}

	/**
	 * Make this the default handler for threads without their own.
	 * @param haltOnFatalError stop the process on a VirtualMachineError
	 */
	public static void install(boolean haltOnFatalError) {
		haltOnFatal = haltOnFatalError;
		Thread.setDefaultUncaughtExceptionHandler(INSTANCE);
	}

	public static FatalErrorHandler getInstance() {
		return INSTANCE;
	}

	/** Threads that died from an uncaught error. */
	public static long getThreadDeaths() {
		return deaths.get();
	}

	static void setHalter(IntConsumer h) {
		halter = h;
	}

	static void setHaltOnFatal(boolean b) {
		haltOnFatal = b;
	}

	@Override
	public void uncaughtException(Thread t, Throwable e) {
		deaths.incrementAndGet();
		boolean fatal = e instanceof VirtualMachineError;
		String msg = "Thread "+t.getName()+" died: "+e
				+(fatal && haltOnFatal ? " - halting the process so it can be restarted" : "");
		//  stderr first: logging may itself fail when memory is exhausted
		System.err.println(msg);
		try {
			logError(msg, e);
		} catch(Throwable ignore) {
		}
		if( fatal && haltOnFatal ) {
			halter.accept(1);
		}
	}
}
