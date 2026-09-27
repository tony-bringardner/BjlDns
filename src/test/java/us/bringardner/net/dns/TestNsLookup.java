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
 * ~version~V000.01.04-V000.00.05-V000.00.04-V000.00.02-V000.00.01-V000.00.00-
 */
package us.bringardner.net.dns;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import us.bringardner.net.dns.util.NsLookup;

/**
 * Live test: runs this machine's nslookup and NsLookup on the same lookups
 * (with the machine's resolv.conf) and compares the output. It needs
 * working DNS, and an ISC nslookup 9.16 or later (Linux) for the same
 * output format; run with -DliveTests=true (mvn test -DliveTests=true).
 * Answers from real servers vary (order, round robin), so the lines are
 * compared sorted. TestNsLookupOffline covers NsLookup without the internet.
 */
@EnabledIfSystemProperty(named = "liveTests", matches = "true")
public class TestNsLookup {

	private static final String [][] LOOKUPS = {
			{"www.google.com"},
			{"irs.gov"},
			{"-type=mx", "google.com"},
			{"-type=ns", "irs.gov"},
			{"-type=soa", "irs.gov"},
			{"-type=txt", "irs.gov"},
			{"8.8.8.8"},
			{"2001:4860:4860::8888"},
			{"no-such-name.invalid"},
			{"-type=ns", "gov"},
	};

	private static String [] result(int exit, String out) {
		List<String> lines = new ArrayList<String>(Arrays.asList(out.split("\n")));
		Collections.sort(lines);
		return new String[] {"exit "+exit, String.join("\n", lines)};
	}

	private static String [] system(String ... args) throws Exception {
		List<String> cmd = new ArrayList<String>();
		cmd.add("nslookup");
		cmd.addAll(Arrays.asList(args));
		Process p;
		try {
			p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
		} catch(java.io.IOException ex) {
			return null;
		}
		p.getOutputStream().close();
		String out;
		try(InputStream in = p.getInputStream()) {
			out = new String(in.readAllBytes(), StandardCharsets.UTF_8);
		}
		p.waitFor(60, TimeUnit.SECONDS);
		return result(p.exitValue(), out);
	}

	private static String [] ours(String ... args) throws Exception {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		PrintStream ps = new PrintStream(out, true, "UTF-8");
		NsLookup.setOut(ps);
		NsLookup.setErr(ps);
		NsLookup.setIn(new BufferedReader(new StringReader("")));
		try {
			int exit = NsLookup.run(args);
			return result(exit, out.toString("UTF-8"));
		} finally {
			NsLookup.setOut(System.out);
			NsLookup.setErr(System.err);
		}
	}

	@Test
	public void sameAsSystemNslookup() throws Exception {
		String [] version = system("-version");
		assumeTrue(version != null && version[1].matches("(?s).*nslookup 9\\.(1[6-9]|[2-9][0-9]).*"), "needs ISC nslookup 9.16+: "+(version == null ? "none" : version[1]));
		for(String [] args : LOOKUPS) {
			String [] expect = system(args);
			String [] actual = ours(args);
			assertEquals(expect[0]+"\n"+expect[1], actual[0]+"\n"+actual[1], String.join(" ", args));
		}
	}
}
