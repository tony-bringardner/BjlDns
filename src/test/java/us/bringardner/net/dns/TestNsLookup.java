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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.util.NsLookup;

public class TestNsLookup implements DNS {

	static class NsLookupTestData {
		String promt;
		String cmd;
		String response;

		@Override
		public boolean equals(Object obj) {
			boolean ret = false;
			if (obj instanceof NsLookupTestData) {
				NsLookupTestData other = (NsLookupTestData) obj;
				ret = cmd.equals(other.cmd) 
						&& response.equals(other.response)
						;
			}

			return ret;
		}

		@Override
		public String toString() {
			return ""+cmd+"\n"+response;
		}
	}




	String ip4 = "[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+";
	String ip6 = "(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))";

	Pattern ip4Pattern = Pattern.compile(ip4);
	Pattern ip6Pattern = Pattern.compile(ip6);

	String dateRx = "[0-9][0-9][-][0-9][0-9][-][0-9][0-9][0-9][0-9] [0-9][0-9][:][0-9][0-9][:][0-9][0-9][.][0-9][0-9][0-9]";
	Pattern datep = Pattern.compile(dateRx);
	// Decimal 
	Pattern decimalPattern = Pattern.compile("[0-9]+");



	@BeforeAll
	public static void setUp() throws Exception {
	}

	@AfterAll
	public static void tearDown() throws Exception {
	}

	private List<List<NsLookupTestData>> parseNsLookupData(String str) {

		List<List<NsLookupTestData>> sessions = new ArrayList<>();
		List<NsLookupTestData> testData = new ArrayList<>();

		String lines [] = str.split("\n");
		NsLookupTestData cd = null;


		for (int idx = 0; idx < lines.length; idx++) {
			String line = lines[idx].trim();
			//  look for a command line
			if( line.startsWith(">")) {
				cd = new NsLookupTestData();
				cd.cmd = line.substring(1).trim();
				testData.add(cd);
				if( cd.cmd.equals("quit")) {
					sessions.add(testData);
					testData = new ArrayList<>();
				}
				StringBuilder buf = new StringBuilder();
				while(idx < lines.length-1) {
					if( lines[idx+1].startsWith(">") ) {
						break;
					} else {
						line = lines[++idx].trim();
						if( line.isEmpty()) {
							continue;
						}
						Matcher m = ip4Pattern.matcher(line);
						while(m.find()) {
							line = m.replaceAll("***ip4address***");
						} 
						m = ip6Pattern.matcher(line);
						while(m.find()) {
							line = m.replaceAll("***ip6address***");
						} 
						m = datep.matcher(line);
						if( m.find()) {
							line = m.replaceAll("***date-time***");
						}
						m = decimalPattern.matcher(line);
						while(m.find()) {							
							line = m.replaceAll("*decimal*");
						}

						buf.append(line);
						buf.append("\n");
					}
				}
				cd.response = buf.toString();
			}
		}
	
		if(!testData.isEmpty()) {
			sessions.add(testData);	
		}


		return sessions;
	}

	@Test
	public void testNsLookup() throws Exception {

		File file = new File("TestFiles/NsLookupTestData.txt").getCanonicalFile();
		assertTrue( file.exists(),""+file+" does not exist");
		String str = null;
		try (InputStream inp = new FileInputStream(file)) {
			str = new String(inp.readAllBytes());
		}

		List<List<NsLookupTestData>> sessions = parseNsLookupData(str);
		System.setProperty("echoCommand","true");

		for(List<NsLookupTestData> session : sessions) {
			StringBuilder buf = new StringBuilder();

			for(NsLookupTestData td : session) {
				buf.append(td.cmd+"\n");
			}
			ByteArrayInputStream in = new ByteArrayInputStream(buf.toString().getBytes());
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			NsLookup.setOut(new PrintStream(out));
			NsLookup.setIn(new BufferedReader(new InputStreamReader(in)));
			NsLookup.main(new String[0]);
			String response = new String(out.toByteArray());
			//System.out.println("response="+response);
			List<List<NsLookupTestData>> sessions2 = parseNsLookupData(response);
			assertTrue(sessions2.size()==1,"Replay should always have one session ="+sessions2.size());
			// fix the replay response because the command is not in output
			// should be one session

			List<NsLookupTestData> actualSession = sessions2.get(0);
			assertTrue(actualSession.size() == session.size(),"Replay session counts don't match ="+actualSession.size());

			for (int idx = 0,sz=session.size(); idx < sz; idx++) {
				NsLookupTestData actual = actualSession.get(idx);
				NsLookupTestData expect = session.get(idx);
				if(!expect.equals(actual)) {
					if( !expect.cmd.equals(actual.cmd) ) {
						showCompare(expect.cmd,actual.cmd);
					}
					if( !expect.response.equals(actual.response) ) {
						if( NsLookup.getMsg().isDebug()) {
							String[] el = expect.response.split("\n");
							String[] al = actual.response.split("\n");
							if( el.length == al.length) {
								continue;
							}
						}
						//showCompare(expect.response,actual.response);
					}
				}
				assertEquals(expect, actual,"NsLookupTestData does not match. idx="+idx);

			}

		}

	}

	private void showCompare(String exp, String act) {
		CompareTextFrame.showFrame(exp, act);
		while(true) {
			try {
				Thread.sleep(10000);
			} catch (InterruptedException e) {
				// Not implemented
				e.printStackTrace();
			}
		}
	}


}
