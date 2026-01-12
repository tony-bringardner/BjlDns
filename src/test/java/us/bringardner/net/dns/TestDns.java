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
 * ~version~V000.01.04-V000.01.02-V000.00.05-V000.00.01-V000.00.00-
 */
package us.bringardner.net.dns;


import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.server.DnsAdminClient;
import us.bringardner.net.dns.server.DnsServer;
import us.bringardner.net.dns.util.NsLookup;

public class TestDns implements DNS {

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



	static class TestFIle extends File {

		private static final long serialVersionUID = 1L;

		public TestFIle(String name) {
			super( name);
		}		
	}

	enum Action  {Add,Delete};

	private interface Manager {

		void doit(Action action,String name, String address) throws IOException;


	}

	private int testQCodes[] = {A,NS,MX,CNAME,SOA,MB,MG,MR,WKS,PTR,HINFO,MINFO,TXT};

	Map<String,String> expected = new HashMap<String, String>();
	private static DnsServer server;
	// etra long timeout for testing
	private static int serverTimeout = 5000*10000;

	private static String localServerAddress;

	private static int localServrPort;



	@BeforeAll
	public static void setUp() throws Exception {

		System.setProperty(DnsServer.PROP_DNS_PROPERTIRS, "TestFiles/TestDns.properties");
		System.setProperty("LogLevel","ERROR");
		System.setProperty("JDns.useDataBase","false");




		server = new DnsServer();
		server.setRecursionAvailable(false);
		// Start server as stand alone
		server.start(true);


		long start = System.currentTimeMillis();
		while(!server.isRunning() && System.currentTimeMillis()-start < serverTimeout) {
			Thread.sleep(100);
		}


		Assertions.assertTrue(server.isRunning(),"DNS Server did not start within timoue = "+serverTimeout );
		localServrPort = DNS.DNSPORT;
		localServerAddress = null;

		String tmp = null;
		if(( tmp = server.getProperty(DnsServer.PROP_BIND_ADDRESS)) != null ) {
			localServerAddress = tmp;
		}

		if(( tmp = server.getProperty(DnsServer.PROP_PORT)) != null ) {
			localServrPort = Integer.parseInt(tmp);
		}


	}

	@AfterAll
	public static void tearDown() throws Exception {
		if( server != null ) {
			server.stop();
		}
	}



	int count(String str) {
		int ret = 0;
		byte [] data = str.getBytes();
		for (int idx = 0; idx < data.length; idx++) {
			if( data[idx] == (byte)':') {
				ret++;
			}
		}
		if( !str.endsWith(":") ) {
			ret++;
		}
		return ret;
	}


	@Test
	public void testServers() throws Exception {



		runTests(NsLookup.getDnsServer(), DNS.DNSPORT,"google.com","irs.gov");


		if( server.isRunning()) {
			runTests(localServerAddress, localServrPort,"foo.com","bar.com");

			testDomain((a,name,d)->{
				switch (a) {
				case Add: server.addDomain(name);	break;
				case Delete: server.removeDomain(name);	break;
				default:
					throw new IOException("Unexpected action = "+a);
				}
			});
		}
	}



	public void testDomain(Manager mgr) throws Exception {

		//  When a domain is added all tests should pass
		String domain = "flunky.bo";
		//server.addDomain(domain);
		mgr.doit(Action.Add, domain, null);
		runTests(localServerAddress, localServrPort,domain);

		// once a domain is removed we should get a NAME ERROR for any request
		//server.removeDomain(domain);
		mgr.doit(Action.Delete, domain, null);
		Message msg = new Message();
		msg.setServer(localServerAddress);
		msg.setPort(localServrPort);
		Message res = msg.query(domain, A, IN);
		assertEquals(domain+" type=A should be a NAME ERROR rcode="+res.getResponseCode(),3, res.getResponseCode());	
	}


	private void assertEquals(String string, int expect, int actual) {
		Assertions.assertEquals(expect,actual,string);		
	}

	@Test
	public void testAdmin() throws  Exception {
		if( server.isRunning()) {

			String expected01="Server state=Waiting for admin connection Wed Nov 13 16:43:10 EST 2024\n"
					+ "Resolver Cache size=0 RemoteServer size=0\n"
					+ " Resolver capacity=20  current=0\n"
					+ "Resolver Stats: inflight=0 completed=0 min=9999999 max=0 ave=0\n"
					+ "\n"
					+ "State of 10 resolver processors follows\n"
					+ "	0 Waiting on fifo Wed Nov 13 16:43:30 EST 2024\n"
					+ "	1 Waiting on fifo Wed Nov 13 16:43:30 EST 2024\n"
					+ "	2 Waiting on fifo Wed Nov 13 16:43:30 EST 2024\n"
					+ "	3 Waiting on fifo Wed Nov 13 16:43:30 EST 2024\n"
					+ "	4 Waiting on fifo Wed Nov 13 16:43:30 EST 2024\n"
					+ "	5 Waiting on fifo Wed Nov 13 16:43:30 EST 2024\n"
					+ "	6 Waiting on fifo Wed Nov 13 16:43:30 EST 2024\n"
					+ "	7 Waiting on fifo Wed Nov 13 16:43:30 EST 2024\n"
					+ "	8 Waiting on fifo Wed Nov 13 16:43:30 EST 2024\n"
					+ "	9 Waiting on fifo Wed Nov 13 16:43:30 EST 2024\n"
					+ "+Status done\n"
					+ "\n";
			String expected02= "Server state=Waiting for admin connection Wed Nov 13 16:43:10 EST 2024\n"
					+ "Resolver Cache size=0 RemoteServer size=0\n"
					+ " Resolver capacity=20  current=0\n"
					+ "Resolver Stats: inflight=0 completed=0 min=9999999 max=0 ave=0\n"
					+ "\n"
					+ "State of 4 tcp processors follows\n"
					+ "	0 Running before sync Wed Nov 13 16:43:41 EST 2024\n"
					+ "	1 Running after sync Wed Nov 13 16:43:51 EST 2024\n"
					+ "	2 Running before sync Wed Nov 13 16:43:51 EST 2024\n"
					+ "	3 Running before sync Wed Nov 13 16:43:46 EST 2024\n"
					+ "+Status done\n"
					+ "\n";
			String expected03=
					"Server state=Waiting for admin connection Wed Nov 13 16:43:10 EST 2024\n"
							+ "Resolver Cache size=0 RemoteServer size=0\n"
							+ " Resolver capacity=20  current=0\n"
							+ "Resolver Stats: inflight=0 completed=0 min=9999999 max=0 ave=0\n"
							+ "\n"
							+ "State of 10 udp processors follows\n"
							+ "	0 Running before sync Wed Nov 13 16:43:50 EST 2024\n"
							+ "	1 Running before sync Wed Nov 13 16:43:26 EST 2024\n"
							+ "	2 Running after sync Wed Nov 13 16:43:55 EST 2024\n"
							+ "	3 Running before sync Wed Nov 13 16:43:30 EST 2024\n"
							+ "	4 Running before sync Wed Nov 13 16:43:30 EST 2024\n"
							+ "	5 Running before sync Wed Nov 13 16:43:21 EST 2024\n"
							+ "	6 Running before sync Wed Nov 13 16:43:16 EST 2024\n"
							+ "	7 Running before sync Wed Nov 13 16:43:16 EST 2024\n"
							+ "	8 Running before sync Wed Nov 13 16:43:35 EST 2024\n"
							+ "	9 Running before sync Wed Nov 13 16:43:55 EST 2024\n"
							+ "+Status done\n"
							+ "\n";

			String expected04= "Server state=Waiting for admin connection Wed Nov 13 16:43:10 EST 2024\n"
					+ "Resolver Cache size=0 RemoteServer size=0\n"
					+ " Resolver capacity=20  current=0\n"
					+ "Resolver Stats: inflight=0 completed=0 min=9999999 max=0 ave=0\n"
					+ "\n"
					+ "State of 10 resolver processors follows\n"
					+ "	0 Waiting on fifo Wed Nov 13 16:44:00 EST 2024\n"
					+ "	1 Waiting on fifo Wed Nov 13 16:44:00 EST 2024\n"
					+ "	2 Waiting on fifo Wed Nov 13 16:44:00 EST 2024\n"
					+ "	3 Waiting on fifo Wed Nov 13 16:44:00 EST 2024\n"
					+ "	4 Waiting on fifo Wed Nov 13 16:44:00 EST 2024\n"
					+ "	5 Waiting on fifo Wed Nov 13 16:44:00 EST 2024\n"
					+ "	6 Waiting on fifo Wed Nov 13 16:44:00 EST 2024\n"
					+ "	7 Waiting on fifo Wed Nov 13 16:44:00 EST 2024\n"
					+ "	8 Waiting on fifo Wed Nov 13 16:44:00 EST 2024\n"
					+ "	9 Waiting on fifo Wed Nov 13 16:44:00 EST 2024\n"
					+ "\n"
					+ "State of 4 tcp processors follows\n"
					+ "	0 Running before sync Wed Nov 13 16:43:41 EST 2024\n"
					+ "	1 Running before sync Wed Nov 13 16:43:56 EST 2024\n"
					+ "	2 Running after sync Wed Nov 13 16:43:56 EST 2024\n"
					+ "	3 Running before sync Wed Nov 13 16:43:46 EST 2024\n"
					+ "\n"
					+ "State of 10 udp processors follows\n"
					+ "	0 Running before sync Wed Nov 13 16:43:50 EST 2024\n"
					+ "	1 Running before sync Wed Nov 13 16:43:26 EST 2024\n"
					+ "	2 Running before sync Wed Nov 13 16:44:00 EST 2024\n"
					+ "	3 Running before sync Wed Nov 13 16:43:30 EST 2024\n"
					+ "	4 Running before sync Wed Nov 13 16:43:30 EST 2024\n"
					+ "	5 Running before sync Wed Nov 13 16:43:21 EST 2024\n"
					+ "	6 Running before sync Wed Nov 13 16:43:16 EST 2024\n"
					+ "	7 Running before sync Wed Nov 13 16:43:16 EST 2024\n"
					+ "	8 Running after sync Wed Nov 13 16:44:00 EST 2024\n"
					+ "	9 Running before sync Wed Nov 13 16:43:55 EST 2024\n"
					+ "+Status done\n"
					+ "";

			int adminPort = DnsServer.getAdminPort();

			DnsAdminClient client = new DnsAdminClient(localServerAddress, adminPort);
			client.setTimeout(100000);

			assertTrue("Could not connect client to "+localServerAddress+":"+adminPort,client.connect());

			try {
				testDomain((a,name,d)->{
					switch (a) {
					case Add: client.addDomain(name);	break;
					case Delete:client.removeDomain(name);	break;
					default:
						throw new IOException("Unexpected action = "+a);
					}
				});
				testDynamic((a,n,d)->{
					switch (a) {
					case Add:client.addDynamic(n, d);break;
					case Delete:client.removeDynamic(n);break;
					default:
						throw new IOException("unexpected action = "+a);
					}
				});

				String tmp = client.statusResolver();				
				compareStatus(expected01,tmp);

				tmp = client.statusTCP();
				compareStatus(expected02,tmp);

				tmp = client.statusUDP();
				compareStatus(expected03,tmp);

				tmp = client.statusALL();
				compareStatus(expected04,tmp);

				tmp = client.memory();
				compareStatus("+Start up=Wed Nov 13 16:55:29 EST 2024 free mem=393961088",tmp);

			} finally {
				try {client.close();} catch (Exception e) {}
			}					
		}
	}

	private void assertTrue(String string, boolean connect) {
		Assertions.assertTrue(connect, string);
		
	}

	private void compareStatus(String expected, String actual) {
		String [] ep = expected.split("\n");
		String [] ap = expected.split("\n");
		assertEquals("Status does not have the same numbrew of lines",ep.length, ap.length);
	}

	@Test
	public void testDynamic () throws IOException {

		testDynamic((a,n,d)->{
			switch (a) {
			case Add:
				server.addDynamic(n, d);
				break;
			case Delete:
				server.removeDynamic(n);
				break;
			default:
				throw new IOException("unexpected action = "+a);
			}
		});

	}

	@Test
	public void testLargeTxt() throws Exception {
		Message msg = new Message();
		msg.setQuestion("default._domainkey.foo.com", TXT, IN);
		msg.setServer("localhost");
		msg.setPort(8888);
		Message res = msg.queryUDP();
		int cnt = res.getAnswerCount();
		assertEquals("cnt",1, cnt);
		String expect = "v=DKIM1;t=s;p=MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1MjtqU+T0iWO4iqE1h1dZjRdYQ/4PWoXE5A5jz6MQDnKJ4PQFQG2+Qw9cvBVKUQZreAnAnGx8PJb+QLiBDSofRKFx10h8aCGLZ/R052dqk+8kKEbMXWFpy8s7H/JpFYJ4eYqoQWM5FRzsPe1toySFBSnVNJOrSKcWHIwI/xUOQselIFcZXaXNSmvXIxKrmZ5pgSzmdAiiofwv0M9Ls2D9SoEC0Bw3o4uxezwNEpHW8L0n4gepnuJJjtGHc6x0Okg5QE8hhLN8afKPOUz6sx88t8dQzV2nF5FKgrpx+bhB6iiyEOPD8JLWsa62Z0mL7jgDDx28KZ+eJjdlmUvXbCWxwTC5SCCCRUfhY5dhpdFZ1yybqJ9LXduKK/IgwcDxBEgTQ+SsLtcWGRWk7mAMpysLXRmUWeCbuieIY8gVY7MfQ41BbL6lK5MiIAHYDdQ0fZivknp2KStGjUF39rlLnv7nszRvJFWQaClzwZ1zGr81ez9dn2g6garKKYfIeZuIgnGpwDQtdC8TRTkhpTfJkrkefqpG278qfDxmm09G+olv7sAT5U/2/fyd5XLM2DM7Xi/71T5bZaDxFqGSsr573/93Z8zv3k8hgxONZEhUJ83PcEFJGNmec9ya3ChHU6N2ew0KjCMyo0BXVENVGmiUQkF544BUXLa3/KuI1VMBlKoOnkCAwEAAQ==";
		
		RR ansnwer = res.getAnswer().get(0);
		if (ansnwer instanceof Txt) {
			Txt txt = (Txt) ansnwer;
			Assertions.assertEquals( expect, txt.getText());
		} else {
			throw new RuntimeException("Answer is not a Txt="+ansnwer.getClass());
		}
		
		
	}
	
	@Test
	public void testAAAA() {



		// formatting for ip6 is kind of tricky
		for(int cnt=0; cnt<9999; cnt++) {
			Random r = new Random();
			StringBuilder buf = new StringBuilder();
			for(int colon=0; colon<8; colon++) {
				if( colon  > 0 ) {
					buf.append(':');	
				}

				int val = r.nextInt(Short.MAX_VALUE);
				if( val % 6==0) {
					val = 0;
				}
				if( val >0 ) {
					buf.append(Integer.toHexString(val));
				}

			}
			String ip = buf.toString();
			boolean valid = ip.indexOf("::") == ip.lastIndexOf("::") && !ip.endsWith(":");

			AAAA a = new AAAA("test");
			try {
				a.setAddress(ip);
				String str = a.getAddressString();
				Assertions.assertEquals(ip, str,"Address did not convet correctly");
			} catch (Throwable e) {
				if( valid ) {
					throw e;
				}
			}


		}

	}


	public void runTests(String server, int port,String ... addresses) throws Exception {
		Message msg = new Message();
		msg.setServer(server);
		msg.setPort(port);


		//msg.setTimeOut(99999999);



		//  All should be good queries
		for(String name : addresses) {
			for(int qtype : testQCodes) {				
				Message res1 = msg.query(name, qtype, IN);
				assertEquals(name+" type="+qtype+" rcode="+res1.getResponseCode(),0, res1.getResponseCode());
				// UDP is the default but here we force it just to test it
				res1 = msg.queryUDP();
				assertEquals(name+"UDP type="+qtype+" rcode="+res1.getResponseCode(),0, res1.getResponseCode());
				//  force use of TCP
				res1 = msg.queryTCP();
				assertEquals(name+"TCP type="+qtype+" rcode="+res1.getResponseCode(),0, res1.getResponseCode());

			}
		}
		// test name error
		Message res = msg.query(addresses[0]+"x", A, IN);
		assertEquals(addresses[0]+" type=A should be a NAME ERROR rcode="+res.getResponseCode(),3, res.getResponseCode());
	}

	public void testDynamic(Manager runner) throws IOException {



		if(server.isRunning()) {
			String name = "boogy.bar.com";
			String address = "1.2.3.4";

			// Add the address
			runner.doit(Action.Add,name, address);

			// validate the name now has the dynamic address
			Message msg = new Message();
			msg.setServer(localServerAddress);
			msg.setPort(localServrPort);
			Message res = msg.query(name, A, IN);
			assertEquals(name+" type=A should be ok rcode="+res.getResponseCode(),0, res.getResponseCode());	
			assertEquals(name+" type=A should be have one answer="+res.getAdditionalCount(),0, res.getAdditionalCount());
			A a = res.getAddress(name);
			assertNotNull(a,"Result did not have an answer ");
			byte [] data = a.getAddress();
			assertNotNull(data,"address data is null ");
			assertEquals(name+" data is not the correct length="+data.length,4, data.length);
			for (int idx = 0; idx < data.length; idx++) {
				assertEquals(name+" address at ="+idx+" is not correct",idx+1, data[idx]);
			}

			// now remove the dynamic address
			runner.doit(Action.Delete,name, address);

			// validate the name results in the global (common) address
			res = msg.query(name, A, IN);
			assertEquals(name+" type=A should be ok rcode="+res.getResponseCode(),0, res.getResponseCode());	
			assertEquals(name+" type=A should be have one answer="+res.getAdditionalCount(),0, res.getAdditionalCount());

			a = res.getAddress(name);
			assertNotNull(a,"Result did not have an answer ");
			data = a.getAddress();
			assertNotNull(data,"address data is null ");
			assertEquals(name+" data is not the correct length="+data.length,4, data.length);
			//zone file for bar.com has 111.69.95.39
			byte expect [] = {111,69,95,39};
			for (int idx = 0; idx < data.length; idx++) {
				assertEquals(name+" address at ="+idx+" is not correct",expect[idx], data[idx]);
			}
		}
	}
	
	

}
