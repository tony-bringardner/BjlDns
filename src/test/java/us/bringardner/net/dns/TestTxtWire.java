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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import us.bringardner.net.dns.resolve.Cache;

/**
 * A TXT record received from the network must be serializable again
 * (e.g. when the resolver forwards an upstream answer to a client).
 */
public class TestTxtWire {

	private static Message txtResponse(String text) {
		Message m = new Message();
		m.setQuestion("example.test", DNS.TXT, DNS.IN);
		m.setMessageTypeResponse();
		Txt t = new Txt("example.test");
		t.setText(text);
		t.setTTL(300);
		m.addAnswer(t);
		return m;
	}

	private static String longText() {
		StringBuilder sb = new StringBuilder("v=DKIM1;t=s;p=");
		for(int i=0; i< 400; i++ ) {
			sb.append((char)('A'+(i % 26)));
		}
		return sb.toString();
	}

	@Test
	public void parsedTxtCanBeSerializedAgain() {
		Message orig = txtResponse("v=spf1 +mx -all");
		byte [] wire = orig.toByteArray();
		Message parsed = new Message(new ByteBuffer(wire));
		assertEquals("v=spf1 +mx -all", ((Txt)parsed.getAnswer().get(0)).getText());
		// threw RuntimeException("Txt is dirty") before
		assertArrayEquals(wire, parsed.toByteArray());
	}

	@Test
	public void longMultiStringTxtRoundTrips() {
		Message orig = txtResponse(longText());
		byte [] wire = orig.toByteArray();
		Message parsed = new Message(new ByteBuffer(wire));
		assertEquals(longText(), ((Txt)parsed.getAnswer().get(0)).getText());
		assertArrayEquals(wire, parsed.toByteArray());
	}

	@Test
	public void txtThroughResolverCache() {
		// The path a forwarded answer takes: upstream bytes -> cache -> client bytes
		Cache c = new Cache(10);
		c.put(new Message(new ByteBuffer(txtResponse(longText()).toByteArray())));
		Message out = c.get(new Section("example.test", DNS.TXT, DNS.IN));
		out.setID(7);
		Message client = new Message(new ByteBuffer(out.toByteArray()));
		assertEquals(longText(), ((Txt)client.getAnswer().get(0)).getText());
	}
}
