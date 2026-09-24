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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Challenge-response authentication for the admin port.
 * <p>
 * The server greets with a random challenge; the client answers
 * {@code auth <hex(HMAC-SHA256(secret, challenge))>}. The shared secret
 * (JDns.adminSecret) never crosses the network and a recorded answer is
 * useless for the next connection (new challenge each time).
 * <p>
 * Note: after authentication the admin commands themselves are still plain
 * text; use a trusted network or an SSH tunnel for remote administration.
 */
public final class AdminAuth {

	private static final SecureRandom RANDOM = new SecureRandom();
	private static final String ALG = "HmacSHA256";

	private AdminAuth() {
	}

	/** A new random challenge (32 hex characters). */
	public static String newChallenge() {
		byte [] b = new byte[16];
		RANDOM.nextBytes(b);
		return hex(b);
	}

	/** The answer a client sends for this challenge. */
	public static String response(String secret, String challenge) {
		try {
			Mac mac = Mac.getInstance(ALG);
			mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), ALG));
			return hex(mac.doFinal(challenge.getBytes(StandardCharsets.UTF_8)));
		} catch(Exception ex) {
			throw new IllegalStateException("HmacSHA256 not available", ex);
		}
	}

	/** Constant-time check of a client's answer. */
	public static boolean verify(String secret, String challenge, String answer) {
		if( secret == null || challenge == null || answer == null ) {
			return false;
		}
		byte [] expected = response(secret, challenge).getBytes(StandardCharsets.US_ASCII);
		byte [] got = answer.trim().toLowerCase().getBytes(StandardCharsets.US_ASCII);
		return MessageDigest.isEqual(expected, got);
	}

	/** Extract the challenge from a server greeting, or null if it has none. */
	public static String challengeFrom(String greeting) {
		if( greeting == null ) {
			return null;
		}
		for(String part : greeting.split(" ")) {
			if( part.startsWith("challenge=") ) {
				return part.substring("challenge=".length());
			}
		}
		return null;
	}

	private static String hex(byte [] b) {
		StringBuilder sb = new StringBuilder(b.length*2);
		for(byte x : b) {
			sb.append(Character.forDigit((x >> 4) & 0xf, 16));
			sb.append(Character.forDigit(x & 0xf, 16));
		}
		return sb.toString();
	}
}
