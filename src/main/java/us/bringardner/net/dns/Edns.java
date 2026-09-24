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

import java.util.Iterator;
import java.util.List;

/**
 * EDNS(0) (RFC 6891) for the server side.
 * <p>
 * A client that sends an OPT record says how large a UDP response it can
 * take. Without EDNS every answer over 512 bytes was truncated and the
 * client had to retry over TCP. With it we answer up to
 * min(client size, {@link #getServerUdpSize()}) bytes over UDP and echo an
 * OPT record, as the RFC requires. DNSSEC (the DO bit) and EDNS options are
 * not supported; options are ignored and the DO bit is never set.
 * <p>
 * The default server size is 1232 bytes (the DNS Flag Day 2020 value, which
 * avoids IP fragmentation); property JDns.ednsUdpSize, 512 turns the larger
 * size off (an OPT is still echoed).
 */
public final class Edns implements DNS {

	/** Recommended EDNS UDP size (DNS Flag Day 2020). */
	public static final int DEFAULT_UDP_SIZE = 1232;
	/** Largest size we will ever use over UDP. */
	public static final int MAX_UDP_SIZE = 4096;

	private static volatile int serverUdpSize = DEFAULT_UDP_SIZE;

	private Edns() {
	}

	public static int getServerUdpSize() {
		return serverUdpSize;
	}

	/** Largest UDP response this server sends to EDNS clients (512..4096). */
	public static void setServerUdpSize(int size) {
		serverUdpSize = Math.max(MAX_UDP_PAYLOAD, Math.min(MAX_UDP_SIZE, size));
	}

	/** What a request said about EDNS. */
	public static final class Request {
		/** A request without an OPT record. */
		public static final Request NONE = new Request(false, MAX_UDP_PAYLOAD, 0, false);

		private final boolean present;
		private final int udpSize;
		private final int version;
		private final boolean malformed;

		Request(boolean present, int udpSize, int version, boolean malformed) {
			this.present = present;
			this.udpSize = udpSize;
			this.version = version;
			this.malformed = malformed;
		}

		/** Did the request carry an OPT record? */
		public boolean isPresent() {
			return present;
		}

		/** The client's UDP payload size (512 if it sent no OPT or less than 512). */
		public int getUdpSize() {
			return udpSize;
		}

		public int getVersion() {
			return version;
		}

		/** More than one OPT, or an OPT with a non-root owner: answer FORMERR (RFC 6891 6.1.1). */
		public boolean isMalformed() {
			return malformed;
		}

		/** An EDNS version we don't implement: answer BADVERS (RFC 6891 6.1.3). */
		public boolean isBadVersion() {
			return present && !malformed && version != 0;
		}

		/** Largest UDP response to send to this client. */
		public int maxUdpResponse() {
			if( !present ) {
				return MAX_UDP_PAYLOAD;
			}
			return Math.max(MAX_UDP_PAYLOAD, Math.min(udpSize, serverUdpSize));
		}

		public String toString() {
			return present ? "EDNS"+version+" udp="+udpSize+(malformed ? " malformed":"") : "no EDNS";
		}
	}

	/** Read the OPT record (if any) of a request. */
	public static Request parse(Message request) {
		if( request == null ) {
			return Request.NONE;
		}
		RR opt = null;
		boolean malformed = false;
		for(RR rr : request.getAdditional()) {
			if( rr.getType() == OPT ) {
				if( opt != null ) {
					malformed = true;
				}
				opt = rr;
			}
		}
		if( opt == null ) {
			return Request.NONE;
		}
		if( opt.getNameAsName().getLables().size() != 0 ) {
			malformed = true;
		}
		//  CLASS holds the payload size; TTL = ext-rcode(8) version(8) DO(1) Z(15)
		int size = Math.max(MAX_UDP_PAYLOAD, opt.getDnsClass() & 0xffff);
		int version = (opt.getTTL() >>> 16) & 0xff;
		return new Request(true, size, version, malformed);
	}

	/** An OPT record with our UDP size and the given extended RCODE bits. */
	public static RR newOpt(int extendedRcode) {
		RR opt = new RR("", OPT, serverUdpSize);
		opt.setTTL((extendedRcode & 0xff) << 24);
		opt.setRdata(new byte[0]);
		return opt;
	}

	/**
	 * Make a response follow the request's EDNS: any OPT copied from
	 * elsewhere (e.g. an upstream answer) is removed and, if the client used
	 * EDNS, our own OPT is added. RCODEs over 15 (BADVERS) are split between
	 * the header and the OPT.
	 */
	public static void applyToResponse(Message response, Request request) {
		if( response == null ) {
			return;
		}
		removeOpt(response.getAdditional());
		if( request == null || !request.isPresent() ) {
			return;
		}
		int rcode = response.getResponseCode();
		int ext = 0;
		if( rcode > 15 ) {
			ext = rcode >> 4;
			response.setResponseCode(rcode & 0xf);
		}
		response.addAdditional(newOpt(ext));
	}

	/** Build the BADVERS reply for a request with an unsupported EDNS version. */
	public static Message badVersion(Message request) {
		Message ret = emptyResponse(request);
		//  BADVERS = 16: header RCODE 0, extended RCODE 1 (RFC 6891 6.1.3)
		ret.setResponseCode(0);
		ret.addAdditional(newOpt(BADVERS >> 4));
		return ret;
	}

	/** FORMERR (no OPT) for a request with more than one OPT or a bad one. */
	public static Message formatError(Message request) {
		Message ret = emptyResponse(request);
		ret.setResponseCodeFormatError();
		return ret;
	}

	private static Message emptyResponse(Message request) {
		Message ret = new Message();
		ret.setHeader(request.getHeader().copy());
		ret.setMessageTypeResponse();
		ret.getHeader().setAA(false);
		ret.getHeader().setTC(false);
		for(Section s : request.getQuestion()) {
			ret.addQuestion(s);
		}
		return ret;
	}

	private static void removeOpt(List<RR> list) {
		if( list == null ) {
			return;
		}
		for(Iterator<RR> it = list.iterator(); it.hasNext(); ) {
			if( it.next().getType() == OPT ) {
				it.remove();
			}
		}
	}
}
