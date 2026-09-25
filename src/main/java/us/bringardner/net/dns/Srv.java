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
 */
package us.bringardner.net.dns;

/**
 * The DNS SRV resource record (RFC 2782): priority, weight, port and target.
 * The target is never compressed on the wire (RFC 2782).
 */
public class Srv extends RR {

	private int priority;
	private int weight;
	private int port;
	private Name target = new Name("");

	public Srv() {
		super();
		setType(SRV);
		setDnsClass(IN);
		isBase = false;
		dirty = true;
	}

	public Srv(String name) {
		this(name, IN);
	}

	public Srv(String name, int dnsClass) {
		super(name,SRV,dnsClass);
		isBase = false;
		dirty = true;
	}

	/** An SRV record from a generic record read from the wire. */
	public Srv(RR rr) {
		super(rr);
		//  Again: the field initializers ran after super() had parsed the rdata
		setFromRdata();
		isBase = false;
	}

	@Override
	public RR copy() {
		Srv ret = new Srv();
		super.copy(ret);
		ret.priority = priority;
		ret.weight = weight;
		ret.port = port;
		ret.target = target;
		return ret;
	}

	public int getPriority() { return priority; }
	public int getWeight() { return weight; }
	public int getPort() { return port; }
	public String getTarget() { return target.toString(); }

	public void setPriority(int priority) {
		this.priority = check(priority, "priority");
		dirty = true;
	}

	public void setWeight(int weight) {
		this.weight = check(weight, "weight");
		dirty = true;
	}

	public void setPort(int port) {
		this.port = check(port, "port");
		dirty = true;
	}

	public void setTarget(String target) {
		this.target = new Name(target);
		dirty = true;
	}

	private static int check(int value, String what) {
		if( value < 0 || value > 0xffff ) {
			throw new IllegalArgumentException("SRV "+what+" must be 0-65535: "+value);
		}
		return value;
	}

	@Override
	public void setFromRdata() {
		ByteBuffer in = new ByteBuffer(rdata);
		if( source != null ) {
			in = new ByteBuffer(source.getBuf(),sourcePos);
		}
		priority = in.nextShort();
		weight = in.nextShort();
		port = in.nextShort();
		target = new Name(in);
		dirty = false;
	}

	@Override
	public void toByteArray(ByteBuffer out) {
		super.toByteArray(out);
		out.setShort(priority);
		out.setShort(weight);
		out.setShort(port);
		writeUncompressed(out, target.toString());
		out.setRdLength();
	}

	/** Write a name without compression pointers (RFC 2782 forbids them in SRV). */
	static void writeUncompressed(ByteBuffer out, String name) {
		if( name != null ) {
			for(String label : name.split("[.]")) {
				if( !label.isEmpty() ) {
					byte [] b = label.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
					out.setByte((byte)b.length);
					out.setBytes(b);
				}
			}
		}
		out.setByte((byte)0);
	}

	@Override
	public String getRdataAsString() {
		return priority+" "+weight+" "+port+" "+target+".";
	}

	@Override
	public String toString() {
		return super.toString()+" priority="+priority+" weight="+weight+" port="+port+" target="+target;
	}
}
