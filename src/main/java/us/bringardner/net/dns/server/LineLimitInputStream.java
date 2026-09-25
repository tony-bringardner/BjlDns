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

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Fails a read once more than maxLine bytes have arrived without a '\n'.
 * <p>
 * The admin session reads lines with a CRLFLineReader, which keeps the line in
 * memory until the terminator arrives; without a limit a client could send bytes
 * without a line end until the heap was exhausted (and an OutOfMemoryError stops
 * the server). Placed between the socket and the reader, this caps a line at
 * maxLine plus one read buffer.
 */
class LineLimitInputStream extends FilterInputStream {

	/** Thrown when a line is longer than the limit. */
	static class LineTooLongException extends IOException {
		private static final long serialVersionUID = 1L;

		LineTooLongException(int max) {
			super("line longer than "+max+" bytes");
		}
	}

	private volatile int maxLine;
	private int sinceNewline;

	LineLimitInputStream(InputStream in, int maxLine) {
		super(in);
		setMaxLine(maxLine);
	}

	void setMaxLine(int maxLine) {
		this.maxLine = Math.max(1, maxLine);
	}

	int getMaxLine() {
		return maxLine;
	}

	private void count(int b) throws LineTooLongException {
		if( b == '\n' ) {
			sinceNewline = 0;
		} else if( ++sinceNewline > maxLine ) {
			throw new LineTooLongException(maxLine);
		}
	}

	@Override
	public int read() throws IOException {
		int b = super.read();
		if( b >= 0 ) {
			count(b);
		}
		return b;
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		int n = super.read(b, off, len);
		for(int i=0; i < n; i++ ) {
			count(b[off+i]);
		}
		return n;
	}

	@Override
	public long skip(long n) throws IOException {
		//  Skipped bytes are not seen, so read them instead
		byte [] buf = new byte[(int)Math.min(Math.max(n, 0), 4096)];
		int got = read(buf, 0, buf.length);
		return Math.max(got, 0);
	}
}
