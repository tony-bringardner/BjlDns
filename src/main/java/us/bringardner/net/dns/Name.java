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
 * ~version~V000.00.05-V000.00.00-
 */
package us.bringardner.net.dns;

import java.util.*;

/**
		A Name is made up of a series of lables
		Each lable is a size followed by ascii bytes
		terminated with a null size
 */
public class Name implements DNS 
{
	private int chrCount = 0;
	private List<Label> myLables = new ArrayList<Label>();
	private boolean doWildCard = true;
	private boolean hasWildCard = false;

	public Name() {
	}
	
	public Name(String name) { 
		setName(name);
	}
	
	public Name(ByteBuffer in) {
		init(in);
	}
	
	public Name(Name name) {

		for(int i=0,sz=name.myLables.size(); i< sz; i++  ) {
			addLabel(new Label(name.myLables.get(i).toString()));
		}

	}
	
	private void addLabel(Label label){
		myLables.add(label);
		if( label.isWildCard() ) {
			hasWildCard = true;
		}
	}
	
	/**
	 * Compares two objects for equality. Returns a boolean that indicates
	 * whether this object is equivalent to the specified object. This method
	 * is used when an object is stored in a hashtable.
	 * @param obj the Object to compare with
	 * @return true if these Objects are equal; false otherwise.
	 * @see java.util.Hashtable
	 */
	public boolean equals(Object obj) {
		boolean ret = false;
		Name other = null;

		if( obj instanceof Name ) {
			int me=myLables.size();
			other = (Name)obj;
			int you = other.myLables.size();
			//  If the sizes are not equal then we are not
			if( me == you ) {

				for(int i=0; i < me ; i++ ) {
					if(!(ret=((Label)myLables.get(i)).equals(((Label)other.myLables.get(i)),doWildCard)) ) {
						//  If any don't match were done 
						break;
					}
				}
			}
		}

		return ret;
	}
	
	public List<Label> getLables() {
		return myLables;
	}
	
	public String getParent() {
		StringBuffer buf = new StringBuffer();
		if( myLables.size() > 1 ) {
			buf.append(myLables.get(1));
			for(int i=2,sz=myLables.size(); i< sz; i++ ) {
				buf.append("."+myLables.get(i));
			}
		}
		return buf.toString();
	}
	
	public Name getParentName() {
		Name parent = null;

		if( myLables.size() > 1 ) {
			parent = new Name();
			for(int i=1,sz=myLables.size(); i< sz; i++ ) {
				parent.myLables.add(myLables.get(i));
			}
		}
		return parent;
	}
	
	/**
	 * 
	 * Creation date: (6/20/2003 9:43:03 AM)
	 * @return boolean
	 */
	public boolean hasWildCard() {
		return hasWildCard;
	}
	
	private void init(ByteBuffer in) {
		myLables = new ArrayList<Label>();
		chrCount = 0;

		in = in.chkPointer();           
		int cnt = in.next();
		while(cnt > 0 ) {
			chrCount += cnt;
			StringBuffer sb = new StringBuffer();
			for(int i=0; i< cnt; i++) {
				sb.append((char)in.next());
			}
			addLabel(new Label(sb.toString()));
			in = in.chkPointer();           
			cnt = in.next();
		}
	}
	
	/**
	 * 
	 * Creation date: (6/20/2003 9:43:03 AM)
	 * @return boolean
	 */
	public boolean isDoWildCard() {
		return doWildCard;
	}
	
	public int matchCount(String str) {
		return matchCount(new Name(str) ) ;
	}
	
	/**
	 * Compare two myLables and determine the number of matching myLables
	 * from the root.
	 **/
	public int matchCount(Name other) {
		int ret = 0;
		int me=myLables.size()-1;
		int you = other.myLables.size()-1;
		while( you>=0 && me >=0 ) {
			if( (myLables.get(me)).equals(other.myLables.get(you)) ) {
				ret++;
				me--;
				you--;
			} else {
				break;
			}
		}

		return ret;
	}
	
	/**
	 * Replace any wild card labels in this name with non wild card labels from the other name
	 * 
	 **/
	public void replaceWildCards(Name other) {
		//int ret = 0;
		int me=myLables.size()-1;
		int you = other.myLables.size()-1;
		while( you>=0 && me >=0 ) {
			Label mine = (Label)myLables.get(me);
			if( mine.isWildCard() ) {
				Label yours = (Label)other.myLables.get(you);
				myLables.set(me,yours);
			}

			me--;
			you--;
		}
	}
	
	/**
	 * 
	 * Creation date: (6/20/2003 9:43:03 AM)
	 * @param newDoWildCard boolean
	 */
	public void setDoWildCard(boolean newDoWildCard) {
		doWildCard = newDoWildCard;
	}
	
	public int setName(byte [] buf, int start) {
		myLables = new ArrayList<Label>();
		chrCount = 0;

		int idx = start;
		int cnt = buf[idx++];

		while(cnt > 0 ) {
			chrCount += cnt;
			StringBuffer sb = new StringBuffer(cnt);
			for(int i=0; i< cnt; i++) {
				sb.append((char)buf[idx++]);
			}
			addLabel(new Label(sb.toString()));
			cnt = buf[idx++];
		}
		return (idx - start);

	}
	
	public void setName(String n) {
		myLables = new ArrayList<Label>();
		chrCount = 0;
		String tmp = null;
		if( n.endsWith(".") ) {
			n = n.substring(0,n.length()-1);
		}
		int idx = n.indexOf(".");

		while(idx > 0 && idx < n.length()) {
			tmp = n.substring(0,idx);
			chrCount += tmp.length();
			n = n.substring(idx+1);
			addLabel(new Label(tmp));
			idx = n.indexOf(".");
		}

		addLabel(new Label(n));
		chrCount += n.length();

		/*
		  If the name is in %d.%d.%d.%d form, make it an 
		  arpa addres by reversing and appending in-addr.arpa
		  caller should also set the question type to PTR.
		 See RFC-1034 (5.2.1 bullet #2)
		 */

		if( n.length() > 0 && Character.isDigit(n.charAt(0)) && myLables.size()==4 ) {
			List<Label> tmp1 = new ArrayList<Label>(6);
			for(int i=3; i>=0; i--) {
				tmp1.add(myLables.get(i));
			}
			tmp1.add(new Label("in-addr"));
			tmp1.add(new Label("arpa"));
			myLables = tmp1;
			hasWildCard = false;
			chrCount+= 11;
		}

	}
	
	public int size() {
		return chrCount+myLables.size()+1;
	}
	
	public byte [] toByteArray() {
		byte [] ret = new byte [chrCount+myLables.size()+1];
		String tmp = null;
		int idx = 0;

		for(int i=0,sz=myLables.size(); i<sz; i++ ) {
			tmp = myLables.get(i).toString();
			ret[idx++] = (byte)tmp.length();
			for(int ii = 0; ii < tmp.length(); ii++) {
				ret[idx++] = (byte)tmp.charAt(ii);
			}
		}

		ret[idx] = 0;
		return ret;

	}
	
	/**
	 * Convert to String form l1.l2[.ln]
	 */
	public String toString() {
		StringBuffer buf = new StringBuffer();
		if( myLables.size() > 0 ) {
			buf.append(myLables.get(0).toString());
			for(int i=1,sz=myLables.size(); i< sz; i++ ) {
				buf.append("."+myLables.get(i));
			}
		}
		return buf.toString();
	}
	
}
