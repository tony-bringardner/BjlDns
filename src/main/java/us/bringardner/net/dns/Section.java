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

/**
This class represents a 'Section' of a DNS Message (as defined in RFC 1035)
 **/
public class Section extends Utility {
	/** A Domian name **/
	Name  name; 

	/** DNS TYPE (A,MX,NS,...) **/
	// 16 bit == type of query
	int   type; 

	/** DNS CLASS (IN,...) **/
	// 16 bit = Query dnsClass (IN,...)
	int   dnsClass;

	/** 
	Default constructor (values name= "", type=A,class=IN)
	 **/
	public Section() {
		this("",A,IN);
	}
	/**
	Construct a section with an assigned name
	 **/
	public Section(String name) 
	{
		this(name,A,IN);
	}
	/**
	Construct a DNS Section
	@param n Name
	@param t Type
	@param c Class
	 **/
	public Section(String name, int type, int dnsClass) 
	{
		this.name = new Name(name);
		this.type = type;
		this.dnsClass = dnsClass;

	}	
	public Section(String name, int type, String dnsClass) 
	{
		this(name,type,IN);
		setDnsClass(dnsClass);
	}	
	public Section(String name, String type, int dnsClass) 
	{
		this(name,A,dnsClass);
		setType(type);
	}
	/**
	Construct a DNS Section
	@param n Name
	@param t Type
	@param c Class
	 **/
	public Section(String name, String type, String dnsClass) 
	{
		this(name,A,IN);
		setDnsClass(dnsClass);
		setType(type);
	}
	/**
	Construct a Section from the data in a byte buffer
	 **/
	public Section(ByteBuffer inme) {
		this();
		name = new Name(inme);
		type = inme.nextShort();
		dnsClass = inme.nextShort();
	}
	
	public Section(Section question) {
		this.dnsClass = question.dnsClass;
		this.name = new Name(question.name);
		this.type = question.type;
		
	}
	
	public void copy(Section newObj){
		newObj.dnsClass = dnsClass;
		newObj.name = new Name(name);
		newObj.type = type;

	}
	
	public int getDnsClass() { return dnsClass;  }
	public String getName() 
	{ 
		return name.toString(); 
	}
	public Name getNameAsName() 
	{ 
		return name;
	}
	public String getParentName() 
	{
		return name.getParent();
	}
	public Name getParentNameAsName() 
	{
		return name.getParentName();
	}
	public int getType() { return type;  }
	public int matchCount(Name other)
	{
		return name.matchCount(other);
	}
	public int matchCount(Section other)
	{
		return name.matchCount(other.name);
	}
	/*
	 * Replace any wild cards in this name with lables from the other name
	 */
	public void replaceWildCards(String otherName)
	{
		replaceWildCards(new Name(otherName));
	}

	/*
	 * Replace any wild cards in this name with lables from the other name
	 */
	public void replaceWildCards(Name otherName)
	{
		name.replaceWildCards(otherName);
	}

	public void setDnsClass(int c) { 
		dnsClass = (short)c; 
	}
	public void setDnsClass(String t) { 
		dnsClass = classOf(t);
	}
	public void setName(String n) { name = new Name(n); }
	public void setType(int t) { type = t; }
	public void setType(String t) { 
		type = typeOf(t);
	}
	public int size() {
		return name.size()+4;
	}
	public void toByteArray(ByteBuffer buf) {
		buf.setName(name);
		buf.setShort(type);
		buf.setShort(dnsClass);
	}
	public String toString() {
		return name.toString()+" "+
				(type==255 ? "ANY":TYPENAMES[type])+" "+
					(dnsClass == 255 ? "ANY": 
						dnsClass > 255 ? 
					"CLASS="+dnsClass:CLASSNAMES[dnsClass]);
	}
}
