package us.bringardner.net.dns.util;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Test access to NsLookup's package-private helpers. */
public class NsLookupAccess {

	public static String reverseName(String text) {
		return NsLookup.reverseName(text);
	}

	public static List<String> searchNames(String name) {
		return NsLookup.searchNames(name);
	}

	public static void searchList(String ... list) {
		NsLookup.searchList = new ArrayList<String>(Arrays.asList(list));
		NsLookup.search = true;
	}

	public static void ndots(int n) {
		NsLookup.ndots = n;
	}

	public static String characterStrings(byte [] rdata) {
		return NsLookup.characterStrings(rdata);
	}

	public static String generic(byte [] rdata) {
		return NsLookup.generic(rdata);
	}

	public static String ipv6Text(byte [] a) {
		return NsLookup.ipv6Text(a);
	}
}
