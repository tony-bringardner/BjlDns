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
 * ~version~V000.01.04-V000.01.02-V000.00.05-V000.00.00-
 */
package us.bringardner.net.dns.server;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import us.bringardner.io.CRLFLineReader;
import us.bringardner.io.CRLFLineWriter;
import us.bringardner.net.dns.A;
import us.bringardner.net.dns.DnsBaseClass;
import us.bringardner.net.dns.Message;
import us.bringardner.net.dns.Section;
import us.bringardner.net.dns.resolve.QueryData;

/**
 * 
 * Creation date: (6/16/2003 9:41:42 AM)
 * @author: Tony Bringardner
 */
public class DnsAdminProcessor  extends DnsBaseClass implements Runnable, DnsAdminConstants {

	private static class CommandArgs {
		List<String> args=new ArrayList<String>();
		Map<String,String> flags= new TreeMap<String, String>(); 
	}


	private interface ICommand {
		String getName();
		String getHelp();
		void proccess(CommandArgs args) throws IOException;
	}

	private class DebugCommand implements ICommand{

		@Override
		public String getName() {
			return DEBUG;
		}

		@Override
		public String getHelp() {
			return "show or set current debug flag\n\tUsage: debug [true|false]";
		}

		@Override
		public void proccess(CommandArgs args) throws IOException {
			if( args.args.size() > 0) {
				DnsServer.setDebug(args.args.get(0).startsWith("t"));
			}
			out.writeLine("+Debug= "+DnsServer.isDebug());
		}

	}

	private class Help implements ICommand{

		@Override
		public String getName() {
			return "help";
		}

		@Override
		public String getHelp() {
			return "Get help for JDns admin commands.\n\tUsage: help [commandName,...";
		}

		@Override
		public void proccess(CommandArgs args) throws IOException {

			Map<String,ICommand> tmp = new TreeMap<String, DnsAdminProcessor.ICommand>();
			if( args.args.size() == 0 ) {
				tmp = commands;
			} else {
				for(int idx=0; idx < args.args.size(); idx++) {
					String name = args.args.get(idx);
					ICommand cmd = commands.get(name);
					if( cmd == null ) {
						out.writeLine("No help availible for "+name);
					} else {
						tmp.put(name, cmd);
					}
				}
			}

			for(ICommand cmd : tmp.values() ) {
				out.writeLine(cmd.getName()+": "+cmd.getHelp());
			}
			out.writeLine("+OK");
		}

	}

	private class ListZones implements ICommand {

		@Override
		public String getName() {
			return LIST;
		}

		@Override
		public String getHelp() {
			return "List all configured domains.\n\tUsage: list";
		}

		@Override
		public void proccess(CommandArgs args) throws IOException {
			boolean dynamic = args.flags.containsKey("d");

			if( dynamic ) {
				Map<String, List<A>> dynamicRecord = server.getDynamic();
				for(List<A> record: dynamicRecord.values()) {
					for(A a : record) {
						out.writeLine(a.toString());
					}
				}
			} else {
				if( args.args.size() > 0 ) {
					listZone(args.args.get(0));
				} else {
					listZones();
				}
			}

		}

	}

	private class Resolve implements ICommand {

		String usage = "Usage: resolve [-r] [-t=type]name [,name,...]\n\tUse -r to use the resolver instead of server query.\n\tUse -t=type to specify type (default is A)";
		@Override
		public String getName() {
			return RESOLVE;
		}

		@Override
		public String getHelp() {
			return "Resolve oen or more names. "+usage;
		}

		@Override
		public void proccess(CommandArgs args) throws IOException {
			if( args.args.size()==0) {
				out.writeLine(usage);
			} else {
				String type =args.flags.get("t");
				if( type == null) {
					type = "A";
				}
				boolean isResolver = args.flags.containsKey("r");
				for(String name : args.args) {
					List<Message> result = null;	

					if(isResolver) {
						Section question = new Section(name,type,us.bringardner.net.dns.Section.IN);
						Message msg = us.bringardner.net.dns.resolve.Resolver.resolve(question);
						out.writeLine("Resolved from Resolver");
						if( msg != null ) {
							result = new ArrayList<>();
							result.add(msg);
							out.writeLine(result.toString());
						}
					} else {

						us.bringardner.net.dns.Message msg = new us.bringardner.net.dns.Message();
						msg.setQuestion(name,type,us.bringardner.net.dns.Section.IN);
						QueryData query = new QueryData(null,-1,msg);
						result = server.query(query);
						out.writeLine("Resolved from Server");	

					}
					if( result == null ) {
						out.writeLine("Null reply ");
					} else if( result.isEmpty()) {
						out.writeLine("No reply ");
					} else {	
						for(Message m : result) {
							out.writeLine(m.toString());
						}
					}
				}
			} 

			out.writeLine("+Complete");

		}

	}


	private class Quit implements ICommand {

		@Override
		public String getName() {
			return QUIT;
		}

		@Override
		public String getHelp() {
			return "Exit the current session (Close socket)";
		}

		@Override
		public void proccess(CommandArgs args) throws IOException {

			out.writeLine("+Exiting");
			stop();
		}

	}

	private class Memory implements ICommand {

		@Override
		public String getName() {
			return MEM;
		}

		@Override
		public String getHelp() {
			return "Report the start time and free memory.";
		}

		@Override
		public void proccess(CommandArgs args) throws IOException {
			out.writeLine("+Start up="+server.getStartTime()+" free mem="+(Runtime.getRuntime().freeMemory()));

		}

	}


	private class Reset implements ICommand {

		@Override
		public String getName() {
			return RESET;
		}

		@Override
		public String getHelp() {
			return "Reset / Clear the Resoler cache ";
		}

		@Override
		public void proccess(CommandArgs args) throws IOException {
			out.writeLine("Cache size before ="+us.bringardner.net.dns.resolve.Resolver.cacheSize());
			us.bringardner.net.dns.resolve.Resolver.reset();
			out.writeLine("Cache size after ="+us.bringardner.net.dns.resolve.Resolver.cacheSize());
			out.writeLine("+Complete");
		}

	}


	private class Status implements ICommand {

		@Override
		public String getName() {
			return STATUS;
		}

		@Override
		public String getHelp() {
			return "Get the current status of the DNS Server";
		}

		@Override
		public void proccess(CommandArgs args) throws IOException {
			out.writeLine("Server state="+server.getState());
			out.writeLine(us.bringardner.net.dns.resolve.Resolver.getStats());

			String type = ALL;
			if( args.args.size() > 0 ) {
				type = args.args.get(0);
			}

			if( type.equals(RESOLVER) || type.equals(ALL)) {
				sendStatus(RESOLVER,us.bringardner.net.dns.resolve.Resolver.getResolvers());
			}

			if( type.equals(TCP) || type.equals(ALL)) {
				sendStatus(TCP,server.getTCPProsessors());
			}
			if( type.equals(UDP) || type.equals(ALL)) {
				sendStatus(UDP,server.getUDPProsessors());
			}

			out.writeLine("+Status done");


		}

	}


	private class AddDynamic implements ICommand {

		String usage = "-Usage: "+ADD_DYNAMIC+" name [ipAddress]\n\tIf ipAddress is not provided the client address will be used.";
		@Override
		public String getName() {
			return ADD_DYNAMIC;
		}

		@Override
		public String getHelp() {
			return "Add or update a dynamic address.\n\t"+usage;
		}

		@Override
		public void proccess(CommandArgs args) throws IOException {
			if( args.args.size() == 0) {
				out.writeLine(usage);
			} else {
				String name = args.args.get(0);
				String addr = null;
				if( args.args.size() == 1) {
					addr = sock.getInetAddress().toString();
					if( addr.endsWith("127.0.0.1")) {
						addr = InetAddress.getLocalHost().toString();
					}
					int idx = addr.indexOf('/');
					if( idx >= 0 ) {
						addr = addr.substring(idx+1);
					}
					System.out.println("addr="+addr+" sock="+sock.getRemoteSocketAddress());
				} else {
					addr = args.args.get(1);
				}

				try {
					server.addOrUpdateDynamic(name, addr);
				} catch (ClassNotFoundException | SQLException e1) {
					throw new IOException(e1);
				}

				out.writeLine("+"+name+"  set to addr="+addr);
			}			
		}
	}

	private class DeleteDynamic implements ICommand {

		@Override
		public String getName() {
			return "del_dynamic";
		}

		@Override
		public String getHelp() {
			return "Delete a dynamic address.\n\tUsage: del_dynamic name [,name,..]";
		}

		@Override
		public void proccess(CommandArgs args) throws IOException {
			if( args.args.size() < 1) {
				out.writeLine("-Usage: del_dynamic name [,name,..]");
			} else {
				for(String name : args.args) {
					server.removeDynamic(name);					
				}
				out.writeLine("+OK");
			}			
		}
	}

	private class AddDomain implements ICommand {

		@Override
		public String getName() {
			return  ADD_DOMAIN;
		}

		@Override
		public String getHelp() {
			return ADD_DOMAIN+" Add a domain to the server.\n\tUsage: "+ADD_DOMAIN+" name [,name,..]";
		}

		@Override
		public void proccess(CommandArgs args) throws IOException {
			if( args.args.size() < 1) {
				out.writeLine("-Usage: "+ADD_DOMAIN+" name [,name,..]");
			} else {
				for(String name : args.args) {
					server.addDomain(name);					
				}
				out.writeLine("+OK");
			}			
		}
	}

	private class DeleteDomain implements ICommand {

		@Override
		public String getName() {
			return  DEL_DOMAIN;
		}

		@Override
		public String getHelp() {
			return DEL_DOMAIN+" Delete a domain to the server.\n\tUsage: "+DEL_DOMAIN+" name [,name,..]";
		}

		@Override
		public void proccess(CommandArgs args) throws IOException {
			if( args.args.size() < 1) {
				out.writeLine("-Usage: "+DEL_DOMAIN+" name [,name,..]");
			} else {
				for(String name : args.args) {
					server.removeDomain(name);					
				}
				out.writeLine("+OK");
			}			
		}
	}
	
	private static void registerCommand(ICommand cmd) {
		commands.put(cmd.getName(), cmd);
	}

	private static Map<String,ICommand> commands = new TreeMap<String, DnsAdminProcessor.ICommand>();

	{

		registerCommand(new AddDomain());
		registerCommand(new DeleteDomain() );
		registerCommand(new Help());
		registerCommand(new ListZones());
		registerCommand(new Status());
		registerCommand(new AddDynamic());
		registerCommand(new DeleteDynamic());
		registerCommand(new DebugCommand());
		registerCommand(new Quit());

		registerCommand(new Memory());
		registerCommand(new Reset());
		registerCommand(new Resolve());
		registerCommand(new Reset());


	}

	private Socket sock;
	private CRLFLineReader in;
	private CRLFLineWriter out;
	private Thread thread;
	private boolean running = false;
	private DnsServer server;

	//  Default timeout = 1min
	private int timeout = 60*1000*10;


	public static void main(String args[] ) {
		String tmp = "test one -x=5 -z -y 6 two three";

		CommandArgs ca = getArgs(tmp.split("[ ]"));
		System.out.println("args="+ca.args);
		System.out.println("flags="+ca.flags);
	}

	/**
	 * AdminProcessor constructor comment.
	 */
	public DnsAdminProcessor(DnsServer server,Socket sock) throws IOException {
		this.server = server;
		this.sock = sock;
		sock.setSoTimeout(5000);
		in = new CRLFLineReader(sock.getInputStream());
		out= new CRLFLineWriter(sock.getOutputStream());
	}

	private static  CommandArgs getArgs(String args[] ) {
		CommandArgs ret = new CommandArgs();
		for(int idx=1; idx<args.length; idx++ ) {
			if( args[idx].startsWith("-")) {
				String name = args[idx].substring(1); 
				String parts[] = name.split("[=]");
				if(parts.length == 1) {
					if( args.length == idx+1 ) {
						ret.flags.put(name,name);	
					} else {
						if( args[idx+1].startsWith("-")) {
							ret.flags.put(name,name);
						} else {
							ret.flags.put(name,args[++idx]);
						}
					}					
				} else {
					ret.flags.put(parts[0],parts[1]);
				}
			} else {
				ret.args.add(args[idx]);
			}
		}

		return ret;
	}

	/**
	 * Code to perform when this object is garbage collected.
	 * 
	 * Any exception thrown by a finalize method causes the finalization to
	 * halt. But otherwise, it is ignored.
	 */
	protected void close() {
		if( in != null ) { try { in.close(); } catch(Exception ex) {} }
		if( out != null ) { try { out.close(); } catch(Exception ex) {} }
		if( sock != null ) { try { sock.close(); } catch(Exception ex) {} }
		in = null;
		out = null;
		sock = null;
	}

	/**
	 * Code to perform when this object is garbage collected.
	 * 
	 * Any exception thrown by a finalize method causes the finalization to
	 * halt. But otherwise, it is ignored.
	 */
	protected void finalize() throws Throwable  {

		if( sock != null ) { 
			close();
		}
	}

	private void listZone(String key) throws IOException {
		Zone zone = server.getZone(key);

		if( zone == null ) {
			out.writeLine("No zone found for '"+key+"'");
		} else {
			out.writeLine(zone.toString(true));
		}
		out.writeLine("+ListComplete");
	}

	private void listZones() throws IOException {
		Map<String, Zone> zones = server.getZones();
		//int sz = zones.size();

		final Iterator<String> it = zones.keySet().iterator();

		while( it.hasNext() ) {
			Zone zone = (Zone)zones.get(it.next().toString());
			out.writeLine(zone.getName());
		}
		out.writeLine("+ListComplete");
	}


	public void delDynamic(String name) throws IOException, ClassNotFoundException, SQLException {
		server.removeDynamic(name);
	}

	public void addDynamic(String name) throws IOException, ClassNotFoundException, SQLException {
		if( name == null || name.indexOf('*') >=0) {
			out.writeLine("-Invalide name='"+name+"'");
			return;
		}

		String addr = sock.getInetAddress().toString();
		if( addr.endsWith("127.0.0.1")) {
			addr = InetAddress.getLocalHost().toString();
		}
		int idx = addr.indexOf('/');
		if( idx >= 0 ) {
			addr = addr.substring(idx+1);
		}
		

		server.addOrUpdateDynamic(name, addr);

		out.writeLine("+"+name+"  set to addr="+addr);
	}




	public void run() {
		
		running = true;
		try {
			sock.setSoTimeout(timeout);
		} catch(Exception ex ) {
			log("Can't set timeout",ex);
		}

		String line = null;
		String lastLine = STATUS;
		try {
			out.writeLine("+JDns admin ready");
		} catch (IOException e) {
		}
		while ( running ) {
			try {
				try {	out.flush();}catch(Exception ex){}

				if((line=in.readLine())==null) {
					running = false;
				} else {
					if( line.length() == 0 ) {
						line = lastLine;
					} else {
						lastLine = line;
					}

					String [] cmd = line.split(" ");
					ICommand icmd = commands.get(cmd[0]);
					if( icmd == null ) {
						out.writeLine("-UnRecognized command "+line);
					} else {
						CommandArgs args = getArgs(cmd);
						icmd.proccess(args);
					}

				}

			} catch(IOException ex) {
				log("Error processing cmd="+line,ex);
				running = false;
			} catch(Exception ex) {
				try {
					out.writeLine("Error processing '"+line+"'");
					out.writeLine(ex.toString());
				} catch(IOException ee) {
					//  Can't communicate with client?
					running = false;
				}
			}			
		}

		try {	out.flush();}catch(Exception ex){}
		if( in != null ) { try { in.close(); } catch(Exception ex) {} }
		if( out != null ) { try { out.close(); } catch(Exception ex) {} }
		if( sock != null ) { try { sock.close(); } catch(Exception ex) {} }

		in = null;
		out = null;
		sock = null;

	}


	private void sendStatus(String type, DnsBaseClass [] procs) throws IOException {
		out.writeLine("");
		out.writeLine("State of "+procs.length+" "+type+ " processors follows");
		for(int i=0; i< procs.length; i++ ) {
			out.writeLine("\t"+i+" "+procs[i].getState());
		}
	}

	public void start() {
		thread = new Thread(this);
		thread.setName("DnsAdmin");
		thread.start();
	}

	public void stop() {
		running = false;
		thread.interrupt();
	}


}
