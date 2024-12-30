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
 * ~version~V000.00.05-V000.00.03-V000.00.01-
 */
package us.bringardner.net.dns;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextPane;
import javax.swing.border.EmptyBorder;
import javax.swing.text.AttributeSet;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyleContext;

/**
 * This class is only here to help debug unit tests.
 */
public class CompareTextFrame extends JFrame {

	private static final long serialVersionUID = 1L;
	private JPanel contentPane;
	private JTextPane expectedTextPane;
	private JTextPane actualTextPane;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					CompareTextFrame frame = new CompareTextFrame();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	
	public static void showFrame(String ex, String ac) {
		int ecol = 0;
		int acol = 0;
		CompareTextFrame frame = new CompareTextFrame();
		frame.setLocationRelativeTo(null);
		byte [] ed = ex.getBytes();
		byte [] ad = ac.getBytes();
		int sz = Math.max(ed.length, ad.length) ;
		
		for(int idx=0; idx < sz; idx++ ) {
			char e = '~';
			char a = '~';
			if( idx< ed.length) {
				e=(char)ed[idx];
			}
			if( idx< ad.length) {
				a = (char)ad[idx];
			} 
			
			if( e=='\n') {
				appendToPane(frame.expectedTextPane, "\t len="+ecol, Color.BLACK);
				ecol = 0;
			}
			if( a=='\n') {
				appendToPane(frame.actualTextPane, "\t len="+acol, Color.BLACK);
				acol = 0;
			}
			
			if( a != e) {
				 appendToPane(frame.expectedTextPane, ""+e, Color.RED);
				 appendToPane(frame.actualTextPane, ""+a, Color.RED);
			} else {
				 appendToPane(frame.expectedTextPane, ""+e, Color.BLACK);
				 appendToPane(frame.actualTextPane, ""+a, Color.BLACK);				
			}	
			acol++;
			ecol++;
			
		}
		
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}
	
	/**
	 * Create the frame.
	 */
	public CompareTextFrame() {
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 1128, 825);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));

		setContentPane(contentPane);
		contentPane.setLayout(new BorderLayout(0, 0));
		
		JScrollPane scrollPane = new JScrollPane();
		contentPane.add(scrollPane, BorderLayout.CENTER);
		
		JSplitPane splitPane = new JSplitPane();
		splitPane.setResizeWeight(0.5);
		scrollPane.setViewportView(splitPane);
		
		expectedTextPane = new JTextPane();
		splitPane.setLeftComponent(expectedTextPane);
		
		actualTextPane = new JTextPane();
		splitPane.setRightComponent(actualTextPane);
	}

	  private static void appendToPane(JTextPane tp, String msg, Color c){
	        StyleContext sc = StyleContext.getDefaultStyleContext();
	        AttributeSet aset = sc.addAttribute(SimpleAttributeSet.EMPTY, StyleConstants.Foreground, c);

	        aset = sc.addAttribute(aset, StyleConstants.FontFamily, "Lucida Console");
	        aset = sc.addAttribute(aset, StyleConstants.Alignment, StyleConstants.ALIGN_JUSTIFIED);

	        int len = tp.getDocument().getLength();
	        tp.setCaretPosition(len);
	        tp.setCharacterAttributes(aset, false);
	        tp.replaceSelection(msg);
	    }
}
