package us.bringardner.net.dns;

import org.junit.jupiter.api.Test;

public class TestMessage {


	@Test()
	public void testTxt() {
		String t1 = "FF2FB217CD5C301313BB23957548E499.2BAC0F66790EAD4ED837ECA1593EBEB6.69593e138115b.comodoca.com";
		String t2 = "FF2FB217CD5C301313BB23957548E499.2BAC0F66790EAD4ED837ECA1593EBEB6.69593e138115b.comodoca.com";

		String name = "default._domainkey";
		String value= "v=DKIM1;k=rsa;p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxyraI6JqtClShfNf/WAg6HZYbt5ESCoRqvGPH2fu0OEEp9eWvwnj9ywq9Y6KNPiCTsCnNJymo0WjTYhQvc3A9sKnHFBGp84XBMJb67GOhm8DiDEpc2oZ5UYv2uwCbBAbaWX3wJ4+7bR1PjS7bS01GqUfjMfJN+dnJIYOLAbatsDdErI5MNMY06eLEH3oSrbv+jdPKSSSiAzBzPnpQIUCMKrv1dR4Nsg1RilEVTad5SpAMjxMvN8aN0OoxmNdkjFMv2qER8gQWNArKAf9sqBz18orE58zQq8kDcF4nS0tslBUZbeuuzQUatF+PgeyQ6wYIiQOzvtg1eyuH0elJrZG4wIDAQAB;";
		String wire=  "v=DKIM1;k=rsa;p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxyraI6JqtClShfNf/WAg6HZYbt5ESCoRqvGPH2fu0OEEp9eWvwnj9ywq9Y6KNPiCTsCnNJymo0WjTYhQvc3A9sKnHFBGp84XBMJb67GOhm8DiDEpc2oZ5UYv2uwCbBAbaWX3wJ4+7bR1PjS7bS01GqUfjMfJN+dnJIYOLAbatsDdErI5MNMY06eLEH3oSrbv+jdPKSSSiAzBzPnpQIUCMKrv1dR4Nsg1RilEVTad5SpAMjxMvN8aN0OoxmNdkjFMv2qER8gQWNArKAf9sqBz18orE58zQq8kDcF4nS0tslBUZbeuuzQUatF+PgeyQ6wYIiQOzvtg1eyuH0elJrZG4wIDAQAB;";
		int nameLen = name.length();
		int valLen=value.length();
		int tot = nameLen+valLen;


		Message msg = new Message();
		msg.addQuestion(name,Message.TXT,DNS.IN);

		Txt txt = new Txt(name);
		txt.setText(value);


		int len1 = txt.rdlength;
		int len2 = txt.rdata.length;
		show(txt.rdata);

		msg.addAnswer(txt);

		String str = msg.toString();
		byte [] data = msg.toByteArray();
		show(data);
		int sz = data.length;
		System.out.println("sz="+sz+" tot="+tot);
		Message msg2 = new Message(new ByteBuffer(data));

		String str2 = msg.toString();
		System.out.println(str.equals(str2));
	}

	private void show(byte[] data) {
		StringBuilder buf = new StringBuilder();

		for (int idx = 0; idx < data.length; idx++) {
			if( idx %16==0) {
				buf.append('\n');
			} else if( idx %8==0) {
				buf.append(' ');
			}
			byte val = data[idx];

			String t = Integer.toHexString(val);
			if( t.length()>2) {
				t = t.substring(t.length()-2);
			}

			if( t.length()<2) {
				buf.append('0');
			} 
			buf.append(t);
			buf.append(' ');
		}

		System.out.println(buf);


	}
}
