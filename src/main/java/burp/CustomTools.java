package burp;

import java.awt.Image;
import java.awt.Toolkit;
import java.net.URL;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;

public class CustomTools 
{
	public static void 
	openURL (String url) 
	{
		String osName = System.getProperty ("os.name");
		try 
		{
			if (osName.startsWith ("Windows"))
				Runtime.getRuntime().exec ("rundll32 url.dll,FileProtocolHandler " + url);
			else 
			{ 
				String[] browsers = {"htmlview", "google-chrome", "firefox", "opera", "konqueror", "iceweasel", "epiphany", "mozilla", "netscape" };
				String browser = null;
				
				for (int count = 0; count < browsers.length && browser == null; count++)
					if (Runtime.getRuntime().exec (new String[] {"which", browsers[count]}).waitFor() == 0)
						browser = browsers[count];
		
				Runtime.getRuntime().exec(new String[] {browser, url});
			}
		}
		catch (Exception e) 
		{
			JOptionPane.showMessageDialog(null, "Error in opening browser" + ":\n" + e.getLocalizedMessage());
		}
	}
	
	public static ImageIcon
	loadIcon (String imgUrl) throws Exception
	{
		/* Dirty as hell, but ir works */
		Class currentClass = new Object() { }.getClass().getEnclosingClass();
		
		URL urlToImage = currentClass.getResource ("/" + imgUrl);
		Image icon = Toolkit.getDefaultToolkit().getImage(urlToImage);
		
		return new ImageIcon (icon);
	}
}
