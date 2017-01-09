package burp.randomheader;

import javax.swing.*;

public interface IRandomHeaderDialogHandler 
{
	public JFrame getContainerWindow ();
	public void okAction (String headerName, RandomHeader.RandomHeaderType type, String [] values) throws Exception;
	public void cancelAction ();
	public RandomHeader getCurrentRandomHeader ();
}
