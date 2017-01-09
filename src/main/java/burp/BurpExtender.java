package burp;

import burp.*;
import burp.randomheader.*;

import java.io.*;
import java.net.URL;

public class BurpExtender implements IBurpExtender
{
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;

	private RandomHeaderUITab tab;
	
	public IExtensionHelpers
	getExtensionHelpers ()
	{
		return helpers;
	}
	
	public java.util.List
	getRandomHeaderList ()
	{
		return tab.getRandomHeaderList ();
	}
	
	public boolean
	isEnabled ()
	{
		return tab.extensionEnabled ();
	}
	
	public boolean
	stayInScope ()
	{
		return tab.inScope ();
	}
	
	public boolean
	inScope (URL url)
	{
		return callbacks.isInScope (url);
	}
	
	@Override 
	public void
	registerExtenderCallbacks (IBurpExtenderCallbacks callbacks)
	{
		this.callbacks = callbacks;
		this.helpers = callbacks.getHelpers ();
		this.callbacks.setExtensionName ("Random Header");
	
		/* Connect HTTP listener */
		callbacks.addSuiteTab(this.tab = new RandomHeaderUITab (this));
		callbacks.registerHttpListener (new HttpListener (this));
	}
}

