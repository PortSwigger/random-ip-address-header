package burp.randomheader;

import burp.*;

import java.util.*;

public class HttpRequestTweaker 
{
	private byte [] contents;
	private List <String> headers;
	private IExtensionHelpers helpers;
	private IHttpRequestResponse currentRequest;
	
	public
	HttpRequestTweaker (BurpExtender extension, IHttpRequestResponse messageInfo)
	{
		IRequestInfo rqInfo;
		byte [] fullReq;
		
		this.helpers = extension.getExtensionHelpers ();
		
		rqInfo = helpers.analyzeRequest (messageInfo);
		this.headers  = rqInfo.getHeaders ();
		
		fullReq = messageInfo.getRequest ();
		
		this.contents = Arrays.copyOfRange(fullReq, rqInfo.getBodyOffset (),fullReq.length);
		this.currentRequest = messageInfo;
	}
	
	public int
	indexOfHeader (String name)
	{
		for (int i = 0; i < this.headers.size (); ++i)
			if (this.headers.get (i).startsWith (name + ": "))
				return i;
		
		return -1;
	}
	
	public boolean
	hasHeader (String name)
	{
		return indexOfHeader (name) != -1;
	}
	
	public void
	setHeader (String name, String value)
	{
		int i;
		String fullHeader = name + ": " + value;
		
		if ((i = indexOfHeader (name)) != -1)
			this.headers.set (i, fullHeader);
		else
			this.headers.add (fullHeader);
	}
	
	public void
	compose ()
	{
		this.currentRequest.setRequest (this.helpers.buildHttpMessage (this.headers, this.contents));
	}
}
