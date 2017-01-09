package burp.randomheader;

import burp.*;
import burp.randomheader.*;

public class HttpListener implements IHttpListener 
{
	private BurpExtender extension;
	RandomHeader header;
	
	public
	HttpListener (BurpExtender extension)
	{
		this.extension = extension;
	}
	
	@Override 
	public void 
	processHttpMessage (int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
	{
		if (extension.isEnabled ())
		{
			if (messageIsRequest && 
					(!extension.stayInScope () || (extension.stayInScope () && extension.inScope (messageInfo.getUrl ()))))
			{
				java.util.List <RandomHeader> headerList = this.extension.getRandomHeaderList ();
				
				HttpRequestTweaker tweaker = new HttpRequestTweaker (this.extension, messageInfo);
			
				for (int i = 0; i < headerList.size (); ++i)
					tweaker.setHeader (headerList.get(i).getHeaderName (), headerList.get(i).generate ());
			
				tweaker.compose ();
			}
		}
	}
}
