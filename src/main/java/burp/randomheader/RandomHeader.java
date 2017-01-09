package burp.randomheader;

import burp.*;
import java.util.*;
import java.net.*;

public class RandomHeader 
{
	public enum RandomHeaderType 
	{
		RANDOM_IPV4,
		RANDOM_IPV6,
		FIXED_LIST
	};
	
	private String headerName;
	private RandomHeaderType type;
	
	private List <String> fixedValues = new ArrayList <String> ();
	private int randomBits;
	private InetAddress netAddr;
	private Random prng;
	
	/* TODO: write more specific exceptions */
	private void
	expectType (RandomHeaderType type) throws Exception
	{
		if (type != this.type)
		{
			switch (type)
			{
			case RANDOM_IPV4:
				throw new Exception ("This method only works for random IPv4 addresses");
				
			case RANDOM_IPV6:
				throw new Exception ("This method only works for random IPv6 addresses");
				
			case FIXED_LIST:
				throw new Exception ("This method only works for a fixed list of IP addresses");
			}
		}
	}
	
	public void
	setHeaderName (String name) throws Exception
	{
		/* TODO: validate name */
		this.headerName = name;
	}
	
	public void
	setIPv4NetAddr (String name) throws Exception
	{
		expectType (RandomHeaderType.RANDOM_IPV4);
		
		String [] parts = name.split("/", 2);
		
		if (parts.length != 2)
			throw new Exception ("Malformed IPv4 range. IPv4 ranges follow CIDR notation (i.e. 192.168.0.1/24)");
		
		try
		{
			this.randomBits = 32 - Integer.parseInt (parts[1]);
			
			if (this.randomBits > 32 || this.randomBits < 0)
				throw new Exception ("Invalid number of subnet bits, they must lay in the [0, 32] bits range");
			
			/* TODO: there must be a safer (and faster) way to turn a String IP into a 
			 * InetAddress without performing a nameserver lookup. */
			
			this.netAddr = Inet4Address.getByName (parts[0]);
		}
		catch (NumberFormatException e)
		{
			throw new Exception ("Invalid number of subnet bits");
		}
		catch (UnknownHostException e)
		{
			throw new Exception (parts[1] + ": cannot solve to a IPv4 Address");
		}
	}
	
	public void
	setIPv6NetAddr (String name) throws Exception
	{
		expectType (RandomHeaderType.RANDOM_IPV6);
		
		String [] parts = name.split("/", 2);
		
		if (parts.length != 2)
			throw new Exception ("Malformed IPv6 range. IPv6 ranges follow CIDR notation (i.e. 2001:db8::/48)");
		
		try
		{
			this.randomBits = 128 - Integer.parseInt (parts[1]);
			
			if (this.randomBits > 128 || this.randomBits < 0)
				throw new Exception ("Invalid number of subnet bits, they must lay in the [0, 128] bits range");
			
			/* TODO: there must be a safer (and faster) way to turn a String IP into a 
			 * InetAddress without performing a nameserver lookup. */
			
			this.netAddr = Inet6Address.getByName (parts[0]);
		}
		catch (NumberFormatException e)
		{
			throw new Exception ("Invalid number of subnet bits");
		}
		catch (UnknownHostException e)
		{
			throw new Exception (parts[1] + ": cannot solve to a IPv6 Address");
		}
	}
	
	public
	RandomHeader (String name, RandomHeaderType type) throws Exception
	{
		this.prng = new Random ();
		this.headerName = name;
		this.type = type;
	}
	
	public void
	addFixed (String name) throws Exception
	{
		expectType (RandomHeaderType.FIXED_LIST);
		
		this.fixedValues.add (name);
	}
	
	public void
	addFixed (String [] values) throws Exception
	{
		expectType (RandomHeaderType.FIXED_LIST);
		
		this.fixedValues.addAll (Arrays.asList (values));
	}
	
	
	public void
	clearFixed () throws Exception
	{
		expectType (RandomHeaderType.FIXED_LIST);
		
		this.fixedValues.clear ();
	}
	
	private int
	containingBytes (int bits)
	{
		return (bits >> 3) + ((bits & 0x7) != 0 ? 1 : 0);
	}
	
	private byte []
	generateRandomBits (int bits)
	{
		byte [] result = new byte[containingBytes (bits)];
		
		prng.nextBytes(result);
		
		if ((bits & 0x7) != 0)
			result[result.length - 1] &= (1 << (bits & 0x7)) - 1; 
		return result;
	}
	
	private byte []
	generateRandomAddress (InetAddress netAddr, int randomBits)
	{
		byte [] rand = generateRandomBits (randomBits);
		byte [] net  = netAddr.getAddress ();
		
		int i;
		int remainderBits = randomBits & 0x7;
		byte netMask = (byte) ~((1 << remainderBits) - 1);
		
		int fullBytes = randomBits >> 3;
			
		for (i = 0; i < fullBytes; ++i)
			net[net.length - 1 - i] = rand[i];

		if (fullBytes < rand.length)
		{
			net[net.length - 1 - fullBytes] &= netMask;
			net[net.length - 1 - fullBytes] |= rand[fullBytes];
		}
		
		return net;
	}
	
	private String
	byteArrayToIPv4 (byte [] array)
	{
		return (0xff & (int) array[0]) + "." + (0xff & (int) array[1]) + "." + (0xff & (int) array[2]) + "." + (0xff & (int) array[3]);
	}
	
	private String
	byteArrayToIPv6 (byte [] array)
	{
		String result = "";
		String group;
		int i;
		
		for (i = 0; i < 16; i += 2)
		{
			if (i > 0)
				result += ":";
			
			/* There must be a cleaner way to pad hexadecimal numbers with zeros */
			group = Integer.toHexString (0xff & (int) array[i + 1]);
			
			if (group.length () < 2)
				group = "0" + group;
			
			group = Integer.toHexString(0xff & (int) array[i]) + group;
			
			if (group.length () < 4)
				group = "0" + group;
			
			result += group;
		}
		
		return result;
	}
	
	public String
	generate ()
	{
		String result;
		
		switch (this.type)
		{
		case RANDOM_IPV4:
			result = byteArrayToIPv4 (generateRandomAddress (this.netAddr, this.randomBits));
			break;
			
		case RANDOM_IPV6:
			result = byteArrayToIPv6 (generateRandomAddress (this.netAddr, this.randomBits));
			break;
			
		case FIXED_LIST:
			result = fixedValues.size () > 0 ? 
					this.fixedValues.get (prng.nextInt (this.fixedValues.size ())) :
					"<empty list>";
			break;
			
		default:
			result = "Pigs fly"; /* Thank you Eclipse, thank you Java, thank you. */
		}
		
		return result;
	}
	
	public RandomHeaderType
	getType ()
	{
		return this.type;
	}
	
	public String
	getTypeString ()
	{
		String result;
		
		switch (this.type)
		{
		case RANDOM_IPV4:
			result = "Random IPv4";
			break;
			
		case RANDOM_IPV6:
			result = "Random IPv6";
			break;
			
		case FIXED_LIST:
			result = "Fixed" + (fixedValues.size () > 1 ? " list of IPs" :  "");
			break;
			
		default:
			result = "DINOSAURS"; /* Will never reach this point */
		}
		
		return result;
	}
	
	public String
	getHeaderName ()
	{
		return this.headerName;
	}
	
	public List <String>
	getValueList ()
	{
		return this.fixedValues;
	}
	
	public String
	getValue ()
	{
		String result;
		
		switch (this.type)
		{
		case RANDOM_IPV4:
		case RANDOM_IPV6:
			result = this.netAddr.getHostAddress () + "/" + (this.type == RandomHeaderType.RANDOM_IPV4 ? 32 - randomBits : 128 - randomBits);
			break;
			
		case FIXED_LIST:
			result = "";
			
			for (int i = 0; i < Math.min (this.fixedValues.size (), 3); ++i)
				result += (i > 0 ? ", " : "") + "\"" + this.fixedValues.get(i) + "\"";
			
			if (this.fixedValues.size () > 3)
				result += "...";
			break;
			
		default:
			result = "NINJAS"; /* Not here either */
		}
		
		return result;
	}
}
