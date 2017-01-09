package burp.randomheader;

import burp.*;
import burp.randomheader.RandomHeader.RandomHeaderType;

import javax.swing.*;
import javax.swing.table.*;

import java.util.*;
import java.awt.*;
import java.awt.event.*;

public class RandomHeaderListComponent 
{
	private BurpExtender extension;
	private JTable table;
	private JScrollPane scrollPane;
	private java.util.List <RandomHeader> list = new ArrayList <RandomHeader> ();
	private RandomHeaderListTableModel tableModel;
	
	public java.util.List <RandomHeader>
	getRandomHeaderList ()
	{
		return list;
	}
	
	public int
	getSelectedHeaderIndex ()
	{
		return table.getSelectedRow ();
	}
	
	public int []
	getSelectedHeaderIndexes ()
	{
		return table.getSelectedRows ();
	}
	
	public RandomHeader
	getSelectedHeader ()
	{
		int selected;
		
		if ((selected = table.getSelectedRow ()) == -1)
			return null;
		
		return list.get(selected);
	}

	public void
	addRandomHeader (RandomHeader header)
	{
		this.list.add (header);
		
		tableModel.fireTableDataChanged ();
	}
	
	public void
	setRandomHeader (int index, RandomHeader header)
	{
		this.list.set(index, header);
		
		tableModel.fireTableDataChanged ();
	}
	
	public void
	removeRandomHeaders (int [] indexes)
	{
		int i;
		
		for (i = 0; i < indexes.length; ++i)
			this.list.remove (0);
		
		tableModel.fireTableDataChanged ();
	}
	
	private void
	addSampleHeaders ()
	{
		RandomHeader header;
		
		try
		{
			header = new RandomHeader ("X-Forwarded-For", RandomHeaderType.RANDOM_IPV4);
			header.setIPv4NetAddr ("10.0.0.0/8");
			addRandomHeader (header);
			
			header = new RandomHeader ("X-Forwarded", RandomHeaderType.RANDOM_IPV4);
			header.setIPv4NetAddr ("172.16.0.0/16");
			addRandomHeader (header);
			
			header = new RandomHeader ("Client-IP", RandomHeaderType.RANDOM_IPV4);
			header.setIPv4NetAddr ("192.168.0.0/24");
			addRandomHeader (header);
			
			header = new RandomHeader ("Cluster-Client-IP", RandomHeaderType.FIXED_LIST);
			header.addFixed("127.0.0.1");
			addRandomHeader (header);
			
			header = new RandomHeader ("True-Client-IP", RandomHeaderType.RANDOM_IPV6);
			header.setIPv6NetAddr ("2a02:f400::/29");
			addRandomHeader (header);
			
			
		}
		catch (Exception e)
		{
			/* kay */
		}
	}
	
	public
	RandomHeaderListComponent (BurpExtender extension)
	{
		this.extension = extension;
		
		this.table = new JTable (tableModel = new RandomHeaderListTableModel (this.list));
		this.table.setPreferredScrollableViewportSize (new Dimension(500, 140));
		this.scrollPane = new JScrollPane (this.table);
		
		addSampleHeaders ();
	}
	
	public Component
	getUiComponent ()
	{
		return this.scrollPane;
	}
}
