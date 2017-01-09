package burp.randomheader;

import java.util.*;

import javax.swing.*;
import javax.swing.table.*;

public class RandomHeaderListTableModel extends AbstractTableModel 
{
	private final List <RandomHeader> headerList;
	private final String [] columnNames = {"Id", "Header name", "Type", "Value"};
	
	public String
	getColumnName (int col)
	{
		return columnNames[col];
	}
	
	public
	RandomHeaderListTableModel (List <RandomHeader> list)
	{
		this.headerList = list;
	}
	
	@Override
	public int
	getColumnCount () 
	{
		return 4;
	}

	@Override
	public int
	getRowCount () 
	{
		if (headerList == null)
			return 0;
		
		return headerList.size ();
	}

	@Override
	public Object
	getValueAt (int row, int col) 
	{
		switch (col)
		{
		case 0:
			return row + 1;
			
		case 1:
			return headerList.get(row).getHeaderName ();
			
		case 2:
			return headerList.get(row).getTypeString ();
			
		case 3:
			return headerList.get(row).getValue ();
		}
		
		return null;
	}
}
