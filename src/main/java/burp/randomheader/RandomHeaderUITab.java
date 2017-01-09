package burp.randomheader;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.InputStream;
import java.net.URL;
import java.util.Random;

import javax.imageio.ImageIO;
import javax.swing.*;

import burp.*;
import burp.randomheader.RandomHeader.RandomHeaderType;

import java.awt.event.*;

public class RandomHeaderUITab implements ITab, IRandomHeaderDialogHandler, ActionListener
{
	private BurpExtender extension;
	private RandomHeaderListComponent list;
	private JPanel contentPane;
	private JPanel gridBagPanel;
	
	private JButton addButton;
	private JButton editButton;
	private JButton removeButton;
	
	private JCheckBox isEnabled;
	private JCheckBox stayInScope;
	
	private int targetRow;
	
	private RandomHeaderUITab
	outer ()
	{
		return this;
	}
	
	/* Interface methods */
	public JFrame
	getContainerWindow ()
	{
		return (JFrame) SwingUtilities.getWindowAncestor (this.contentPane);
	}
	
	public java.util.List <RandomHeader>
	getRandomHeaderList ()
	{
		return list.getRandomHeaderList ();
	}
	
	public void
	setTargetRow (int id)
	{
		this.targetRow = id;
	}
	
	private GridBagConstraints
	placeAt (int x, int y)
	{
		GridBagConstraints c = new GridBagConstraints ();
		
		c.fill = GridBagConstraints.HORIZONTAL;
		c.gridx = x;
		c.gridy = y;
		c.anchor = GridBagConstraints.NORTHWEST;
		
		return c;
	}
	
	private GridBagConstraints
	placeAt (int x, int y, int colspan)
	{
		GridBagConstraints c = placeAt (x, y);
		
		c.gridwidth = colspan;
		
		return c;
	}
	
	private JPanel
	createAddEditRemovePanel ()
	{
		JPanel panel = new JPanel (new GridBagLayout ());
		
		panel.add (this.addButton = new JButton ("Add"), placeAt (0, 0));
		
		this.addButton.addActionListener
		(
				new java.awt.event.ActionListener() 
				{
					public void actionPerformed(java.awt.event.ActionEvent evt)
					{
						try
						{
							setTargetRow (-1);
							
							RandomHeaderDialog dialog = new RandomHeaderDialog (outer (), true);
							dialog.setVisible (true);
						}
						catch (Exception e)
						{
							System.out.println (e.toString ());
						};
					}
				}
		);
		
		panel.add (this.editButton = new JButton ("Edit"), placeAt (0, 1));
		this.editButton.addActionListener
		(
				new java.awt.event.ActionListener() 
				{
					public void actionPerformed(java.awt.event.ActionEvent evt)
					{
						try
						{
							int targetRow;
							
							if ((targetRow = list.getSelectedHeaderIndex ()) != -1)
							{
								setTargetRow (targetRow);
								
								RandomHeaderDialog dialog = new RandomHeaderDialog (outer (), false);
								dialog.setVisible (true);
							}
						}
						catch (Exception e)
						{
							System.out.println (e.toString ());
						};
					}
				}
		);
		
		panel.add (this.removeButton = new JButton ("Remove"), placeAt (0, 2));
		this.removeButton.addActionListener
		(
				new java.awt.event.ActionListener() 
				{
					public void actionPerformed(java.awt.event.ActionEvent evt)
					{
						try
						{
							int [] targetRows;
							
							if ((targetRows = list.getSelectedHeaderIndexes ()).length > 0)
								list.removeRandomHeaders (targetRows);
						}
						catch (Exception e)
						{
							System.out.println (e.toString ());
						};
					}
				}
		);
		
		return panel;
	}
	
	private JPanel
	copyrightLine ()
	{
		JPanel p = new JPanel (new FlowLayout (FlowLayout.LEFT, 0, 0));
		p.add (new TarlogicLogo ("Random Header extension by Gonzalo J. Carracedo - (c) 2013 Tarlogic Security"));
		
		return p;
	}
	
	public boolean
	extensionEnabled ()
	{
		return this.isEnabled.isSelected ();
	}
	
	public boolean
	inScope ()
	{
		return this.stayInScope.isSelected ();
	}
	
	private void
	updateComponentStates ()
	{
		this.addButton.setEnabled (extensionEnabled ());
		this.editButton.setEnabled (extensionEnabled ());
		this.removeButton.setEnabled (extensionEnabled ());
		this.stayInScope.setEnabled (extensionEnabled ());
		this.list.getUiComponent().setEnabled (extensionEnabled ());
	}
	
	public
	RandomHeaderUITab (BurpExtender extender)
	{
		this.contentPane = new JPanel (new FlowLayout (FlowLayout.LEFT, 0, 0));
		
		this.gridBagPanel = new JPanel (new GridBagLayout ()); 
	
		this.list = new RandomHeaderListComponent (extender);
		
		this.gridBagPanel.add (this.isEnabled = new JCheckBox ("Enable Random Header"), placeAt (0, 0, 2));
		
		this.gridBagPanel.add (this.stayInScope = new JCheckBox ("Apply to in-scope requests only"), placeAt (0, 1, 2));
		
		this.stayInScope.setSelected (true);
		
		this.isEnabled.addActionListener (this);
		
		this.gridBagPanel.add (createAddEditRemovePanel (), placeAt (0, 2));
		
		this.gridBagPanel.add (this.list.getUiComponent (), placeAt (1, 2));
		
		this.gridBagPanel.add (copyrightLine (), placeAt (0, 3, 2));
		
		this.contentPane.setBorder (BorderFactory.createEmptyBorder (10, 10, 10, 10));
		
		this.contentPane.add (this.gridBagPanel);
		
		this.extension = extender;
		
		updateComponentStates ();
	}
	
	@Override
	public String getTabCaption() 
	{
		return "Random Header";
	}

	@Override
	public Component
	getUiComponent() 
	{
		return this.contentPane;
	}

	public void
	okAction (String headerName, RandomHeader.RandomHeaderType type, String [] values) throws Exception
	{
		RandomHeader newHeader = new RandomHeader (headerName, type);
		
		switch (type)
		{
		case RANDOM_IPV4:
			newHeader.setIPv4NetAddr (values[0]);
			break;
			
		case RANDOM_IPV6:
			newHeader.setIPv6NetAddr (values[0]);
			break;
			
		case FIXED_LIST:
			newHeader.addFixed (values);
		}
		
		if (targetRow != -1)
			this.list.setRandomHeader(targetRow, newHeader);
		else
			this.list.addRandomHeader (newHeader);
		
	}
	
	public RandomHeader
	getCurrentRandomHeader ()
	{
		return list.getSelectedHeader ();
	}
	
	public void
	cancelAction ()
	{
		/* Nothing */
	}

	@Override
	public void actionPerformed (ActionEvent e)
	{
		updateComponentStates ();
	}
}
