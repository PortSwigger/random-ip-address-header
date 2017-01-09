package burp.randomheader;

import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.URL;

import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.border.Border;

import burp.CustomTools;

public class RandomHeaderDialog extends JDialog implements ActionListener
{
	private IRandomHeaderDialogHandler handler;
	
	enum RandomHeaderDialogType
	{
		RANDOM_IPV4,
		RANDOM_IPV6,
		FILE,
		FIXED
	}

	private RandomHeaderDialogType type = RandomHeaderDialogType.RANDOM_IPV4;
	private File selectedFile;
	private String [] values; /* To be processed by RandomHeader */
	
	
	/* Interface components */
	private JLabel nameLabel = new JLabel ("Header name");
	private JLabel typeLabel = new JLabel ("Type");
	private JLabel range4Label = new JLabel ("Range");
	private JLabel range6Label = new JLabel ("Range");
	private JButton okButton;
	private JButton cancelButton;
	private JButton fileChooserButton;
	
	private JTextField headerNameField = new JTextField (15);
	private JTextField range4Field = new JTextField (15);
	private JTextField range6Field = new JTextField (15);
	private JLabel activeFileLabel = new JLabel ("(no file)");
	private JTextField fixedTextField = new JTextField (20);
	
	private JRadioButton ipv4RadioButton  = new JRadioButton ("Random IPv4 address");
	private JRadioButton ipv6RadioButton  = new JRadioButton ("Random IPv6 address");
	private JRadioButton fileRadioButton  = new JRadioButton ("List file");
	private JRadioButton fixedRadioButton = new JRadioButton ("Fixed value");
	
	private ButtonGroup typeGroup = new ButtonGroup ();
	private ButtonGroup dialogGroup = new ButtonGroup ();
	
	private GridBagConstraints
	placeAt (int x, int y)
	{
		GridBagConstraints c = new GridBagConstraints ();
		
		c.fill = GridBagConstraints.HORIZONTAL;
		c.gridx = x;
		c.gridy = y;
		c.weightx = 0.5;
		c.weighty = 0.5;
		
		c.anchor = GridBagConstraints.NORTHWEST;
		
		return c;
	}
	
	private void
	updateComponentStates ()
	{
		range4Label.setEnabled (this.type == RandomHeaderDialogType.RANDOM_IPV4);
		range4Field.setEnabled (this.type == RandomHeaderDialogType.RANDOM_IPV4);
		
		range6Label.setEnabled (this.type == RandomHeaderDialogType.RANDOM_IPV6);
		range6Field.setEnabled (this.type == RandomHeaderDialogType.RANDOM_IPV6);
		
		activeFileLabel.setEnabled (this.type == RandomHeaderDialogType.FILE);
		fileChooserButton.setEnabled (this.type == RandomHeaderDialogType.FILE);
		
		fixedTextField.setEnabled (this.type == RandomHeaderDialogType.FIXED);
	}
	
	public String [] 
	loadListFile (File file) throws IOException
	{
        FileReader reader = new FileReader (file);
        BufferedReader bufferedReader = new BufferedReader (reader);
        
        java.util.List <String> lines = new java.util.ArrayList <String>();
        
        String line = null;
        
        while ((line = bufferedReader.readLine()) != null)
        	lines.add(line);

        bufferedReader.close();
        
        return lines.toArray (new String[lines.size()]);
    }
	
	private void
	collectValues () throws Exception
	{
		switch (this.type)
		{
		case RANDOM_IPV4:
			this.values = new String [] {range4Field.getText ()};
			break;
			
		case RANDOM_IPV6:
			this.values = new String [] {range6Field.getText ()};
			break;
			
		case FIXED:
			this.values = new String [] {fixedTextField.getText ()};
			break;
		
		case FILE:
			if (selectedFile == null)
				throw new Exception ("No list file selected");
			
			this.values = loadListFile (selectedFile);
			
			break;
		}
	}
	
	private JButton
	JIconButton (String caption, String imgUrl)
	{
		try
		{
			return new JButton (caption, CustomTools.loadIcon (imgUrl));
		}
		catch (Exception e)
		{
			return new JButton (caption);
		}
	}
	
	private String
	TypeToString (RandomHeaderDialogType type)
	{
		switch (type)
		{
		case RANDOM_IPV4:
			return "IPv4";
			
		case RANDOM_IPV6:
			return "IPv6";
			
		case FILE:
			return "File";
			
		case FIXED:
			return "Fixed";
		}
		
		return "Unknown";
	}
	
	private RandomHeaderDialogType
	StringToType (String type)
	{
		switch (type)
		{
		case "IPv4":
			return RandomHeaderDialogType.RANDOM_IPV4;
		
		case "IPv6":
			return RandomHeaderDialogType.RANDOM_IPV6;
			
		case "File":
			return RandomHeaderDialogType.FILE;
			
		case "Fixed":
			return RandomHeaderDialogType.FIXED;
			
		}
		
		return RandomHeaderDialogType.FIXED; /* TODO: throw exception and handle it */
	}
	
	private void
	switchTo (RandomHeaderDialogType type)
	{
		this.type = type;
		
		switch (type)
		{
		case RANDOM_IPV4:
			ipv4RadioButton.setSelected (true);
			break;
			
		case RANDOM_IPV6:
			ipv6RadioButton.setSelected (true);
			break;
			
		case FILE:
			fileRadioButton.setSelected (true);
			break;
			
		case FIXED:
			fixedRadioButton.setSelected (true);
			break;
		}
		
		updateComponentStates ();
	}
	
	private void
	fillDataFromHeader (RandomHeader header)
	{
		if (header == null)
			return;
		
		this.setTitle ("Edit " + header.getHeaderName ());
		
		this.headerNameField.setText (header.getHeaderName ());
		switch (header.getType ())
		{
		case RANDOM_IPV4:
			this.range4Field.setText (header.getValue ());
			switchTo (RandomHeaderDialogType.RANDOM_IPV4);
			break;
			
		case RANDOM_IPV6:
			this.range6Field.setText (header.getValue ());
			switchTo (RandomHeaderDialogType.RANDOM_IPV6);
			break;
			
		case FIXED_LIST:
			/* TODO: save file */
			java.util.List <String> valueList = header.getValueList ();
			
			if (valueList.size () == 1)
			{
				this.fixedTextField.setText (valueList.get(0));
				switchTo (RandomHeaderDialogType.FIXED);
			}
			else
				switchTo (RandomHeaderDialogType.FILE);
			
			break;
		}
	}
	
	private void
	fillDialog (boolean isNew)
	{
		this.fileChooserButton = JIconButton ("Browse...", "document-open-6.png");
		this.fileChooserButton.addActionListener (this);
		
		JPanel content = new JPanel (new GridBagLayout ());
	
		content.setBorder (BorderFactory.createEmptyBorder (10, 10, 10, 10));
		
		/* First row */
		JPanel row = new JPanel (new FlowLayout (FlowLayout.LEFT));
		content.add (row, placeAt (0, 0));
		{	
			row.add (this.nameLabel);
			row.add (this.headerNameField);
		}
		
		/* Second row */
		JPanel typeRow = new JPanel (new GridBagLayout ());
		content.add (typeRow, placeAt (0, 1));
		{
			typeRow.add (this.typeLabel, placeAt (0, 0));
			
			JPanel typeList = new JPanel (new GridBagLayout ());
			{
				typeList.add (this.ipv4RadioButton, placeAt (0, 0));
				JPanel ipv4Panel = new JPanel (new FlowLayout (FlowLayout.LEFT));
				{
					ipv4Panel.add (this.range4Label);
					ipv4Panel.add (this.range4Field);
				}
				
				typeList.add (ipv4Panel, placeAt (0, 1));
				
				typeList.add (this.ipv6RadioButton, placeAt (0, 2));
				JPanel ipv6Panel = new JPanel (new FlowLayout (FlowLayout.LEFT));
				{
					ipv6Panel.add (this.range6Label);
					ipv6Panel.add (this.range6Field);
				}
				
				typeList.add (ipv6Panel, placeAt (0, 3));
				
				typeList.add (this.fileRadioButton, placeAt (0, 4));
				
				JPanel filePanel = new JPanel (new FlowLayout (FlowLayout.LEFT));
				{
					filePanel.add (this.activeFileLabel);
					filePanel.add (this.fileChooserButton);
				}
				
				typeList.add (filePanel, placeAt (0, 5));
				
				typeList.add (this.fixedRadioButton, placeAt (0, 6));
				
				JPanel fixedPanel = new JPanel (new FlowLayout (FlowLayout.LEFT));
				{
					fixedPanel.add (this.fixedTextField);
				}
				
				typeList.add (fixedPanel, placeAt (0, 7));
			}
			
			typeRow.add (typeList, placeAt (0, 1));
			
			this.typeGroup.add (this.ipv4RadioButton);
			this.typeGroup.add (this.ipv6RadioButton);
			this.typeGroup.add (this.fileRadioButton);
			this.typeGroup.add (this.fixedRadioButton);
			
			this.ipv4RadioButton.setActionCommand (TypeToString (RandomHeaderDialogType.RANDOM_IPV4));
			this.ipv6RadioButton.setActionCommand (TypeToString (RandomHeaderDialogType.RANDOM_IPV6));
			this.fileRadioButton.setActionCommand (TypeToString (RandomHeaderDialogType.FILE));
			this.fixedRadioButton.setActionCommand (TypeToString (RandomHeaderDialogType.FIXED));
			
			this.ipv4RadioButton.addActionListener (this);
			this.ipv6RadioButton.addActionListener (this);
			this.fileRadioButton.addActionListener (this);
			this.fixedRadioButton.addActionListener (this);
			
			this.ipv4RadioButton.setSelected (true);
		}
		
		/* Third row, dialog buttons */
		JPanel dialogButtonsRow = new JPanel (new FlowLayout (FlowLayout.RIGHT));
		content.add (dialogButtonsRow, placeAt (0, 2));
		{
			okButton = JIconButton ("OK", "dialog-accept.png");
			cancelButton = JIconButton ("Cancel", "dialog-cancel-4.png");
			
			dialogButtonsRow.add (okButton);
			dialogButtonsRow.add (cancelButton);
			
			okButton.addActionListener (this);
			cancelButton.addActionListener (this);
			
			dialogGroup.add (okButton);
			dialogGroup.add (cancelButton);
		}
		
		this.getContentPane().add (content);
		
		if (!isNew)
			fillDataFromHeader (handler.getCurrentRandomHeader ());
		else
			this.setTitle ("Add new random header");
	}
	
	public RandomHeaderDialog (IRandomHeaderDialogHandler handler, boolean isNew)
	{
		super (handler.getContainerWindow ());
		
		this.setLocationRelativeTo (handler.getContainerWindow ());
		this.setModalityType (Dialog.ModalityType.APPLICATION_MODAL);
		this.setSize(new Dimension (300, 370));
		
		this.setResizable (false);
		
		
		this.handler = handler;
		
		fillDialog (isNew);
		updateComponentStates ();
	}
	
	private boolean
	eventIsFromTypeButtons (ActionEvent e)
	{
		return e.getSource () == ipv4RadioButton ||
			e.getSource () == ipv6RadioButton ||
			e.getSource () == fileRadioButton ||
			e.getSource () == fixedRadioButton;
	}
	
	RandomHeader.RandomHeaderType
	dialogTypeToHeaderType (RandomHeaderDialogType type)
	{
		switch (type)
		{
		case RANDOM_IPV4:
			return RandomHeader.RandomHeaderType.RANDOM_IPV4;
			
		case RANDOM_IPV6:
			return RandomHeader.RandomHeaderType.RANDOM_IPV4;
			
		case FILE:
		case FIXED:
			return RandomHeader.RandomHeaderType.FIXED_LIST;
		}
		
		/* This will never happen */
		return RandomHeader.RandomHeaderType.FIXED_LIST;
	}
	
	/* Callbacks go here */
	public void
	actionPerformed (ActionEvent e)
	{
		if (eventIsFromTypeButtons (e))
		{
			type = StringToType (e.getActionCommand ());
			
			updateComponentStates ();
		}
		else if (e.getSource () == this.fileChooserButton)
		{
			JFileChooser fc = new JFileChooser ();
			int retVal = fc.showOpenDialog (this);
			
			if (retVal == JFileChooser.APPROVE_OPTION)
			{
				this.selectedFile = fc.getSelectedFile ();
				this.activeFileLabel.setText(this.selectedFile.getName ());
			}
		}
		else if (e.getSource () == this.okButton)
		{
			try
			{
				collectValues ();
				handler.okAction (this.headerNameField.getText (), dialogTypeToHeaderType (type), values);
			}
			catch (Exception oke)
			{
				JOptionPane.showMessageDialog (this, "Cannot set header values: " + oke.toString (),
					    "Random Header", JOptionPane.ERROR_MESSAGE);
			}
			finally
			{
				this.dispose ();
			}
		}
		else if (e.getSource () == this.cancelButton)
		{
			this.dispose ();
		}
	}
}
