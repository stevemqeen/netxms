/**
 * NetXMS - open source network management system
 * Copyright (C) 2003-2013 Victor Kirhenshtein
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
package org.netxms.ui.eclipse.objectmanager.propertypages;

import java.util.HashMap;
import java.util.Set;
import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.swt.SWT;
import org.eclipse.swt.layout.FillLayout;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.ui.dialogs.PropertyPage;
import org.netxms.client.NXCObjectModificationData;
import org.netxms.client.NXCSession;
import org.netxms.client.objects.AbstractNode;
import org.netxms.client.objects.AbstractObject;
import org.netxms.ui.eclipse.jobs.ConsoleJob;
import org.netxms.ui.eclipse.objectbrowser.widgets.ObjectList;
import org.netxms.ui.eclipse.objectmanager.Activator;
import org.netxms.ui.eclipse.objectmanager.Messages;
import org.netxms.ui.eclipse.shared.ConsoleSharedData;

/**
 *"Trusted nodes" property page for NetXMS objects
 */
public class TrustedNodes extends PropertyPage
{
	public static final int COLUMN_NAME = 0;
	
	private AbstractObject object = null;
	private ObjectList objList = null;
	private boolean isModified = false;

	/* (non-Javadoc)
	 * @see org.eclipse.jface.preference.PreferencePage#createContents(org.eclipse.swt.widgets.Composite)
	 */
	@Override
	protected Control createContents(Composite parent)
	{
		Composite dialogArea = new Composite(parent, SWT.NONE);
		
		object = (AbstractObject)getElement().getAdapter(AbstractObject.class); 
      dialogArea.setLayout(new FillLayout());   

      HashMap<Long, AbstractObject> trustedNodes = new HashMap<Long, AbstractObject>(0);
      AbstractObject[] nodes = object.getTrustedNodes();
      for(int i = 0; i < nodes.length; i++)
      {
         if (nodes[i] != null)
            trustedNodes.put(nodes[i].getObjectId(), nodes[i]);
      }
      
      objList = new ObjectList(dialogArea, SWT.NONE, Messages.get().TrustedNodes_Node, trustedNodes, AbstractNode.class, new Runnable() {
         
         @Override
         public void run()
         {
            isModified = true;
         }
      });
      
		return dialogArea;
	}
	
	/**
	 * Apply changes
	 * 
	 * @param isApply true if update operation caused by "Apply" button
	 */
	protected void applyChanges(final boolean isApply)
	{
		if (!isModified)
			return;		// Nothing to apply
		
		if (isApply)
			setValid(false);
		
		final NXCSession session = (NXCSession)ConsoleSharedData.getSession();
		final NXCObjectModificationData md = new NXCObjectModificationData(object.getObjectId());
		Set<Long> idList = objList.getObjects().keySet();
		long[] nodes = new long[idList.size()];
		int i = 0;
		for(long id : idList)
			nodes[i++] = id;
		md.setTrustedNodes(nodes);
		
		new ConsoleJob(String.format(Messages.get().TrustedNodes_JobName, object.getObjectName()), null, Activator.PLUGIN_ID, null) {
			@Override
			protected void runInternal(IProgressMonitor monitor) throws Exception
			{
				session.modifyObject(md);
			}

			@Override
			protected void jobFinalize()
			{
				if (isApply)
				{
					runInUIThread(new Runnable() {
						@Override
						public void run()
						{
							TrustedNodes.this.setValid(true);
						}
					});
				}
			}

			@Override
			protected String getErrorMessage()
			{
				return Messages.get().TrustedNodes_JobError;
			}
		}.schedule();
	}

	/* (non-Javadoc)
	 * @see org.eclipse.jface.preference.PreferencePage#performApply()
	 */
	@Override
	protected void performApply()
	{
		applyChanges(true);
	}

	/* (non-Javadoc)
	 * @see org.eclipse.jface.preference.PreferencePage#performOk()
	 */
	@Override
	public boolean performOk()
	{
		applyChanges(false);
		return true;
	}

	/* (non-Javadoc)
	 * @see org.eclipse.jface.preference.PreferencePage#performDefaults()
	 */
	@Override
	protected void performDefaults()
	{
		objList.performDefaults();
		isModified = true;
		super.performDefaults();
	}
}
