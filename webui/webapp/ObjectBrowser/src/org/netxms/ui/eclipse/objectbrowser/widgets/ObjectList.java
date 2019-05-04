package org.netxms.ui.eclipse.objectbrowser.widgets;

import java.util.HashMap;
import java.util.Iterator;
import org.eclipse.jface.viewers.ArrayContentProvider;
import org.eclipse.jface.viewers.ILabelProvider;
import org.eclipse.jface.viewers.IStructuredSelection;
import org.eclipse.jface.window.Window;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.events.SelectionListener;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.layout.RowData;
import org.eclipse.swt.layout.RowLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.ui.model.WorkbenchLabelProvider;
import org.netxms.client.objects.AbstractObject;
import org.netxms.ui.eclipse.objectbrowser.Messages;
import org.netxms.ui.eclipse.objectbrowser.dialogs.ObjectSelectionDialog;
import org.netxms.ui.eclipse.tools.ObjectLabelComparator;
import org.netxms.ui.eclipse.tools.WidgetHelper;
import org.netxms.ui.eclipse.widgets.SortableTableViewer;

public class ObjectList extends Composite
{      
   private SortableTableViewer viewer;
   private HashMap<Long, AbstractObject> nodeMap;
   private Button addButton;
   private Button deleteButton;

   public ObjectList(Composite parent, int style, String columnName, HashMap<Long, AbstractObject> objects, final Class<? extends AbstractObject> classFilter, final Runnable callback)
   {
      super(parent, style);
      nodeMap = objects;
      
      GridLayout layout = new GridLayout();
      layout.verticalSpacing = WidgetHelper.OUTER_SPACING;
      layout.marginWidth = 0;
      layout.marginHeight = 0;
      setLayout(layout);
      
      final String[] columnNames = { columnName };
      final int[] columnWidths = { 300 };
      viewer = new SortableTableViewer(this, columnNames, columnWidths, 0, SWT.UP,
                                       SWT.BORDER | SWT.MULTI | SWT.FULL_SELECTION);
      viewer.setContentProvider(new ArrayContentProvider());
      viewer.setLabelProvider(new WorkbenchLabelProvider());
      viewer.setComparator(new ObjectLabelComparator((ILabelProvider)viewer.getLabelProvider()));
      viewer.setInput(objects.values().toArray());
      
      GridData gridData = new GridData();
      gridData.verticalAlignment = GridData.FILL;
      gridData.grabExcessVerticalSpace = true;
      gridData.horizontalAlignment = GridData.FILL;
      gridData.grabExcessHorizontalSpace = true;
      gridData.heightHint = 0;
      viewer.getControl().setLayoutData(gridData);
      
      Composite buttons = new Composite(this, SWT.NONE);
      RowLayout buttonLayout = new RowLayout();
      buttonLayout.type = SWT.HORIZONTAL;
      buttonLayout.pack = false;
      buttonLayout.marginWidth = 0;
      buttons.setLayout(buttonLayout);
      gridData = new GridData();
      gridData.horizontalAlignment = SWT.RIGHT;
      buttons.setLayoutData(gridData);

      addButton = new Button(buttons, SWT.PUSH);
      addButton.setText(Messages.get().ObjectList_Add);
      addButton.addSelectionListener(new SelectionListener() {
         @Override
         public void widgetDefaultSelected(SelectionEvent e)
         {
            widgetSelected(e);
         }

         @Override
         public void widgetSelected(SelectionEvent e)
         {
            ObjectSelectionDialog dlg = new ObjectSelectionDialog(getShell(), null, ObjectSelectionDialog.createNodeSelectionFilter(true));
            if (dlg.open() == Window.OK)
            {
               AbstractObject[] nodes = dlg.getSelectedObjects(classFilter);
               for(int i = 0; i < nodes.length; i++)
                  nodeMap.put(nodes[i].getObjectId(), nodes[i]);
               viewer.setInput(nodeMap.values().toArray());
               if (callback != null)
                  callback.run();
            }
         }
      });
      RowData rd = new RowData();
      rd.width = WidgetHelper.BUTTON_WIDTH_HINT;
      addButton.setLayoutData(rd);
      
      deleteButton = new Button(buttons, SWT.PUSH);
      deleteButton.setText(Messages.get().ObjectList_Delete);
      deleteButton.addSelectionListener(new SelectionListener() {
         @Override
         public void widgetDefaultSelected(SelectionEvent e)
         {
            widgetSelected(e);
         }

         @SuppressWarnings("unchecked")
         @Override
         public void widgetSelected(SelectionEvent e)
         {
            IStructuredSelection selection = (IStructuredSelection)viewer.getSelection();
            Iterator<AbstractObject> it = selection.iterator();
            if (it.hasNext())
            {
               while(it.hasNext())
               {
                  AbstractObject object = it.next();
                  nodeMap.remove(object.getObjectId());
               }
               viewer.setInput(nodeMap.values().toArray());
               if (callback != null)
                  callback.run();
            }
         }
      });
      rd = new RowData();
      rd.width = WidgetHelper.BUTTON_WIDTH_HINT;
      deleteButton.setLayoutData(rd);      
   }
   
   public void performDefaults()
   {
      nodeMap.clear();
      viewer.setInput(new AbstractObject[0]);
   }

   public HashMap<Long, AbstractObject> getObjects()
   {
      return nodeMap;
   }
}
