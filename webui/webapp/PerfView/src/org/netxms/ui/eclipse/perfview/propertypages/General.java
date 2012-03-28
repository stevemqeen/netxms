/**
 * NetXMS - open source network management system
 * Copyright (C) 2003-2010 Victor Kirhenshtein
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
package org.netxms.ui.eclipse.perfview.propertypages;

import org.eclipse.swt.SWT;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.events.SelectionListener;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Group;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Scale;
import org.eclipse.swt.widgets.Spinner;
import org.eclipse.ui.dialogs.PropertyPage;
import org.netxms.client.datacollection.GraphSettings;
import org.netxms.ui.eclipse.tools.WidgetHelper;
import org.netxms.ui.eclipse.widgets.LabeledText;

/**
 * "General" property page for chart
 *
 */
public class General extends PropertyPage
{
	private static final long serialVersionUID = 1L;

	private GraphSettings settings;
	private LabeledText title;
	private Button checkShowGrid;
	private Button checkShowLegend;
	private Button checkAutoScale;
	private Button checkShowHostNames;
	private Button checkShowRuler;
	private Button checkEnableZoom;
	private Button checkAutoRefresh;
	private Button checkLogScale;
	private Scale refreshIntervalScale;
	private Spinner refreshIntervalSpinner;
	
	/* (non-Javadoc)
	 * @see org.eclipse.jface.preference.PreferencePage#createContents(org.eclipse.swt.widgets.Composite)
	 */
	@Override
	protected Control createContents(Composite parent)
	{
		settings = (GraphSettings)getElement().getAdapter(GraphSettings.class);
		
		Composite dialogArea = new Composite(parent, SWT.NONE);
		
		GridLayout layout = new GridLayout();
		layout.verticalSpacing = WidgetHelper.OUTER_SPACING;
		layout.marginWidth = 0;
		layout.marginHeight = 0;
      dialogArea.setLayout(layout);
      
      title = new LabeledText(dialogArea, SWT.NONE, SWT.BORDER);
      title.setLabel("Title");
      title.setText(settings.getTitle());
      GridData gd = new GridData();
      gd.horizontalAlignment = SWT.FILL;
      gd.grabExcessHorizontalSpace = true;
      title.setLayoutData(gd);
      
      Group optionsGroup = new Group(dialogArea, SWT.NONE);
      optionsGroup.setText("Options");
      layout = new GridLayout();
      layout.marginWidth = WidgetHelper.OUTER_SPACING;
      layout.marginHeight = WidgetHelper.OUTER_SPACING;
      layout.verticalSpacing = WidgetHelper.OUTER_SPACING;
      layout.makeColumnsEqualWidth = true;
      layout.numColumns = 2;
      optionsGroup.setLayout(layout);
      gd = new GridData();
      gd.horizontalAlignment = SWT.FILL;
      gd.grabExcessHorizontalSpace = true;
      optionsGroup.setLayoutData(gd);
      
      checkShowGrid = new Button(optionsGroup, SWT.CHECK);
      checkShowGrid.setText("Show &grid lines");
      checkShowGrid.setSelection(settings.isGridVisible());

      checkAutoScale = new Button(optionsGroup, SWT.CHECK);
      checkAutoScale.setText("&Autoscale");
      checkAutoScale.setSelection(settings.isAutoScale());

      checkShowLegend = new Button(optionsGroup, SWT.CHECK);
      checkShowLegend.setText("Show &legend");
      checkShowLegend.setSelection(settings.isLegendVisible());

      checkShowRuler = new Button(optionsGroup, SWT.CHECK);
      checkShowRuler.setText("Show &ruler");
      checkShowRuler.setSelection(false);

      checkShowHostNames = new Button(optionsGroup, SWT.CHECK);
      checkShowHostNames.setText("Show &host names");
      checkShowHostNames.setSelection(settings.isHostNamesVisible());

      checkEnableZoom = new Button(optionsGroup, SWT.CHECK);
      checkEnableZoom.setText("Enable &zoom");
      checkEnableZoom.setSelection(false);

      checkAutoRefresh = new Button(optionsGroup, SWT.CHECK);
      checkAutoRefresh.setText("&Refresh automatically");
      checkAutoRefresh.setSelection(settings.isAutoRefresh());

      checkLogScale = new Button(optionsGroup, SWT.CHECK);
      checkLogScale.setText("L&ogaritmic scale");
      checkLogScale.setSelection(settings.isLogScale());
      
      Composite refreshIntervalGroup = new Composite(optionsGroup, SWT.NONE);
      layout = new GridLayout();
      layout.numColumns = 2;
      layout.horizontalSpacing = WidgetHelper.OUTER_SPACING;
      layout.marginHeight = 0;
      layout.marginWidth = 0;
      layout.marginTop = WidgetHelper.OUTER_SPACING;
      refreshIntervalGroup.setLayout(layout);
      gd = new GridData();
      gd.horizontalAlignment = SWT.FILL;
      gd.grabExcessHorizontalSpace = true;
      gd.horizontalSpan = 2;
      refreshIntervalGroup.setLayoutData(gd);
      
      Label label = new Label(refreshIntervalGroup, SWT.NONE);
      label.setText("Refresh interval:");
      gd = new GridData();
      gd.horizontalAlignment = SWT.LEFT;
      gd.horizontalSpan = 2;
      label.setLayoutData(gd);
      
      refreshIntervalScale = new Scale(refreshIntervalGroup, SWT.HORIZONTAL);
      refreshIntervalScale.setMinimum(1);
      refreshIntervalScale.setMaximum(600);
      refreshIntervalScale.setSelection(settings.getAutoRefreshInterval() / 1000);
      gd = new GridData();
      gd.horizontalAlignment = SWT.FILL;
      gd.grabExcessHorizontalSpace = true;
      refreshIntervalScale.setLayoutData(gd);
      refreshIntervalScale.addSelectionListener(new SelectionListener() {
      	private static final long serialVersionUID = 1L;

			@Override
			public void widgetSelected(SelectionEvent e)
			{
				refreshIntervalSpinner.setSelection(refreshIntervalScale.getSelection());
			}

			@Override
			public void widgetDefaultSelected(SelectionEvent e)
			{
				widgetSelected(e);
			}
      });
      
      refreshIntervalSpinner = new Spinner(refreshIntervalGroup, SWT.BORDER);
      refreshIntervalSpinner.setMinimum(1);
      refreshIntervalSpinner.setMaximum(600);
      refreshIntervalSpinner.setSelection(settings.getAutoRefreshInterval() / 1000);
      refreshIntervalSpinner.addSelectionListener(new SelectionListener() {
      	private static final long serialVersionUID = 1L;

			@Override
			public void widgetSelected(SelectionEvent e)
			{
				refreshIntervalScale.setSelection(refreshIntervalSpinner.getSelection());
			}
			
			@Override
			public void widgetDefaultSelected(SelectionEvent e)
			{
				widgetSelected(e);
			}
		});

      return dialogArea;
	}

	/* (non-Javadoc)
	 * @see org.eclipse.jface.preference.PreferencePage#performDefaults()
	 */
	@Override
	protected void performDefaults()
	{
		super.performDefaults();
		
		title.setText("");
		checkShowGrid.setSelection(true);
		checkShowLegend.setSelection(true);
		checkAutoScale.setSelection(true);
		checkShowHostNames.setSelection(false);
		checkShowRuler.setSelection(false);
		checkEnableZoom.setSelection(true);
		checkAutoRefresh.setSelection(true);
		checkLogScale.setSelection(false);
		
		refreshIntervalScale.setSelection(30);
		refreshIntervalSpinner.setSelection(30);
	}

	/**
	 * Apply changes
	 * 
	 * @param isApply true if update operation caused by "Apply" button
	 */
	protected void applyChanges(final boolean isApply)
	{
		settings.setTitle(title.getText());
		settings.setGridVisible(checkShowGrid.getSelection());
		settings.setLegendVisible(checkShowLegend.getSelection());
		settings.setAutoScale(checkAutoScale.getSelection());
		settings.setHostNamesVisible(checkShowHostNames.getSelection());
		settings.setAutoRefresh(checkAutoRefresh.getSelection());
		settings.setLogScale(checkLogScale.getSelection());
		settings.setAutoRefreshInterval(refreshIntervalSpinner.getSelection() * 1000);
		
		settings.fireChangeNotification();
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
}
