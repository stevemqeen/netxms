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
package org.netxms.ui.eclipse.console.resources;

import java.util.HashMap;
import java.util.Map;
import org.eclipse.swt.SWT;
import org.eclipse.swt.graphics.Color;
import org.eclipse.swt.graphics.RGB;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Event;
import org.eclipse.swt.widgets.Listener;
import org.netxms.ui.eclipse.console.ColorManager;
import org.netxms.ui.eclipse.tools.ColorCache;

/**
 * Shared colors
 */
public class SharedColors
{
	public static final String BORDER = "Border"; 
	public static final String CGROUP_BORDER = "CGroup.Border"; 
	public static final String CGROUP_TITLE = "CGroup.Title"; 
	public static final String DASHBOARD_BACKGROUND = "Dashboard.Background"; 
	public static final String DIAL_CHART_LEGEND = "DialChart.Legend"; 
	public static final String DIAL_CHART_NEEDLE = "DialChart.Needle";
	public static final String DIAL_CHART_NEEDLE_PIN = "DialChart.NeedlePin";
	public static final String DIAL_CHART_SCALE = "DialChart.Scale"; 
	public static final String DIAL_CHART_VALUE = "DialChart.Value"; 
	public static final String DIAL_CHART_VALUE_BACKGROUND = "DialChart.ValueBackground"; 
	public static final String ERROR_BACKGROUND = "ErrorBackground"; 
	public static final String GEOMAP_TITLE = "GeoMap.Title"; 
	public static final String MAP_GROUP_BOX_TITLE = "Map.GroupBox.Title"; 
	public static final String MIB_EXPLORER_HEADER_BACKGROUND = "MibExplorer.Header.Background"; 
	public static final String MIB_EXPLORER_HEADER_TEXT = "MibExplorer.Header.Text"; 
	public static final String OBJECT_TAB_BACKGROUND = "ObjectTab.Background"; 
	public static final String SERVICE_AVAILABILITY_LEGEND = "ServiceAvailability.Legend"; 
	public static final String TEXT_ERROR = "Text.Error"; 
	public static final String TEXT_NORMAL = "Text.Normal"; 
	
	/**
	 * Default color to be used when no named default found
	 */
	private static final RGB DEFAULT_COLOR = new RGB(0,0,0);
	
	private static final Map<Display, SharedColors> instances = new HashMap<Display, SharedColors>();
	private static final Map<String, RGB> defaultColors = new HashMap<String, RGB>();
	
	static
	{
		defaultColors.put(BORDER, new RGB(153, 180, 209));
		defaultColors.put(CGROUP_BORDER, new RGB(153, 180, 209));
		defaultColors.put(CGROUP_TITLE, new RGB(0, 0, 0));
		defaultColors.put(DASHBOARD_BACKGROUND, new RGB(255, 255, 255));
		defaultColors.put(DIAL_CHART_LEGEND, new RGB(0, 0, 0));
		defaultColors.put(DIAL_CHART_NEEDLE, new RGB(51, 78, 113));
		defaultColors.put(DIAL_CHART_NEEDLE_PIN, new RGB(239, 228, 176));
		defaultColors.put(DIAL_CHART_SCALE, new RGB(0, 0, 0));
		defaultColors.put(DIAL_CHART_VALUE, new RGB(255, 255, 255));
		defaultColors.put(DIAL_CHART_VALUE_BACKGROUND, new RGB(255, 255, 255));
		defaultColors.put(ERROR_BACKGROUND, new RGB(255, 0, 0));
		defaultColors.put(GEOMAP_TITLE, new RGB(0, 0, 0));
		defaultColors.put(MAP_GROUP_BOX_TITLE, new RGB(255, 255, 255));
		defaultColors.put(MIB_EXPLORER_HEADER_BACKGROUND, new RGB(153, 180, 209));
		defaultColors.put(MIB_EXPLORER_HEADER_TEXT, new RGB(255, 255, 255));
		defaultColors.put(OBJECT_TAB_BACKGROUND, new RGB(255, 255, 255));
		defaultColors.put(SERVICE_AVAILABILITY_LEGEND, new RGB(0, 0, 0));
		defaultColors.put(TEXT_ERROR, new RGB(255, 0, 0));
		defaultColors.put(TEXT_NORMAL, new RGB(0, 0, 0));
	}
	
	/**
	 * Get shared colors instance for given display
	 * 
	 * @param display
	 * @return
	 */
	private static SharedColors getInstance(Display display)
	{
		SharedColors instance;
		synchronized(instances)
		{
			instance = instances.get(display);
			if (instance == null)
			{
				instance = new SharedColors(display);
				instances.put(display, instance);
			}
		}
		return instance;
	}
	
	private ColorCache colors;
	
	/**
	 * @param display
	 */
	public SharedColors(final Display display)
	{
		colors = new ColorCache();
		display.addListener(SWT.Dispose, new Listener() {
			@Override
			public void handleEvent(Event event)
			{
				synchronized(instances)
				{
					instances.remove(display);
				}
				colors.dispose();
			}
		});
	}
	
	/**
	 * @param name
	 * @param defaultValue
	 * @param display
	 * @return
	 */
	public static Color getColor(String name, Display display)
	{
		RGB rgb = ColorManager.getInstance().getColor(name);
		if (rgb == null)
		{
			rgb = defaultColors.get(name);
			if (rgb == null)
				rgb = DEFAULT_COLOR;
		}
		return getInstance(display).colors.create(rgb);
	}
}
