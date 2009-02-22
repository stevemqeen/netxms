/**
 * 
 */
package org.netxms.ui.eclipse.alarmviewer.actions;

import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.core.runtime.IStatus;
import org.eclipse.core.runtime.Status;
import org.eclipse.core.runtime.jobs.Job;
import org.eclipse.jface.action.IAction;
import org.eclipse.jface.viewers.ISelection;
import org.eclipse.jface.viewers.IStructuredSelection;
import org.eclipse.ui.IObjectActionDelegate;
import org.eclipse.ui.IWorkbenchPart;
import org.eclipse.ui.progress.IWorkbenchSiteProgressService;
import org.netxms.client.NXCAlarm;
import org.netxms.client.NXCException;
import org.netxms.ui.eclipse.alarmviewer.Activator;
import org.netxms.ui.eclipse.alarmviewer.AlarmView;
import org.netxms.ui.eclipse.shared.NXMCSharedData;


/**
 * @author Victor
 *
 */
public class TerminateAlarm implements IObjectActionDelegate
{
	private class TerminateJob extends Job
	{
		private Object selection[];
		
		/**
		 * Constructor for alarm termination job.
		 * @param selection Currently selected alarms in alarm list
		 */
		TerminateJob(Object selection[])
		{
			super("Terminate alarms");
			setUser(true);
			this.selection = selection;
		}

		@Override
		protected IStatus run(IProgressMonitor monitor)
		{
			IStatus status;
			
			try
			{
				for(int i = 0; i < selection.length; i++)
					if (selection[i] instanceof NXCAlarm)
						NXMCSharedData.getInstance().getSession().terminateAlarm(((NXCAlarm)selection[i]).getId());
				status = Status.OK_STATUS;
			}
			catch(Exception e)
			{
				status = new Status(Status.ERROR, Activator.PLUGIN_ID, 
				                    (e instanceof NXCException) ? ((NXCException)e).getErrorCode() : 0,
				                    "Cannot terminate alarm: " + e.getMessage(), e);
			}
			return status;
		}

		/* (non-Javadoc)
		 * @see org.eclipse.core.runtime.jobs.Job#belongsTo(java.lang.Object)
		 */
		@Override
		public boolean belongsTo(Object family)
		{
			return family == AlarmView.JOB_FAMILY;
		}
	}
	
	private IWorkbenchPart wbPart;
	private Object[] currentSelection;
	
	/* (non-Javadoc)
	 * @see org.eclipse.ui.IActionDelegate#run(org.eclipse.jface.action.IAction)
	 */
	@Override
	public void run(IAction action)
	{
		IWorkbenchSiteProgressService siteService =
	      (IWorkbenchSiteProgressService)wbPart.getSite().getAdapter(IWorkbenchSiteProgressService.class);
		siteService.schedule(new TerminateJob(currentSelection), 0, true);
	}

	/* (non-Javadoc)
	 * @see org.eclipse.ui.IActionDelegate#selectionChanged(org.eclipse.jface.action.IAction, org.eclipse.jface.viewers.ISelection)
	 */
	@Override
	public void selectionChanged(IAction action, ISelection selection)
	{
		if (selection instanceof IStructuredSelection)
			currentSelection = ((IStructuredSelection)selection).toArray();
	}

	/* (non-Javadoc)
	 * @see org.eclipse.ui.IObjectActionDelegate#setActivePart(org.eclipse.jface.action.IAction, org.eclipse.ui.IWorkbenchPart)
	 */
	@Override
	public void setActivePart(IAction action, IWorkbenchPart targetPart)
	{
		wbPart = targetPart;
	}
}
