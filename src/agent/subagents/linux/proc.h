/* $Id: proc.h,v 1.1 2004-10-22 22:08:35 alk Exp $ */

/* 
** NetXMS subagent for GNU/Linux
** Copyright (C) 2004 Alex Kirhenshtein
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
**
**/

#ifndef __PROC_H__
#define __PROC_H__

typedef struct t_ProcEnt
{
	unsigned int nPid;
	char szProcName[128];
} PROC_ENT;

int ProcRead(PROC_ENT **, char *);

#endif // __PROC_H__

///////////////////////////////////////////////////////////////////////////////
/*

$Log: not supported by cvs2svn $

*/
