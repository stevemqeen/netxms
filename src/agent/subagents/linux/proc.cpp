/* $Id: proc.cpp,v 1.1 2004-10-22 22:08:34 alk Exp $ */

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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>

#include "proc.h"

static int ProcFilter(const struct dirent *pEnt)
{
	char *pTmp;

	if (pEnt == NULL)
	{
		return 0; // ignore file
	}

	pTmp = (char *)pEnt->d_name;
	while (*pTmp != 0)
	{
		if (*pTmp < '0' || *pTmp > '9')
		{
			return 0; // skip
		}
		pTmp++;
	}

	return 1;
}

int ProcRead(PROC_ENT **pEnt, char *szPatern)
{
	struct dirent **pNameList;
	int nCount, nFound;
	char *pPatern;

	if (szPatern != NULL)
	{
		pPatern = szPatern;
	}
	else
	{
		pPatern = "";
	}

	nFound = -1;

	nCount = scandir("/proc", &pNameList, &ProcFilter, alphasort);
	if (nCount < 0)
	{
		//perror("scandir");
	}
	else
	{
		nFound = 0;

		if (nCount > 0 && pEnt != NULL)
		{
			*pEnt = (PROC_ENT *)malloc(sizeof(PROC_ENT) * (nCount + 1));

			if (*pEnt == NULL)
			{
				nFound = -1;
				// cleanup
				while(nCount--)
				{
					free(pNameList[nCount]);
				}
			}
			else
			{
				memset(*pEnt, 0, sizeof(PROC_ENT) * (nCount + 1));
			}
		}

		while(nCount--)
		{
			char szFileName[256];
			FILE *hFile;

			snprintf(szFileName, sizeof(szFileName),
					"/proc/%s/stat", pNameList[nCount]->d_name);
			hFile = fopen(szFileName, "r");
			if (hFile != NULL)
			{
				char szBuff[1024];
				if (fgets(szBuff, sizeof(szBuff), hFile) != NULL)
				{
					char *pProcName;
					unsigned int nPid;

					if (sscanf(szBuff, "%lu ", &nPid) == 1)
					{
						pProcName = strchr(szBuff, ')');
						if (pProcName != NULL)
						{
							*pProcName = 0;

							pProcName =  strchr(szBuff, '(');
							if (pProcName != NULL)
							{
								pProcName++;

								if (strstr(pProcName, pPatern) != NULL)
								{
									nFound++;
									if (pEnt != NULL)
									{
										(*pEnt)[nFound].nPid = nPid;
										strncpy((*pEnt)[nFound].szProcName, pProcName,
												sizeof((*pEnt)[nFound].szProcName));
									}
								}
							}
						}
					}
				}

				fclose(hFile);
			}
			free(pNameList[nCount]);
		}
		free(pNameList);
	}

	return nFound;
}

///////////////////////////////////////////////////////////////////////////////
/*

$Log: not supported by cvs2svn $

*/
