/* 
** NetXMS - Network Management System
** NetXMS Scripting Language Interpreter
** Copyright (C) 2003-2010 Victor Kirhenshtein
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU Lesser General Public License as published by
** the Free Software Foundation; either version 3 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU Lesser General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
**
** fILE: library.cpp
**
**/

#include "libnxsl.h"


//
// Constructor
//

NXSL_Library::NXSL_Library()
{
   m_mutex = MutexCreate();
   m_dwNumScripts = 0;
   m_ppScriptList = NULL;
   m_ppszNames = NULL;
   m_pdwIdList = NULL;
}


//
// Destructor
//

NXSL_Library::~NXSL_Library()
{
   DWORD i;

   for(i = 0; i < m_dwNumScripts; i++)
   {
      delete m_ppScriptList[i];
      free(m_ppszNames[i]);
   }
   safe_free(m_ppScriptList);
   safe_free(m_ppszNames);
   safe_free(m_pdwIdList);
   MutexDestroy(m_mutex);
}


//
// Add script to list
//

BOOL NXSL_Library::addScript(DWORD dwId, const TCHAR *pszName, NXSL_Program *pScript)
{
   DWORD i;

   for(i = 0; i < m_dwNumScripts; i++)
      if (!_tcsicmp(m_ppszNames[i], pszName))
         return FALSE;

   m_dwNumScripts++;
   m_ppScriptList = (NXSL_Program **)realloc(m_ppScriptList, sizeof(NXSL_Program *) * m_dwNumScripts);
   m_ppszNames = (TCHAR **)realloc(m_ppszNames, sizeof(char *) * m_dwNumScripts);
   m_pdwIdList = (DWORD *)realloc(m_pdwIdList, sizeof(DWORD) * m_dwNumScripts);
   m_ppScriptList[i] = pScript;
   m_ppszNames[i] = _tcsdup(pszName);
   m_pdwIdList[i] = dwId;
   return TRUE;
}


//
// Delete script from list
//

void NXSL_Library::deleteInternal(int nIndex)
{
   delete m_ppScriptList[nIndex];
   free(m_ppszNames[nIndex]);
   m_dwNumScripts--;
   memmove(&m_ppScriptList[nIndex], &m_ppScriptList[nIndex + 1],
           sizeof(NXSL_Program *) * (m_dwNumScripts - nIndex));
   memmove(&m_ppszNames[nIndex], &m_ppszNames[nIndex + 1],
           sizeof(char *) * (m_dwNumScripts - nIndex));
   memmove(&m_pdwIdList[nIndex], &m_pdwIdList[nIndex + 1],
           sizeof(DWORD) * (m_dwNumScripts - nIndex));
}

void NXSL_Library::deleteScript(const TCHAR *pszName)
{
   DWORD i;

   for(i = 0; i < m_dwNumScripts; i++)
      if (!_tcsicmp(m_ppszNames[i], pszName))
      {
         deleteInternal(i);
         break;
      }
}

void NXSL_Library::deleteScript(DWORD dwId)
{
   DWORD i;

   for(i = 0; i < m_dwNumScripts; i++)
      if (m_pdwIdList[i] == dwId)
      {
         deleteInternal(i);
         break;
      }
}

/**
 * Find script by name
 */
NXSL_Program *NXSL_Library::findScript(const TCHAR *pszName)
{
   DWORD i;

   for(i = 0; i < m_dwNumScripts; i++)
      if (!_tcsicmp(m_ppszNames[i], pszName))
      {
         return m_ppScriptList[i];
      }
   return NULL;
}

/**
 * Fill NXCP message with script data
 */
void NXSL_Library::fillMessage(CSCPMessage *pMsg)
{
   DWORD i, dwId;

   pMsg->SetVariable(VID_NUM_SCRIPTS, m_dwNumScripts);
   for(i = 0, dwId = VID_SCRIPT_LIST_BASE; i < m_dwNumScripts; i++)
   {
      pMsg->SetVariable(dwId++, m_pdwIdList[i]);
      pMsg->SetVariable(dwId++, m_ppszNames[i]);
   }
}
