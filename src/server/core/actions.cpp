/* 
** NetXMS - Network Management System
** Copyright (C) 2003, 2004 Victor Kirhenshtein
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
** $module: actions.cpp
**
**/

#include "nms_core.h"


//
// Static data
//

static DWORD m_dwNumActions = 0;
static NXC_ACTION *m_pActionList = NULL;
static RWLOCK m_rwlockActionListAccess;
static DWORD m_dwUpdateCode;


//
// Send updates to all connected clients
//

static void SendActionDBUpdate(ClientSession *pSession, void *pArg)
{
   pSession->OnActionDBUpdate(m_dwUpdateCode, (NXC_ACTION *)pArg);
}


//
// Destroy action list
//

static void DestroyActionList(void)
{
   DWORD i;

   RWLockWriteLock(m_rwlockActionListAccess, INFINITE);
   if (m_pActionList != NULL)
   {
      for(i = 0; i < m_dwNumActions; i++)
         safe_free(m_pActionList[i].pszData);
      free(m_pActionList);
      m_pActionList = NULL;
      m_dwNumActions = 0;
   }
   RWLockUnlock(m_rwlockActionListAccess);
}


//
// Load actions list from database
//

static BOOL LoadActions(void)
{
   DB_RESULT hResult;
   BOOL bResult = FALSE;
   DWORD i;
   char *pStr;

   hResult = DBSelect(g_hCoreDB, "SELECT action_id,action_name,action_type,"
                                 "is_disabled,rcpt_addr,email_subject,action_data "
                                 "FROM actions ORDER BY action_id");
   if (hResult != NULL)
   {
      DestroyActionList();
      m_dwNumActions = (DWORD)DBGetNumRows(hResult);
      m_pActionList = (NXC_ACTION *)malloc(sizeof(NXC_ACTION) * m_dwNumActions);
      for(i = 0; i < m_dwNumActions; i++)
      {
         m_pActionList[i].dwId = DBGetFieldULong(hResult, i, 0);
         strncpy(m_pActionList[i].szName, DBGetField(hResult, i, 1), MAX_OBJECT_NAME);
         m_pActionList[i].iType = DBGetFieldLong(hResult, i, 2);
         m_pActionList[i].bIsDisabled = DBGetFieldLong(hResult, i, 3);

         pStr = DBGetField(hResult, i, 4);
         strcpy(m_pActionList[i].szRcptAddr, CHECK_NULL(pStr));
         DecodeSQLString(m_pActionList[i].szRcptAddr);

         pStr = DBGetField(hResult, i, 5);
         strcpy(m_pActionList[i].szEmailSubject, CHECK_NULL(pStr));
         DecodeSQLString(m_pActionList[i].szEmailSubject);

         m_pActionList[i].pszData = strdup(DBGetField(hResult, i, 6));
         DecodeSQLString(m_pActionList[i].pszData);
      }
      DBFreeResult(hResult);
      bResult = TRUE;
   }
   else
   {
      WriteLog(MSG_ACTIONS_LOAD_FAILED, EVENTLOG_ERROR_TYPE, NULL);
   }
   return bResult;
}


//
// Initialize action-related stuff
//

BOOL InitActions(void)
{
   BOOL bSuccess = FALSE;

   m_rwlockActionListAccess = RWLockCreate();
   if (m_rwlockActionListAccess != NULL)
      bSuccess = LoadActions();
   return bSuccess;
}


//
// Cleanup action-related stuff
//

void CleanupActions(void)
{
   DestroyActionList();
   RWLockDestroy(m_rwlockActionListAccess);
}


//
// Save action record to database
//

static void SaveActionToDB(NXC_ACTION *pAction)
{
   DB_RESULT hResult;
   BOOL bExist = FALSE;
   char szQuery[4096];

   // Check if action with given ID already exist in database
   sprintf(szQuery, "SELECT action_id FROM actions WHERE action_id=%ld", pAction->dwId);
   hResult = DBSelect(g_hCoreDB, szQuery);
   if (hResult != NULL)
   {
      bExist = (DBGetNumRows(hResult) > 0);
      DBFreeResult(hResult);
   }

   // Prepare and execute INSERT or UPDATE query
   if (bExist)
      sprintf(szQuery, "UPDATE actions SET action_name='%s',action_type=%d,is_disabled=%d,"
                       "rcpt_addr='%s',email_subject='%s',action_data='%s'"
                       "WHERE action_id=%ld",
              pAction->szName, pAction->iType, pAction->bIsDisabled,
              pAction->szRcptAddr, pAction->szEmailSubject,
              (pAction->pszData == NULL ? "" : pAction->pszData), pAction->dwId);
   else
      sprintf(szQuery, "INSERT INTO actions (action_id,action_name,action_type,"
                       "is_disabled,rcpt_addr,email_subject,action_data VALUES"
                       " (%ld,'%s',%d,%d,'%s','%s','%s')",
              pAction->dwId,pAction->szName, pAction->iType, pAction->bIsDisabled,
              pAction->szRcptAddr, pAction->szEmailSubject,
              (pAction->pszData == NULL ? "" : pAction->pszData));
   DBQuery(g_hCoreDB, szQuery);
}


//
// Compare action's id for bsearch()
//

static int CompareId(const void *key, const void *elem)
{
   return (DWORD)key < ((NXC_ACTION *)elem)->dwId ? -1 : 
            ((DWORD)key > ((NXC_ACTION *)elem)->dwId ? 1 : 0);
}


//
// Execute action on specific event
//

BOOL ExecuteAction(DWORD dwActionId, Event *pEvent)
{
   NXC_ACTION *pAction;
   BOOL bSuccess = FALSE;

   RWLockReadLock(m_rwlockActionListAccess, INFINITE);
   pAction = (NXC_ACTION *)bsearch((void *)dwActionId, m_pActionList, 
                                   m_dwNumActions, sizeof(NXC_ACTION), CompareId);
   if (pAction != NULL)
   {
      if (pAction->bIsDisabled)
      {
         DbgPrintf(AF_DEBUG_ACTIONS, "*actions* Action %d (%s) is disabled and will not be executed\n",
                   dwActionId, pAction->szName);
         bSuccess = TRUE;
      }
      else
      {
         char *pszExpandedData;

         pszExpandedData = pEvent->ExpandText(pAction->pszData);
         switch(pAction->iType)
         {
            case ACTION_EXEC:
               DbgPrintf(AF_DEBUG_ACTIONS, "*actions* Executing command \"%s\"\n", pszExpandedData);
               bSuccess = ExecCommand(pszExpandedData);
               break;
            case ACTION_SEND_EMAIL:
               DbgPrintf(AF_DEBUG_ACTIONS, "*actions* Sending mail to %s: \"%s\"\n", 
                         pAction->szRcptAddr, pszExpandedData);
               break;
            case ACTION_SEND_SMS:
               DbgPrintf(AF_DEBUG_ACTIONS, "*actions* Sending SMS to %s: \"%s\"\n", 
                         pAction->szRcptAddr, pszExpandedData);
               break;
            case ACTION_REMOTE:
               DbgPrintf(AF_DEBUG_ACTIONS, "*actions* Executing on \"%s\": \"%s\"\n", 
                         pAction->szRcptAddr, pszExpandedData);
               break;
            default:
               break;
         }
         free(pszExpandedData);
      }
   }
   RWLockUnlock(m_rwlockActionListAccess);
   return bSuccess;
}


//
// Create new action
//

DWORD CreateNewAction(char *pszName, DWORD *pdwId)
{
   DWORD i, dwResult = RCC_SUCCESS;

   RWLockWriteLock(m_rwlockActionListAccess, INFINITE);

   // Check for duplicate name
   for(i = 0; i < m_dwNumActions; i++)
      if (!stricmp(m_pActionList[i].szName, pszName))
      {
         dwResult = RCC_ALREADY_EXIST;
         break;
      }

   // If not exist, create it
   if (i == m_dwNumActions)
   {
      m_dwNumActions++;
      m_pActionList = (NXC_ACTION *)realloc(m_pActionList, sizeof(NXC_ACTION) * m_dwNumActions);
      m_pActionList[i].dwId = CreateUniqueId(IDG_ACTION);
      strncpy(m_pActionList[i].szName, pszName, MAX_OBJECT_NAME);
      m_pActionList[i].bIsDisabled = TRUE;
      m_pActionList[i].iType = ACTION_EXEC;
      m_pActionList[i].szEmailSubject[0] = 0;
      m_pActionList[i].szRcptAddr[0] = 0;
      m_pActionList[i].pszData = NULL;

      SaveActionToDB(&m_pActionList[i]);
      m_dwUpdateCode = NX_NOTIFY_ACTION_CREATED;
      EnumerateClientSessions(SendActionDBUpdate, &m_pActionList[i]);
      *pdwId = m_pActionList[i].dwId;
   }

   RWLockUnlock(m_rwlockActionListAccess);
   return dwResult;
}
