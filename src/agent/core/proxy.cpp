/*
** NetXMS multiplatform core agent
** Copyright (C) 2019 Raden Solutions
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
** File: datacoll.cpp
**
**/

#include "nxagentd.h"
#include <socket_listener.h>

#define DEBUG_TAG _T("proxy")
#define REC_MSG_SIZE 16
#define LISTEN_PORT 4700

/**
 * Data collectors thread pool
 */
extern ThreadPool *g_dataCollectorPool;

HashMap<ProxyKey, DataCollectionProxy> *g_proxyList = new HashMap<ProxyKey, DataCollectionProxy>();
Mutex g_proxyListMutex;
bool g_proxyConnectionCheckScheduled = false;

DataCollectionProxy::DataCollectionProxy(UINT64 serverId, UINT32 proxyId, InetAddress ipAddr)
{
   m_serverId = serverId;
   m_proxyId = proxyId;
   m_addr = ipAddr;
   m_connected = true;
   m_used = false;
}


DataCollectionProxy::DataCollectionProxy(DataCollectionProxy *obj)
{
   m_serverId = obj->m_serverId;
   m_proxyId = obj->m_proxyId;
   m_addr = obj->m_addr;
   m_connected = obj->m_connected;
   m_used = obj->m_used;
}

static void SaveProxyToDatabase(UINT64 serverId, HashMap<ProxyKey, DataCollectionProxy> *proxyList)
{
   DB_HANDLE hdb = GetLocalDatabaseHandle();
   DBBegin(hdb);

   Iterator<DataCollectionProxy> *it = proxyList->iterator();

   TCHAR query[256];
   _sntprintf(query, 256, _T("DELETE FROM dc_config WHERE server_id=") UINT64_FMT, serverId);
   if (DBQuery(hdb, query))
   {
      DBRollback(hdb);
      return;
   }
   DB_STATEMENT hStmt = DBPrepare(hdb, _T("INSERT INTO dc_proxy (server_id,proxy_id,ip_address) VALUES (?,?,?)"), true);
   if (hStmt == NULL)
   {
      DBRollback(hdb);
      return;
   }
   if(it->hasNext())
   {
      DataCollectionProxy *dcp = it->next();
      DBBind(hStmt, 1, DB_SQLTYPE_BIGINT, dcp->getServerId());
      DBBind(hStmt, 2, DB_SQLTYPE_INTEGER, dcp->getProxyId());
      DBBind(hStmt, 3, DB_SQLTYPE_VARCHAR, dcp->getAddr().toString(), DB_BIND_STATIC);
      if (!DBExecute(hStmt))
      {
         DBRollback(hdb);
         return;
      }
   }
   DBFreeStatement(hStmt);
   delete it;
   DBCommit(hdb);
}

void LoadProxyFromDatabase()
{
   DB_HANDLE hdb = GetLocalDatabaseHandle();
   DB_RESULT hResult = DBSelect(hdb, _T("SELECT server_id,proxy_id,ip_address FROM dc_proxy"));
   if (hResult != NULL)
   {
      int count = DBGetNumRows(hResult);
      for(int row = 0; row < count; row++)
      {
         DataCollectionProxy *proxy = new DataCollectionProxy(DBGetFieldInt64(hResult, row, 0), DBGetFieldULong(hResult, row, 1), DBGetFieldInetAddr(hResult, row, 2));
         g_proxyList->set(proxy->getKey(), proxy);
      }
      DBFreeResult(hResult);
   }
}

/**
 * Connect to given host/port
 *
 * @return connected socket on success or INVALID_SOCKET on error
 */
SOCKET ConnectToHostUDP(const InetAddress& addr, UINT16 port, UINT32 timeout) //TODO: Add IPv6?
{
   SOCKET s = socket(addr.getFamily(), SOCK_DGRAM, 0);
   if (s == INVALID_SOCKET)
      return INVALID_SOCKET;

   SockAddrBuffer saBuffer;
   struct sockaddr *sa = addr.fillSockAddr(&saBuffer, port);
   //connect
   int rc = connect(s, sa, SA_LEN(sa));
   if (rc == -1)
   {
      closesocket(s);
      s = INVALID_SOCKET;
   }
   return s;
}

static bool IsConnected(SOCKET sd, ProxyKey key) {
   bool result = false;
   int nRet, retryCount;
   ProxyKey tmp;
   tmp.m_serverId = htonq(key.m_serverId);
   tmp.m_proxyId = htonl(key.m_proxyId);
   ProxyResponseMsg response;

   for (int retryCount = 5; retryCount > 0; retryCount--) {
#ifdef MSG_NOSIGNAL
      nRet = send(sd, &tmp, sizeof(tmp), MSG_NOSIGNAL);
#else
      nRet = send(sd, &tmp, sizeof(tmp), 0);
#endif

      if (nRet <= 0) {
         continue;
      }

      nRet = RecvEx(sd, &response, sizeof(response), 0, 1000);
      if (nRet <= 0) {
         if (nRet == 0 || nRet == -1) {
            break; // in case if socket was closed or on error just fail
         }
      } else {
         tmp.m_serverId = ntohq(response.m_serverId);
         tmp.m_proxyId = ntohl(response.m_proxyId);
         if(g_proxyList->contains(tmp))
         {
            result = true;
            break;
         }
      }
   }
   return result;
}

/**
 * Thread checks if used in DCI proxy node is connected
 */
void ProxyConnectionChecked(void *arg)
{
   g_proxyListMutex.lock();
   Iterator<DataCollectionProxy> *it = g_proxyList->iterator();
   bool reschedule = false;
   if(it->hasNext())
   {
      DataCollectionProxy *dcProxy = it->next();
      if(dcProxy->isUsed())
      {
         reschedule = true;
         SOCKET sd = ConnectToHostUDP(dcProxy->getAddr(), LISTEN_PORT, 5000);
         if(sd != INVALID_SOCKET)
         {
            dcProxy->setConnected(IsConnected(sd, dcProxy->getKey()));
         }
         closesocket(sd);
      }
   }
   delete it;
   g_proxyConnectionCheckScheduled = reschedule;
   if(reschedule)
      ThreadPoolScheduleRelative(g_dataCollectorPool, 5000, ProxyConnectionChecked, NULL);

   g_proxyListMutex.unlock();
}

/**
 * Update proxy targets on data collection configuration update
 */
void UpdateProxyTargets(UINT64 serverId, HashMap<ProxyKey, DataCollectionProxy> *proxyList)
{
   g_proxyListMutex.lock();
   Iterator<DataCollectionProxy> *it = proxyList->iterator();
   if(it->hasNext())
   {
      DataCollectionProxy *dcpNew = it->next();
      DataCollectionProxy *dcpOld = g_proxyList->get(dcpNew->getKey());
      if(dcpOld != NULL)
      {
         dcpOld->setAddr(dcpNew->getAddr());
      }
      else
      {
         g_proxyList->set(dcpNew->getKey(), new DataCollectionProxy(dcpNew));
      }
   }
   delete it;

   it = g_proxyList->iterator();
   if(it->hasNext())
   {
      DataCollectionProxy *dcpOld = it->next();
      if(dcpOld->getServerId() == serverId)
      {
         DataCollectionProxy *dcpNew = proxyList->get(dcpOld->getKey());
         if(dcpNew == NULL)
         {
            it->remove();
         }
      }
   }
   delete it;
   if(!g_proxyConnectionCheckScheduled)
      ThreadPoolScheduleRelative(g_dataCollectorPool, 0, ProxyConnectionChecked, NULL);

   g_proxyListMutex.unlock();

   SaveProxyToDatabase(serverId, proxyList);
}

/**
 * Client listener class
 */
class ProxyConnectionListener : public DatagramSocketListener
{
protected:
   virtual ConnectionProcessingResult processConnection(SOCKET s, const InetAddress& peer);
   virtual bool isStopConditionReached();

public:
   ProxyConnectionListener(UINT16 port) : DatagramSocketListener(port) { setName(_T("ProxyConnection")); }
};

/**
 * Listener stop condition
 */
bool ProxyConnectionListener::isStopConditionReached()
{
   return IsShutdownInProgress();
}

/**
 * Process incoming message
 */
ConnectionProcessingResult ProxyConnectionListener::processConnection(SOCKET s, const InetAddress& peer)
{
   ProxyKey tmp;
   ProxyResponseMsg response;
   SockAddrBuffer addr;
   socklen_t addrLen = sizeof(SockAddrBuffer);
   int bytes = recvfrom(s, &tmp, sizeof(tmp), 0, (struct sockaddr *)&addr, &addrLen);
   if (bytes > 0)
   {

      //decrypt information
      //process information
   }
   return CPR_COMPLETED;
}
