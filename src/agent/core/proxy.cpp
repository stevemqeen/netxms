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
#define LISTEN_PORT 4700

/**
 * Data collectors thread pool
 */
extern ThreadPool *g_dataCollectorPool;

HashMap<ProxyKey, DataCollectionProxy> *g_proxyList = new HashMap<ProxyKey, DataCollectionProxy>();
HashMap<UINT64, ServerProxyConfig> *g_proxyserverConfList = new HashMap<UINT64, ServerProxyConfig>();
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

static void SaveProxyToDatabase(UINT64 serverId, HashMap<ProxyKey, DataCollectionProxy> *proxyList, ServerProxyConfig *cfg)
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
   while (it->hasNext())
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
   //TODO: save cfg to database

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

   //TODO: load cfg from database
}

/**
 * Connect to given host/port
 *
 * @return connected socket on success or INVALID_SOCKET on error
 */
SOCKET ConnectToHostUDP(const InetAddress& addr, UINT16 port) //TODO: Add IPv6?
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

static bool IsConnected(SOCKET sd, ProxyKey key, const BYTE *sharedKey, UINT32 nodeId) { //shared key is 16 byte
   bool result = false;
   int nRet, retryCount;
   ProxyKey tmp;
   ProxyMsg request;
   ProxyMsg response;
   GenerateRandomBytes(request.m_challange, PROXY_CHALANGE_SIZE);
   request.m_serverId = htonq(key.m_serverId);
   request.m_proxyIdDest = htonl(key.m_proxyId);
   request.m_proxyIdSelf = htonl(nodeId);
   SignMessage(reinterpret_cast<BYTE *>(&request), sizeof(request) - sizeof(request.m_hmac), sharedKey, ZONE_PROXY_KEY_LENGTH, request.m_hmac);

   for (int retryCount = 5; retryCount > 0; retryCount--)
   {
#ifdef MSG_NOSIGNAL
      nRet = send(sd, &tmp, sizeof(tmp), MSG_NOSIGNAL);
#else
      nRet = send(sd, &tmp, sizeof(tmp), 0);
#endif

      if (nRet <= 0)
      {
         continue;
      }

      nRet = RecvEx(sd, &response, sizeof(response), 0, 1000);
      if (nRet <= 0)
      {
         if (nRet == 0 || nRet == -1)
         {
            break; // in case if socket was closed or on error just fail
         }
      }
      else
      {
         if(ValidateMessageSignature(reinterpret_cast<BYTE *>(&response), sizeof(response) - sizeof(response.m_hmac), sharedKey, ZONE_PROXY_KEY_LENGTH, response.m_hmac) &&
               !memcmp(response.m_challange, request.m_challange, PROXY_CHALANGE_SIZE) && request.m_proxyIdDest == response.m_proxyIdSelf &&
               response.m_proxyIdDest == request.m_proxyIdSelf)
         {
            result = true;
            break;
         }
         else
         {
            TCHAR cp1[PROXY_CHALANGE_SIZE * 2 + 1];
            TCHAR cp2[PROXY_CHALANGE_SIZE * 2 + 1];
            TCHAR hmac1[SHA256_DIGEST_SIZE * 2 + 1];
            TCHAR hmac2[SHA256_DIGEST_SIZE * 2 + 1];
            nxlog_debug_tag(DEBUG_TAG, 1, _T("Invalid response message. Request message: challange=%s, serverId=") UINT64X_FMT(_T("016"))
                  _T(", proxyDest=%d, proxySource=%d, hmac=%s. Response: challange=%s, serverId=") UINT64X_FMT(_T("016"))
                  _T(", proxyDest=%d, proxySource=%d, hmac=%s."), BinToStr(request.m_challange, MD5_DIGEST_SIZE, cp1),
                  key.m_serverId, key.m_proxyId, nodeId, BinToStr(request.m_hmac, MD5_DIGEST_SIZE, hmac1),
                  BinToStr(response.m_challange, MD5_DIGEST_SIZE, cp2), ntohq(response.m_serverId), ntohl(response.m_proxyIdDest),
                  ntohl(response.m_proxyIdSelf), BinToStr(response.m_hmac, MD5_DIGEST_SIZE, hmac2));
         }
      }
   }
   return result;
}

/**
 * Thread checks if used in DCI proxy node is connected
 */
void ProxyConnectionChecker(void *arg)
{
   g_proxyListMutex.lock();
   Iterator<DataCollectionProxy> *it = g_proxyList->iterator();
   bool reschedule = false;
   while (it->hasNext())
   {
      DataCollectionProxy *dcProxy = it->next();
      if(dcProxy->isUsed())
      {
         reschedule = true;
         SOCKET sd = ConnectToHostUDP(dcProxy->getAddr(), LISTEN_PORT);
         if(sd != INVALID_SOCKET)
         {
            ServerProxyConfig *cfg = g_proxyserverConfList->get(dcProxy->getServerId());
            dcProxy->setConnected(IsConnected(sd, dcProxy->getKey(), cfg->getSharedSecret(), cfg->getThisNodeId()));
         }
         closesocket(sd);
      }
   }
   delete it;
   g_proxyConnectionCheckScheduled = reschedule;
   if(reschedule)
      ThreadPoolScheduleRelative(g_dataCollectorPool, 5000, ProxyConnectionChecker, NULL);

   g_proxyListMutex.unlock();
}

/**
 * Update proxy targets on data collection configuration update
 */
void UpdateProxyTargets(UINT64 serverId, HashMap<ProxyKey, DataCollectionProxy> *proxyList, ServerProxyConfig *cfg)
{
   g_proxyListMutex.lock();
   Iterator<DataCollectionProxy> *it = proxyList->iterator();
   while (it->hasNext())
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
   while (it->hasNext())
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
      ThreadPoolScheduleRelative(g_dataCollectorPool, 0, ProxyConnectionChecker, NULL);

   ServerProxyConfig *old = g_proxyserverConfList->get(serverId);
   if(old == NULL)
   {
      g_proxyserverConfList->set(serverId, new ServerProxyConfig(cfg));
   }
   else
   {
      old->update(cfg);
   }

   g_proxyListMutex.unlock();

   SaveProxyToDatabase(serverId, proxyList, cfg);
}

/**
 * Client listener class
 */
class ProxyConnectionListener : public DatagramSocketListener
{
protected:
   virtual ConnectionProcessingResult processDatagram(SOCKET s);
   virtual bool isStopConditionReached();

public:
   ProxyConnectionListener(UINT16 port,  bool allowV4, bool allowV6) : DatagramSocketListener(port, allowV4, allowV6) { setName(_T("ProxyConnection")); }
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
ConnectionProcessingResult ProxyConnectionListener::processDatagram(SOCKET s)
{
   ProxyMsg request;
   SockAddrBuffer addr;
   TCHAR buffer[64];
   socklen_t addrLen = sizeof(SockAddrBuffer);
   int bytes = recvfrom(s, &request, sizeof(request), 0, (struct sockaddr *)&addr, &addrLen);
   if (bytes > 0)
   {
      g_proxyListMutex.lock();
      ServerProxyConfig *cfg = g_proxyserverConfList->get(ntohl(request.m_serverId));
      bool isValid = false;

      if(cfg != NULL &&
            ValidateMessageSignature(reinterpret_cast<BYTE *>(&request), sizeof(request) - sizeof(request.m_hmac), cfg->getSharedSecret(), ZONE_PROXY_KEY_LENGTH, request.m_hmac) &&
            ntohl(request.m_proxyIdDest) == cfg->getThisNodeId())
      {
         if(g_proxyList->contains(GetKey(cfg->getServerId(), ntohl(request.m_proxyIdSelf))) &&
               cfg->getZoneUIN() == request.m_zoneUin)
         {
            isValid = true;
            UINT32 tmp = request.m_proxyIdDest;
            request.m_proxyIdDest = request.m_proxyIdSelf;
            request.m_proxyIdSelf = tmp;
            SignMessage(reinterpret_cast<BYTE *>(&request), sizeof(request) - sizeof(request.m_hmac), cfg->getSharedSecret(), ZONE_PROXY_KEY_LENGTH, request.m_hmac);
         }
      }
      g_proxyListMutex.unlock();

      if(isValid)
      {
         if (sendto(s, &request, sizeof(request), 0, (struct sockaddr *)&addr, addrLen) < 0)
         {
            nxlog_debug_tag(DEBUG_TAG, 1, _T("ProxyConnectionListener: unable send response to requester: %s"), SockaddrToStr((struct sockaddr *)&addr, buffer));
         }
      }
      else
      {
         nxlog_debug_tag(DEBUG_TAG, 1, _T("ProxyConnectionListener: the packet drop: ip=%s, serverid=") UINT64X_FMT(_T("016")) _T(", nodeid=%d"),
                        SockaddrToStr((struct sockaddr *)&addr, buffer), ntohl(request.m_serverId), ntohl(request.m_proxyIdSelf));
      }
   }
   return CPR_COMPLETED;
}



/**
 * Listener thread
 */
THREAD_RESULT THREAD_CALL ProxyListenerThread(void *arg)
{
   ThreadSetName("ProxyAgentsListener");
   ProxyConnectionListener listener(LISTEN_PORT, (g_dwFlags & AF_DISABLE_IPV4), (g_dwFlags & AF_DISABLE_IPV6));
   if (!listener.initialize())
      return THREAD_OK;

   listener.mainLoop();
   listener.shutdown();
   return THREAD_OK;
}
