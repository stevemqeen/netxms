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

#define DEBUG_TAG _T("proxy")

class DataCollectionProxy;

HashMap<ProxyKey, DataCollectionProxy> *g_proxyList = new HashMap<ProxyKey, DataCollectionProxy>(); //Initialize on agent start !!!
Mutex g_proxyListMutex;

DataCollectionProxy::DataCollectionProxy(UINT64 serverId, UINT32 proxyId, InetAddress ipAddr)
{
   m_serverId = serverId;
   m_proxyId = proxyId;
   m_addr = ipAddr;
   m_connected = true;
   m_used = false;
}

/**
 * Update proxy targets on data collection configuration update
 */
void UpdateProxyTargets(HashMap<ProxyKey, DataCollectionProxy> *proxyList)
{
   g_proxyListMutex.lock();
   Iterator<DataCollectionProxy> *it = proxyList->iterator();
   if(it->hasNext())
   {
      DataCollectionProxy *dcpNew = it->next();
      DataCollectionProxy *dcpOld = g_proxyList->get(dcpNew->getKey());
      if(dcpOld != NULL)
      {
         dcpNew->setConnected(dcpOld->isConnected());
      }
   }
   g_proxyList = proxyList;
   g_proxyListMutex.unlock();
}
