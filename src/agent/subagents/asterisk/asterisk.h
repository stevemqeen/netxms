/*
** NetXMS Asterisk subagent
** Copyright (C) 2004-2018 Victor Kirhenshtein
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
** File: asterisk.h
**
**/

#ifndef _asterisk_h_
#define _asterisk_h_

#include <nms_common.h>
#include <nms_util.h>
#include <nms_agent.h>

#define DEBUG_TAG _T("asterisk")

#define MAX_AMI_TAG_LEN       32
#define MAX_AMI_SUBTYPE_LEN   64

/**
 * AMI message type
 */
enum AmiMessageType
{
   AMI_UNKNOWN = 0,
   AMI_EVENT = 1,
   AMI_ACTION = 2,
   AMI_RESPONSE = 3
};

/**
 * AMI message tag
 */
struct AmiMessageTag
{
   AmiMessageTag *next;
   char name[MAX_AMI_TAG_LEN];
   char *value;

   AmiMessageTag(const char *_name, const char *_value, AmiMessageTag *_next)
   {
      strlcpy(name, _name, MAX_AMI_TAG_LEN);
      value = strdup(_value);
      next = _next;
   }

   ~AmiMessageTag()
   {
      MemFree(value);
   }
};

/**
 * AMI message
 */
class AmiMessage : public RefCountObject
{
private:
   AmiMessageType m_type;
   char m_subType[MAX_AMI_SUBTYPE_LEN];
   INT64 m_id;
   AmiMessageTag *m_tags;
   StringList *m_data;

   AmiMessage();

   AmiMessageTag *findTag(const char *name);

protected:
   virtual ~AmiMessage();

public:
   AmiMessage(const char *subType);

   AmiMessageType getType() const { return m_type; }
   const char *getSubType() const { return m_subType; }
   bool isSuccess() const { return !stricmp(m_subType, "Success") || !stricmp(m_subType, "Follows"); }

   INT64 getId() const { return m_id; }
   void setId(INT64 id) { m_id = id; }

   const char *getTag(const char *name);
   int getTagAsInt(const char *name, int defaultValue = 0);
   void setTag(const char *name, const char *value);

   const StringList *getData() const { return m_data; }
   StringList *acquireData() { StringList *d = m_data; m_data = NULL; return d; }

   ByteStream *serialize();

   static AmiMessage *createFromNetwork(RingBuffer& buffer);
};

/**
 * AMI event listener
 */
class AmiEventListener
{
public:
   virtual ~AmiEventListener() { }

   virtual void processEvent(AmiMessage *event) = 0;
};

/**
 * Cumulative event counters
 */
struct EventCounters
{
   UINT64 callBarred;
   UINT64 callRejected;
   UINT64 channelUnavailable;
   UINT64 congestion;
   UINT64 noRoute;
   UINT64 subscriberAbsent;
};

/**
 * Asterisk system information
 */
class AsteriskSystem
{
private:
   TCHAR *m_name;
   InetAddress m_ipAddress;
   UINT16 m_port;
   char *m_login;
   char *m_password;
   SOCKET m_socket;
   THREAD m_connectorThread;
   RingBuffer m_networkBuffer;
   INT64 m_requestId;
   INT64 m_activeRequestId;
   MUTEX m_requestLock;
   CONDITION m_requestCompletion;
   AmiMessage *m_response;
   bool m_amiSessionReady;
   bool m_resetSession;
   ObjectArray<AmiEventListener> m_eventListeners;
   MUTEX m_eventListenersLock;
   UINT32 m_amiTimeout;
   EventCounters m_globalEventCounters;
   StringObjectMap<EventCounters> m_peerEventCounters;

   static THREAD_RESULT THREAD_CALL connectorThreadStarter(void *arg);

   AmiMessage *readMessage() { return AmiMessage::createFromNetwork(m_networkBuffer); }
   bool processMessage(AmiMessage *msg);
   void connectorThread();

   bool sendLoginRequest();

   void processHangup(AmiMessage *msg);

   AsteriskSystem(const TCHAR *name);

public:
   static AsteriskSystem *createFromConfig(ConfigEntry *config, bool defaultSystem);

   ~AsteriskSystem();

   const TCHAR *getName() const { return m_name; }
   bool isAmiSessionReady() const { return m_amiSessionReady; }

   void start();
   void stop();
   void reset();

   void addEventListener(AmiEventListener *listener);
   void removeEventListener(AmiEventListener *listener);

   AmiMessage *sendRequest(AmiMessage *request, ObjectRefArray<AmiMessage> *list = NULL, UINT32 timeout = 0);

   LONG readSingleTag(const char *rqname, const char *tag, TCHAR *value);
   ObjectRefArray<AmiMessage> *readTable(const char *rqname);
   StringList *executeCommand(const char *command);

   const EventCounters *getGlobalEventCounters() const { return &m_globalEventCounters; }
   const EventCounters *getPeerEventCounters(const TCHAR *peer) const { return m_peerEventCounters.get(peer); }
};

/**
 * Get configured asterisk system by name
 */
AsteriskSystem *GetAsteriskSystemByName(const TCHAR *name);

/**
 * Get peer name from channel name
 */
char *PeerFromChannelA(const char *channel, char *peer, size_t size);
#ifdef UNICODE
WCHAR *PeerFromChannelW(const char *channel, WCHAR *peer, size_t size);
#define PeerFromChannel PeerFromChannelW
#else
#define PeerFromChannel PeerFromChannelA
#endif

/**
 * Standard prologue for parameter handler - retrieve system from first argument
 */
#define GET_ASTERISK_SYSTEM(n) \
TCHAR sysName[256]; \
if (n > 0) { \
   TCHAR temp[256]; \
   if (!AgentGetParameterArg(param, n + 1, temp, 256)) \
      return SYSINFO_RC_UNSUPPORTED; \
   if (temp[0] != 0) { \
      if (!AgentGetParameterArg(param, 1, sysName, 256)) \
         return SYSINFO_RC_UNSUPPORTED; \
   } else { \
      sysName[0] = 0; \
   } \
} else { \
if (!AgentGetParameterArg(param, 1, sysName, 256)) \
   return SYSINFO_RC_UNSUPPORTED; \
} \
AsteriskSystem *sys = GetAsteriskSystemByName((sysName[0] != 0) ? sysName : _T("LOCAL")); \
if (sys == NULL) \
   return SYSINFO_RC_NO_SUCH_INSTANCE;

/**
 * Get first argument after system ID (must be used after GET_ASTERISK_SYSTEM)
 */
#define GET_ARGUMENT(n, b, s) \
do { if (!AgentGetParameterArg(param, (sysName[0] == 0) ? n : n + 1, b, s)) return SYSINFO_RC_UNSUPPORTED; } while(0)

/**
 * Get first argument after system ID as multibyte string (must be used after GET_ASTERISK_SYSTEM)
 */
#define GET_ARGUMENT_A(n, b, s) \
do { if (!AgentGetParameterArgA(param, (sysName[0] == 0) ? n : n + 1, b, s)) return SYSINFO_RC_UNSUPPORTED; } while(0)

#endif
