/*
 ** LoraWAN subagent
 ** Copyright (C) 2009 - 2017 Raden Solutions
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

#include "lorawan.h"

/**
 * LoraWAN server link constructor
 */
LoraWanServerLink::LoraWanServerLink(const ConfigEntry *config)
{
   char *m_user;
   char *m_pass;
#ifdef UNICODE
   m_user = UTF8StringFromWideString(config->getSubEntryValue(L"User", 0, L"admin"));
   m_pass = UTF8StringFromWideString(config->getSubEntryValue(L"Password", 0, L"admin"));
   m_url = UTF8StringFromWideString(config->getSubEntryValue(L"URL", 0, L"http://localhost"));
#else
   m_user = strdup(config->getSubEntryValue("User", 0, "admin"));
   m_pass = strdup(config->getSubEntryValue("Password", 0, "admin"));
   m_url =  strdup(config->getSubEntryValue("URL", 0, "http://localhost"));
#endif
   m_response = 0;

   snprintf(m_auth, MAX_AUTH_LENGTH, "%s:%s", m_user, m_pass);
   m_curl = NULL;

   free(m_user);
   free(m_pass);
}

/*
 * LoraWAN server link destructor
 */
LoraWanServerLink::~LoraWanServerLink()
{
   disconnect();
   free(m_url);
}

/**
 * Callback for processing data received from cURL
 */
static size_t OnCurlDataReceived(char *ptr, size_t size, size_t nmemb, void *userdata)
{
   char *data = (char *)userdata;
   data = (char *)malloc(size * nmemb);
   memcpy(data, ptr, size * nmemb);
   data[size * nmemb] = 0;

   return size * nmemb;
}

/**
 * Send cURL request
 */
UINT32 LoraWanServerLink::sendRequest(const char *method, const char *url, const char *responseData, const curl_slist *headers, char *postFields)
{
   curl_easy_setopt(m_curl, CURLOPT_URL, url);
   curl_easy_setopt(m_curl, CURLOPT_CUSTOMREQUEST, method);
   curl_easy_setopt(m_curl, CURLOPT_HTTPHEADER, headers);
   curl_easy_setopt(m_curl, CURLOPT_WRITEDATA, responseData);
   curl_easy_setopt(m_curl, CURLOPT_POSTFIELDS, postFields);

   UINT32 rcc = curl_easy_perform(m_curl);
   if (rcc == CURLE_OK)
   {
      curl_easy_getinfo(m_curl, CURLINFO_RESPONSE_CODE, &m_response);
      nxlog_debug(7, _T("LoraWAN Module: LoraWAN server request - URL: %hs, Method: %hs, Response: %03d"), url, method, m_response);
   }
   else
      nxlog_debug(7, _T("LoraWAN Module: call to curl_easy_perform() failed: %hs"), m_errorBuffer);

   return rcc;
}

/**
 * Connect to LoraWAN server
 */
void LoraWanServerLink::connect()
{
   disconnect();

   m_curl = curl_easy_init();
   if (m_curl == NULL)
   {
      nxlog_debug(4, _T("LoraWAN Module: call to curl_easy_init() failed"));
      return;
   }

   curl_easy_setopt(m_curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
   curl_easy_setopt(m_curl, CURLOPT_USERPWD, m_auth);
   curl_easy_setopt(m_curl, CURLOPT_URL, m_url);
   curl_easy_setopt(m_curl, CURLOPT_ERRORBUFFER, m_errorBuffer);
   curl_easy_setopt(m_curl, CURLOPT_WRITEFUNCTION, OnCurlDataReceived);

   if (sendRequest("OPTIONS", m_url) == CURLE_OK)
   {
      if (m_response == 200)
         nxlog_debug(4, _T("LoraWAN Module: LoraWAN server login successful"));
      else
         nxlog_debug(4, _T("LoraWAN Module: LoraWAN server login failed, HTTP response code %03d"), m_response);
   }
}

/**
 * Disconnect from LoraWAN server
 */
void LoraWanServerLink::disconnect()
{
   if (m_curl == NULL)
      return;

   curl_easy_cleanup(m_curl);
   m_curl = NULL;
}

/**
 * Register new LoraWAN device
 */
UINT32 LoraWanServerLink::registerDevice(const char *xmlConfig, uuid guid)
{
   UINT32 rcc;

   if (true)   // TODO check connection
   {
      Config config;
      config.loadXmlConfigFromMemory(xmlConfig, (int)strlen(xmlConfig), NULL, "config", false);

      nxlog_debug(4, _T("LoraWAN Module: Config DevAddr %s"), config.getValue(_T("/DevAddr")));
      nxlog_debug(4, _T("LoraWAN Module: Config DevEUI %s"), config.getValue(_T("/DevEUI")));
      struct deviceData *data = new struct deviceData();
      data->guid = guid;
      data->decoder = config.getValueAsInt(_T("/decoder"), 0);
      nxlog_debug(4, _T("LoraWAN Module: decoder %d"), data->decoder);

      json_t *root = json_object();
      json_object_set_new(root, "adr_flag_set", json_integer(1)); // Config value?
      json_object_set_new(root, "app", json_string("backend"));
      json_object_set_new(root, "appid", json_string("LoraWAN Devices")); // Config value?
      json_object_set_new(root, "can_join", json_true());
      json_object_set_new(root, "fcnt_check", json_integer(3));
      json_object_set_new(root, "region", json_string("EU863-870")); // Config value?
      json_object_set_new(root, "appargs", data->guid.toJson());

      char url[MAX_PATH];
      strcpy(url, m_url);
      if (config.getValueAsInt(_T("/registrationType"), 0)) // OTAA
      {
         StrToBin(config.getValue(_T("/DevEUI")), data->devEui, 8);
         json_object_set_new(root, "deveui", json_string_t(config.getValue(_T("/DevEUI"))));
         json_object_set_new(root, "appeui", json_string_t(config.getValue(_T("/AppEUI"))));
         json_object_set_new(root, "appkey", json_string_t(config.getValue(_T("/AppKey"))));
         strcat(url, "/devices");
      }
      else  // ABP
      {
         StrToBin(config.getValue(_T("/DevAddr")), data->devAddr, 4);
         json_object_set_new(root, "devaddr", json_string_t(config.getValue(_T("/DevAddr"))));
         json_object_set_new(root, "appskey", json_string_t(config.getValue(_T("/AppSKey"))));
         json_object_set_new(root, "nwkskey", json_string_t(config.getValue(_T("/NwkSKey"))));
         strcat(url, "/nodes");
      }

      char *request = json_dumps(root, 0);
      struct curl_slist *headers = NULL;
      headers = curl_slist_append(headers, "Content-Type: application/json;charset=UTF-8");

      if (sendRequest("POST", url, NULL, headers, request) == CURLE_OK)
      {
         if (m_response == 204)
         {
            nxlog_debug(4, _T("LoraWAN Module: New LoraWAN device successfully registered"));
            rcc = AddDevice(data);
         }
         else
         {
            nxlog_debug(4, _T("LoraWAN Module: LoraWAN device registration failed, HTTP response code %03d"), m_response);
            rcc = ERR_BAD_RESPONSE;
         }
      }
      else
         rcc = ERR_EXEC_FAILED;

      free(root);
      free(request);
   }
   else
      rcc = ERR_CONNECTION_BROKEN;

   return rcc;
}

/**
 * Delete LoraWAN device
 */
UINT32 LoraWanServerLink::deleteDevice(uuid guid)
{
   UINT32 rcc = ERR_INVALID_OBJECT;
   if (true)// TODO check connection
   {
      struct deviceData *data = FindDevice(guid);
      if (data == NULL)
         return rcc;

      char url[MAX_PATH];
      if (data->devEui != 0)  // if OTAA
      {
         char devEui[20];
         BinToStrA(data->devEui, 20, devEui);

         snprintf(url, MAX_PATH, "%s/devices/%s", m_url, devEui);
         if (sendRequest("DELETE", url) == CURLE_OK)
         {
            curl_easy_getinfo(m_curl, CURLINFO_RESPONSE_CODE, &m_response);
            if (m_response == 204)
               nxlog_debug(4, _T("LoraWAN Module: New LoraWAN device successfully deleted"));
            else
               nxlog_debug(4, _T("LoraWAN Module: LoraWAN device deletion failed, HTTP response code %03d"), m_response);
         }
      }

      char devAddr[20];
      BinToStrA(data->devAddr, 20, devAddr);

      snprintf(url, MAX_PATH, "%s/nodes/%s", m_url, devAddr);
      struct curl_slist *headers = NULL;
      headers = curl_slist_append(headers, "Accept: application/json");
      char *responseData;
      if (sendRequest("GET", url, responseData, headers) == CURLE_OK)
      {
         if (m_response == 200)
         {
            if (sendRequest("DELETE", url) == CURLE_OK)
            {
               if (m_response == 204)
               {
                  nxlog_debug(4, _T("LoraWAN Module: New LoraWAN node successfully deleted"));
                  rcc = RemoveDevice(guid);
               }
               else
               {
                  nxlog_debug(4, _T("LoraWAN Module: LoraWAN node deletion failed, HTTP response code %03d"), m_response);
                  rcc = ERR_BAD_RESPONSE;
               }
            }
         }
         else
            nxlog_debug(4, _T("LoraWAN Module: LoraWAN node deletion failed, HTTP response code %03d"), m_response);
      }
      else
         rcc = ERR_EXEC_FAILED;

      free(responseData);
   }
   else
      rcc = ERR_CONNECTION_BROKEN;

   return rcc;
}