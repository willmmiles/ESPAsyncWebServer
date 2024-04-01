/*
  Asynchronous WebServer library for Espressif MCUs

  Copyright (c) 2016 Hristo Gochkov. All rights reserved.
  This file is part of the esp8266 core for Arduino environment.

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#include "ESPAsyncWebServer.h"
#include "WebHandlerImpl.h"

#ifndef ASYNCWEBSERVER_MINIMUM_ALLOC
#define ASYNCWEBSERVER_MINIMUM_ALLOC 1024
#endif

#ifdef ASYNCWEBSERVER_DEBUG_TRACE
#define DEBUG_PRINTFP(fmt, ...) Serial.printf_P(PSTR("[%d]" fmt), millis(), ##__VA_ARGS__)
#else
#define DEBUG_PRINTFP(...)
#endif

bool ON_STA_FILTER(AsyncWebServerRequest *request) {
  return WiFi.localIP() == request->client()->localIP();
}

bool ON_AP_FILTER(AsyncWebServerRequest *request) {
  return WiFi.localIP() != request->client()->localIP();
}

static bool minimal_send_503(AsyncClient* c) {
    const static char msg_progmem[] PROGMEM = "HTTP/1.1 503 Service Unavailable\r\n\r\n";
    char msg_stack[sizeof(msg_progmem)];  // stack, so we can pull it out of flash memory
    memcpy_P(msg_stack, msg_progmem, sizeof(msg_stack));
    auto w = c->write(msg_stack, sizeof(msg_stack)-1);
    // assume any nonzero value is success
    DEBUG_PRINTFP("**** Sent 503 to %d, result %d\n", (intptr_t) c, w);
    if (w != 0) { c->onAck([](void *, AsyncClient* c, size_t s, uint32_t ){  c->close(); }); }
    return (w != 0);  
}

#ifdef ESP8266
#define GET_MAX_BLOCK_SIZE getMaxFreeBlockSize
#else
#define GET_MAX_BLOCK_SIZE getMaxAllocHeap
#endif

static bool heap_ok(size_t minHeap) {
  return (ESP.getFreeHeap() > minHeap)
    && (ESP.GET_MAX_BLOCK_SIZE() > ASYNCWEBSERVER_MINIMUM_ALLOC);
}

AsyncWebServer::AsyncWebServer(uint16_t port, size_t reqHeapUsage, size_t minHeap)
  : AsyncWebServer(IPADDR_ANY, port, reqHeapUsage, minHeap)
{
}

AsyncWebServer::AsyncWebServer(IPAddress addr, uint16_t port, size_t reqHeapUsage, size_t minHeap)
  : _server(addr, port)
  , _rewrites([](AsyncWebRewrite* r){ delete r; })
  , _handlers([](AsyncWebHandler* h){ delete h; })
  , _requestQueue(LinkedList<AsyncWebServerRequest*>::OnRemove {})
  , _reqHeapUsage(reqHeapUsage)
  , _minHeap(minHeap)
{
  _catchAllHandler = new AsyncCallbackWebHandler();
  if(_catchAllHandler == NULL)
    return;
  _server.onClient([this](void *s, AsyncClient* c){
    if(c == NULL)
      return;

    if ((_minHeap > 0) && !heap_ok(_minHeap)) {
      // Don't even allocate anything we can avoid.  Tell the client we're in trouble with a static response.
      DEBUG_PRINTFP("**** Rejecting client %d: %d, %d\n", (intptr_t) c, _requestQueue.length(), ESP.getFreeHeap());
      c->setNoDelay(true);
      if (!minimal_send_503(c)) {
        c->onPoll([](void *r, AsyncClient* c) { if (minimal_send_503(c)) c->onPoll(nullptr); });
      }
      c->onDisconnect([](void*r, AsyncClient* c){ DEBUG_PRINTFP("*** Client %d disconnected\n", (intptr_t)c);});
      return;
    }

    c->setRxTimeout(3);

    AsyncWebServerRequest *r = new AsyncWebServerRequest((AsyncWebServer*)s, c);
    if(r == NULL){
      c->close(true);
      c->free();
      delete c;
      return;
    }
    _requestQueue.add(r);
  }, this);
}

AsyncWebServer::~AsyncWebServer(){
  reset();  
  end();
  if(_catchAllHandler) delete _catchAllHandler;
}

AsyncWebRewrite& AsyncWebServer::addRewrite(AsyncWebRewrite* rewrite){
  _rewrites.add(rewrite);
  return *rewrite;
}

bool AsyncWebServer::removeRewrite(AsyncWebRewrite *rewrite){
  return _rewrites.remove(rewrite);
}

AsyncWebRewrite& AsyncWebServer::rewrite(const char* from, const char* to){
  return addRewrite(new AsyncWebRewrite(from, to));
}

AsyncWebHandler& AsyncWebServer::addHandler(AsyncWebHandler* handler){
  _handlers.add(handler);
  return *handler;
}

bool AsyncWebServer::removeHandler(AsyncWebHandler *handler){
  return _handlers.remove(handler);
}

void AsyncWebServer::begin(){
  _server.setNoDelay(true);
  _server.begin();
}

void AsyncWebServer::end(){
  _server.end();
}

#if ASYNC_TCP_SSL_ENABLED
void AsyncWebServer::onSslFileRequest(AcSSlFileHandler cb, void* arg){
  _server.onSslFileRequest(cb, arg);
}

void AsyncWebServer::beginSecure(const char *cert, const char *key, const char *password){
  _server.beginSecure(cert, key, password);
}
#endif

void AsyncWebServer::_handleDisconnect(AsyncWebServerRequest *request){
  delete request;
}

void AsyncWebServer::_rewriteRequest(AsyncWebServerRequest *request){
  for(const auto& r: _rewrites){
    if (r->match(request)){
      request->_url = r->toUrl();
      request->_addGetParams(r->params());
    }
  }
}

void AsyncWebServer::_attachHandler(AsyncWebServerRequest *request){
  for(const auto& h: _handlers){
    if (h->filter(request) && h->canHandle(request)){
      request->setHandler(h);
      return;
    }
  }
  
  request->addInterestingHeader("ANY");
  request->setHandler(_catchAllHandler);
}


AsyncCallbackWebHandler& AsyncWebServer::on(String uri, WebRequestMethodComposite method, ArRequestHandlerFunction onRequest, ArUploadHandlerFunction onUpload, ArBodyHandlerFunction onBody){
  AsyncCallbackWebHandler* handler = new AsyncCallbackWebHandler();
  handler->setUri(std::move(uri));
  handler->setMethod(method);
  handler->onRequest(onRequest);
  handler->onUpload(onUpload);
  handler->onBody(onBody);
  addHandler(handler);
  return *handler;
}

AsyncCallbackWebHandler& AsyncWebServer::on(String uri, WebRequestMethodComposite method, ArRequestHandlerFunction onRequest, ArUploadHandlerFunction onUpload){
  AsyncCallbackWebHandler* handler = new AsyncCallbackWebHandler();
  handler->setUri(std::move(uri));
  handler->setMethod(method);
  handler->onRequest(onRequest);
  handler->onUpload(onUpload);
  addHandler(handler);
  return *handler;
}

AsyncCallbackWebHandler& AsyncWebServer::on(String uri, WebRequestMethodComposite method, ArRequestHandlerFunction onRequest){
  AsyncCallbackWebHandler* handler = new AsyncCallbackWebHandler();
  handler->setUri(std::move(uri));
  handler->setMethod(method);
  handler->onRequest(onRequest);
  addHandler(handler);
  return *handler;
}

AsyncCallbackWebHandler& AsyncWebServer::on(String uri, ArRequestHandlerFunction onRequest){
  AsyncCallbackWebHandler* handler = new AsyncCallbackWebHandler();
  handler->setUri(std::move(uri));
  handler->onRequest(onRequest);
  addHandler(handler);
  return *handler;
}

AsyncStaticWebHandler& AsyncWebServer::serveStatic(String uri, fs::FS& fs, String path, const char* cache_control){
  AsyncStaticWebHandler* handler = new AsyncStaticWebHandler(std::move(uri), fs, std::move(path), cache_control);
  addHandler(handler);
  return *handler;
}

void AsyncWebServer::onNotFound(ArRequestHandlerFunction fn){
  _catchAllHandler->onRequest(fn);
}

void AsyncWebServer::onFileUpload(ArUploadHandlerFunction fn){
  _catchAllHandler->onUpload(fn);
}

void AsyncWebServer::onRequestBody(ArBodyHandlerFunction fn){
  _catchAllHandler->onBody(fn);
}

void AsyncWebServer::reset(){
  _rewrites.free();
  _handlers.free();
  
  if (_catchAllHandler != NULL){
    _catchAllHandler->onRequest(NULL);
    _catchAllHandler->onUpload(NULL);
    _catchAllHandler->onBody(NULL);
  }
}

void AsyncWebServer::_processQueue() {  
  // Consider the state of the requests in the queue.
  // Requests in STATE_END have already been handled; we can assume any heap they need has already been allocated.
  // Requests in STATE_QUEUED are pending.  Each iteration we consider the first one.
  // We always allow one request, regardless of heap state.
  {
    size_t count = 0, active = 0, queued = 0;
    for(auto element: _requestQueue) {
      ++count;
      if (element->_parseState == 100) ++active;
      if (element->_parseState == 200) ++queued;
    }
    DEBUG_PRINTFP("Queue: %d entries, %d running, %d queued\n", count, active, queued);
  }

  do { 
    auto heap_ok = ESP.getFreeHeap() >= (_reqHeapUsage + _minHeap);    
    bool active_entries = false;
    AsyncWebServerRequest* next_queued_request = nullptr;
    for(auto entry: _requestQueue) {
      if (entry->_parseState == 100) {
        active_entries = true;
      } else if ((entry->_parseState == 200) && !next_queued_request) {
        next_queued_request = entry;
      };
      if (next_queued_request && active_entries) break;  // no need to go further
    }

    if (next_queued_request && (heap_ok || !active_entries)) {
      next_queued_request->_handleRequest();
      continue; // process another entry
    } 
  } while(0); // as long as we have memory and queued requests.  TODO: some kind of limit

  for(auto entry: _requestQueue) {
    // Un-defer requests
    if (entry->_parseState == 201) entry->_parseState = 200;
  }
}

void AsyncWebServer::_dequeue(AsyncWebServerRequest *request){
  DEBUG_PRINTFP("Removing %d from queue\n", (intptr_t) request);
  _requestQueue.remove(request);
  _processQueue();
}

void AsyncWebServer::dumpStatus() {    
    Serial.println(F("Web server status:"));
    auto end = _requestQueue.end();
    for(auto it = _requestQueue.begin(); it != end; ++it) {
      Serial.printf_P(PSTR(" Request %d, state %d"), (intptr_t) *it, (*it)->_parseState);
      if ((*it)->_response) {
        auto r = (*it)->_response;
        Serial.printf_P(PSTR(" -- Response %d, state %d, [%d %d - %d %d %d]"), (intptr_t) r, r->_state, r->_headLength, r->_contentLength, r->_sentLength, r->_ackedLength, r->_writtenLength);
      }
      Serial.println();
    }
}