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

bool ON_STA_FILTER(AsyncWebServerRequest *request) {
  return WiFi.localIP() == request->client()->localIP();
}

bool ON_AP_FILTER(AsyncWebServerRequest *request) {
  return WiFi.localIP() != request->client()->localIP();
}

AsyncWebServer::AsyncWebServer(uint16_t port, size_t parallelRequests, size_t maxRequests)
  : AsyncWebServer(IPADDR_ANY, port, parallelRequests, maxRequests)
{
}

AsyncWebServer::AsyncWebServer(IPAddress addr, uint16_t port, size_t parallelRequests, size_t maxRequests)
  : _server(addr, port)
  , _rewrites([](AsyncWebRewrite* r){ delete r; })
  , _handlers([](AsyncWebHandler* h){ delete h; })
  , _requestQueue(LinkedList<AsyncWebServerRequest*>::OnRemove {})
  , _parallelRequests(parallelRequests)
  , _maxRequests(maxRequests)
{
  _catchAllHandler = new AsyncCallbackWebHandler();
  if(_catchAllHandler == NULL)
    return;
  _server.onClient([this](void *s, AsyncClient* c){
    if(c == NULL)
      return;
    c->setRxTimeout(3);
    
    AsyncWebServerRequest *r = new AsyncWebServerRequest((AsyncWebServer*)s, c);
    if(r == NULL){
      c->close(true);
      c->free();
      delete c;
      return;
    }

    if (!_maxRequests || _requestQueue.length() < _maxRequests) {
      _requestQueue.add(r);
    } else {
      // Immediately send a try-again-later response 
      AsyncWebServerResponse *response = r->beginResponse(503);
      if(!response){
        c->close(true);
        c->free();
        delete c;
        return;
      } 
      response->addHeader(F("Retry-After"), F("1"));
      r->send(response);
    }
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

bool AsyncWebServer::_isQueued(AsyncWebServerRequest *request){
  if (!_parallelRequests) return false;
  // Find ordinal of element in queue
  auto it = _requestQueue.begin();
  auto end = _requestQueue.end();
  auto i = 0U;
  while ((i < _parallelRequests) && (it != end)) {
    if (*it == request) return false;
    ++i, ++it;
  }
  return true;
}

void AsyncWebServer::_dequeue(AsyncWebServerRequest *request){
  _requestQueue.remove(request);

  // Start someone else, if need be
  if (_parallelRequests) {
    auto it = _requestQueue.begin();
    auto end = _requestQueue.end();
    auto i = 0U;
    while ((i < _parallelRequests) && (it != end)) {
      // Do something to tell the request it's OK to proceed
      (*it)->_onReady();
      ++i, ++it;
    }
  }

}
