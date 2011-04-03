#include "http_packet.hpp"
#include <iostream>
#include <stdlib.h>
#include <cstring>

#define CALLME(METHOD) \
cout<<"Method name is "<<METHOD




void to_lower(string &str){
    
    const int length = str.length();
	for(int i=0; i < length; ++i)
        str[i] = std::tolower(str[i]);
}


bool HttpPacket::isComplete()
{
 // cout<<"message complete is "<<m_complete<<endl;
  return m_complete;
}



string HttpPacket::from()
{
  return m_from;
}

string HttpPacket::getpayload()
{
  return payload;
}

void HttpPacket::setpayload(char *content)
{
    this->payload = (string)content;
}

string HttpPacket::to()
{
  return m_to;
}

string HttpPacket::path()
{
  return m_path;
}

string HttpPacket::url()
{
  return m_url;
}


string  HttpPacket::query()
{
  return m_query;
}

string  HttpPacket::body()
{
  return m_body;
}


HeaderMap HttpPacket::headers() 
{
  return m_headers;
}

string HttpPacket::host()
{
  return get_header("host");
}

string HttpPacket::method()
{
  return http_method_str((enum http_method) m_parser->method);
}

string HttpPacket::user_agent()
{
  return get_header("user-agent");
}

string HttpPacket::cookies()
{
  return get_header("cookie");
}

void HttpPacket::add_header(string name, string value)
{
  //CALLME("add_header");  
  HeaderMap::iterator iter;
  string semi = ";";
  iter = m_headers.find(name);
  if (iter == m_headers.end()) {
    m_headers[name] = value;
  } else {
    // FIXME: Technically this is allowed in certain situations, but I doubt 
    // any browsers would do this.
    // http://github.com/ry/node/blob/master/lib/http.js#L219
   // cerr << "Ignoring duplicate header: " << name << endl;
   // cerr << "  Old: " << m_headers[name] << endl;
   // cerr << "  New: " << value << endl;
   //value.append(semi)
  }
}

string HttpPacket::get_header(string name)
{ 
  //CALLME("get_header");  
  HeaderMap::iterator iter;
  iter = m_headers.find(name);
  if (iter != m_headers.end())
    return iter->second;
  else
    return string();
}

int HttpPacket::path_cb(const char *buf, size_t len)
{
  //CALLME("path_cb");  
  m_path.append(buf,len);
    
  //cout<<buf<<endl;
  return 0;
}

int HttpPacket::query_string_cb(const char *buf, size_t len)
{
  //CALLME("query_string_cb");
  
  //cout<<"size is "<<m_query.size()<<endl;
  //cout<<"m_query is "<<m_query<<endl;
  m_query.append(buf,len);

  return 0;
}

int HttpPacket::header_field_cb(const char *buf, size_t len)
{
  //CALLME("header_field_cb");  
  string str(buf, len);
  ::to_lower(str);
  
  if (!m_tmp_header_value.empty()) {
    add_header(m_tmp_header_name, m_tmp_header_value);
    m_tmp_header_name.clear();
    m_tmp_header_value.clear();
  }
  
  
    m_tmp_header_name = str;
  
  //cout<<str<<endl;
  return 0;
}

int HttpPacket::header_value_cb(const char *buf, size_t len)
{
  //CALLME("header_value_cb");
  if(m_tmp_header_value.empty())
    m_tmp_header_value = string(buf,len);
  else
    m_tmp_header_value.append(buf, len);
    
   // cout<<buf<<endl;
  return 0;
}

int HttpPacket::headers_complete_cb()
{ 
    
  //CALLME("headers_complete_cb");  
  if(!m_tmp_header_value.empty()) {
    add_header(m_tmp_header_name, m_tmp_header_value);
    m_tmp_header_name.clear();
    m_tmp_header_value.clear();
  }
  return 1; // Skip body
}
    
int HttpPacket::message_complete_cb()
{
  //CALLME("setting message_complete_cb");  
  m_complete = 1;
  return 0;
}

int HttpPacket::url_cb(const char *buf, size_t len){
    
    //CALLME("url_cb callback");
    
   
    m_url.append(buf,len);
    
   // cout<<buf<<endl;

    return 0;
}

int HttpPacket::body_cb(const char *buf, size_t len){
    
    //CALLME("url_cb callback");
    
   
    m_body.append(buf,len);
    
   // cout<<buf<<endl;

    return 0;
}

int HttpPacket::message_begin_cb(){
    
    //CALLME("message begin callback");
    return 0;
}

HttpPacket::HttpPacket(string from, string to) : m_from(from), m_to(to), m_complete(false){
    
    
    
    m_settings = (http_parser_settings*)malloc(sizeof(http_parser_settings));
    if(m_settings == NULL){
        cout<<"[m_settings] memory allocation error"<<endl;
        exit(1);
        //return EXIT_FAILURE;
    }
    m_settings->on_header_field     = header_field_cb_wrapper;
    m_settings->on_header_value     = header_value_cb_wrapper;
    m_settings->on_path             = path_cb_wrapper;
    m_settings->on_query_string     = query_string_cb_wrapper;
    m_settings->on_headers_complete = headers_complete_cb_wrapper;
    m_settings->on_message_complete = message_complete_cb_wrapper;
    m_settings->on_message_begin    = message_begin_cb_wrapper;
    m_settings->on_url              = url_cb_wrapper;
    m_settings->on_fragment         = 0;
    m_settings->on_body             = body_cb_wrapper;

    m_parser = (http_parser*)malloc(sizeof(http_parser));
    if(m_parser == NULL){
        cout<<"[m_parser] memory allocation error"<<endl;
        exit(1);
        //return EXIT_FAILURE;
    }
    http_parser_init(m_parser, HTTP_BOTH);
    m_parser->data = this;
}

bool HttpPacket::parse(const char *payload, int payload_size){
    
    if(payload_size > 0){
        //cout<<"parsing .....\n";
        int len = http_parser_execute(m_parser, m_settings, payload, payload_size);
        //cout<<"parsing completed\n";
        //cout<<"return len is "<<len<<" original size is "<<payload_size<<"\n";
        //cout<<"parser state is "<<(unsigned int)m_parser->state<<"\n";
        
        return ((unsigned int)m_parser->state != 1 && len == payload_size);
    }
    return false;
}
