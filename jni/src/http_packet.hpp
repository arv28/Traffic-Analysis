#ifndef HTTP_PACKET_H
#define HTTP_PACKET_H

#include <string>
#include <map>
#include <stdlib.h>
#include "http-parser/http_parser.h"
using namespace std;



typedef map<string, string> HeaderMap;
#define HTTP_PARSER_DATA_CALLBACK(NAME)                                             \
static int NAME##_cb_wrapper (http_parser *parser, const char *buf, size_t len) {   \
  HttpPacket *packet = (HttpPacket*)parser->data;                                      \
  return packet->NAME##_cb(buf, len);                                               \
}                                                                                   \
int NAME##_cb(const char *buf, size_t len);

#define HTTP_PARSER_CALLBACK(NAME)                    \
static int NAME##_cb_wrapper (http_parser *parser) {  \
  HttpPacket *packet = (HttpPacket*)parser->data;          \
  return packet->NAME##_cb();                         \
}                                                     \
int NAME##_cb();

class HttpPacket {
    
    public:
        HttpPacket(string from, string to);
        ~HttpPacket(){
            
            
            if(m_parser != NULL)
                free(m_parser);
           if(m_settings != NULL)
                free(m_settings);
            
        }
        bool parse(const char *payload, int payload_size);
        bool isComplete();
        string from();
        string to();
        string host();
        string method();
        string url();
        string path();
        string user_agent();
        string query();
        string cookies();
        string getpayload();
        string body();
        void setpayload(char *buffer);
        HeaderMap headers();
        
        
    private:
        http_parser *m_parser;
        http_parser_settings *m_settings;
        string m_from;
        string m_to;
        string m_url;
        string m_path;
        string m_body;
       // string m_query;
        HeaderMap m_headers;
        string m_tmp_header_name;
        string m_tmp_header_value;
        string payload;
        bool m_complete;
        
        string m_query;
       
        HTTP_PARSER_DATA_CALLBACK(query_string);
        
  HTTP_PARSER_DATA_CALLBACK(url);
  HTTP_PARSER_DATA_CALLBACK(body);
  HTTP_PARSER_DATA_CALLBACK(header_field);
  HTTP_PARSER_DATA_CALLBACK(header_value);
  HTTP_PARSER_DATA_CALLBACK(path);
  
  HTTP_PARSER_CALLBACK(headers_complete);
  HTTP_PARSER_CALLBACK(message_complete);
  HTTP_PARSER_CALLBACK(message_begin); 
        
        
        void add_header(string name, string value);
        string get_header(string name);
};

typedef void (*http_packet_cb) (HttpPacket*);

#endif
