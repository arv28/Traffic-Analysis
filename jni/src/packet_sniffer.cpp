#include "../pcapsrc/pcap.h"
#include <stdexcept>
#include <netinet/in.h>
#include <sys/socket.h> 
#include <arpa/inet.h>
#include <net/if_ether.h>
#include "packet_sniffer.hpp"
#include "tcp_ip.h"
#include <cstdlib>
#include <stdlib.h>
#include <sstream>
#include <string>
using namespace std;


PacketSniffer::PacketSniffer(string inetface, string filter, http_packet_cb callback)
    :m_intface(inetface), m_filter(filter), m_callback(callback){ }

string convert(int number)
{
   ostringstream sin;
   sin << number;
   return sin.str();
}    
    
void print_addr(const u_char *addr){
    
    int i = ETHER_ADDR_LEN;
    
    do{
        printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*addr++);
    }while(--i>0);
}


void print_ip(const struct sniff_ip *ip){
    
    char *srcip, *destip;
    srcip = inet_ntoa(ip->ip_src);
    cout<<"Source IP : "<<srcip<<"\n";
    destip = inet_ntoa(ip->ip_dst);
    cout<<"Destination IP : "<<destip<<"\n";
    
}
    
    
void PacketSniffer::start(){
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    //char *net, *mask;
    struct bpf_program fp;
    bpf_u_int32 maskp = 0;     /* subnet mask */
    bpf_u_int32 netp  = 0;     /* ip */
    //struct in_addr addr;
    
    handle = pcap_open_live(m_intface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL)
        throw runtime_error("Error in opening the device\n");
    
    if (pcap_lookupnet(m_intface.c_str(), &netp, &maskp, errbuf) == -1)
        throw runtime_error("couldn't get ip/netmask for the device\n");
    
    /*addr.s_addr = netp;
     net = inet_ntoa(addr);
     if(net != NULL)
        cout<<net<<"\n";
     addr.s_addr = maskp;
     mask = inet_ntoa(addr);
     if(mask != NULL)
        cout<<mask<<"\n";*/
    if(pcap_compile(handle, &fp, (char*)m_filter.c_str(),0,netp) == -1)
        throw runtime_error("couldn't parse filter\n");
    if(pcap_setfilter(handle, &fp) == -1)
        throw runtime_error("Error installing filter");
    
    pcap_loop(handle, 0, packet_wrapper, (u_char*) this);
    
    pcap_freecode(&fp);
    pcap_close(handle);  
    
    
    
}

void PacketSniffer::got_packet(const struct pcap_pkthdr *header, const u_char *packet){
    
    const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	char *payload; /* Packet payload */
    //const char *buffer;
    const u_char *destaddr, *srcaddr;
    int payload_size, ip_len;
    u_int size_ip;
	u_int size_tcp;
    string from, to, sep = ":", key;
    HttpPacket *http_packet = 0;
    
    if(packet == NULL){ 
        throw runtime_error("Packet is NULL");
    }  
    
    //cout<<"-------------------------------------------------------------------------\n"; 
    //cout<<"Packet length is "<<header->len<<"\n";
    //cout<<"Received at....."<<ctime((const time_t*)&header->ts.tv_sec)<<"\n";
    
    ethernet = (struct sniff_ethernet *) packet;
    /*if(ntohs(ethernet->ether_type) == ETHERTYPE_IP)
        cout<<"Ethernet type is IP Packet\n";
    else if(ntohs(ethernet->ether_type == ETHERTYPE_ARP))   
        cout<<"Ethernet type is ARP Packet\n";
    else
        cout<<"Different packet\n";
    
    cout<<"source address :";
    srcaddr = (const u_char*)ethernet->ether_shost;
    ::print_addr(srcaddr);
    cout<<"\n";
    cout<<"destination address:";
    destaddr = (const u_char*)ethernet->ether_dhost;
    ::print_addr(destaddr);
    
    cout<<"\n";
    */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    ip_len = ntohs(ip->ip_len);
    if(size_ip < 20)
        throw runtime_error("IP header length less than 20 bytes\n");
    if (!(ip && ip->ip_p == IPPROTO_TCP))
    return;
    //::print_ip(ip);
    from = string(inet_ntoa(ip->ip_src)); from.append(sep);
    to = string(inet_ntoa(ip->ip_dst)); to.append(sep);
    //cout<<"IP protocol is "<<(unsigned int)ip->ip_p;
    //cout<<"\n";
    
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;
    if(size_tcp < 20)
        throw runtime_error("TCP header length less than 20 bytes\n");
    payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    //cout<<"source port is "<<ntohs(tcp->th_sport)<<"\n";
    //cout<<"Destination port is "<<ntohs(tcp->th_dport)<<"\n";
    
    from.append(::convert(ntohs(tcp->th_sport)));
    
    to.append(::convert(ntohs(tcp->th_dport)));
    //cout<<from<<"\n";
    //cout<<to<<"\n";
    //cout<<payload;
    payload_size =  ip_len - (size_ip + size_tcp);
    //cout<<"payload size is " <<payload_size;
    key.append(from);
    key.append("-");
    key.append(to);
   // cout<<"key is"<<key;
   
   http_packet = new HttpPacket(from, to);
   
   if(http_packet->parse(payload, payload_size)){
       
       if(http_packet->isComplete()){
           http_packet->setpayload(payload);
           m_callback(http_packet);
           
        }
        
       
    }
    
    delete http_packet;
    
    
    
    
     
   // cout<<"\n";
   
    //cout<<"----------------------------------------------------------------------\n";
    
    
    
    
    
}








