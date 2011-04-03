#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include <string>
#include <iostream>
#include "http_packet.hpp"

using namespace std;

typedef map<string, HttpPacket *> PacketCacheMap;

class PacketSniffer{
    
    public:
        PacketSniffer(string intface, string filter, http_packet_cb callback);
        void start();
    private:
        string m_intface;
        string m_filter;
        PacketCacheMap m_pending_packets;
        void got_packet(const struct pcap_pkthdr *header, const u_char *packet);
    protected:  
    http_packet_cb m_callback;  
    static void packet_wrapper(u_char *user, const struct pcap_pkthdr *header, const u_char *packet){
        PacketSniffer *sniffer = (PacketSniffer*) user;
        sniffer->got_packet(header,packet);
    }
    
};

#endif
