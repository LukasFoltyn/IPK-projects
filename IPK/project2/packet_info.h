/** Project: IPK Packet sniffer **/
/** File: packet_info.h        **/
/** Author: Lukas Foltyn       **/

// network libraries
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>


// standard c and c++ libraries
#include <iostream>
#include <ctime>
#include <unistd.h>
#include <stdlib.h>
#include <string>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <cstring>

#ifndef PACKET_INFO_H
#define PACKET_INFO_H

// packet bytes that are ptinted on one line (hexadecimal and ascii characters)
#define ONE_L_LENGHT 16
// maximum bytes that can by captured in one packet
#define MAXBYTES2CAPTURE 65535

// offsets for getting parts of IPV4 (uint_32)
#define P1_IPV4(ip) (ip & 0x000000ff) 
#define P2_IPV4(ip) ((ip & 0x0000ff00) >> 8)
#define P3_IPV4(ip) ((ip & 0x00ff0000) >> 16)
#define P4_IPV4(ip) ((ip & 0xff000000) >> 24)
#define EIGHT_OCTETS 8
#define DOUBLEWORD_TO_BYTES_SHIFT 2
#define QUADWORD_TO_BYTES_SHIFT 3

/**
* @class PacketInfo
* @brief class for parsing packets and extracting certain information
**/
class PacketInfo {
    private:
        /** pointer to the packet data **/
        const u_char *packet_data;
        /** structure that keeps lenght of packet and time when the packt was received **/
        const pcap_pkthdr *pcap_header;
    public:

        /**
         * @brief simple constructor 
         * @param pckt_data pointer to array of bytes representing packet
         * @param header pointer to struct, that keeps basic info about the packet
         **/
        PacketInfo(const u_char * pckt_data, const pcap_pkthdr *header) : packet_data{pckt_data}, pcap_header{header} {}
        
        /**
         * @brief functions that determines network protocol of a packet
         * @return uint16_t representing network protocol according to a standard
         **/
        uint16_t get_network_protocol() const;
        
        /**
         * @brief functions that determines transport protocol of a packet
         * @return uint8_t representing transport protocol according to a standard
         **/
        uint8_t get_transport_protocol() const;
        
        /**
         * @brief functions that determines on which byte starts the transport header
         * @return const u_char* position of tranposrt layer header
         **/
        const u_char *get_transport_header() const;
        
        /**
         * @brief functions that determines on which byte starts the network header
         * @return const u_char* position of network layer header
         **/
        const u_char *get_network_header() const;
        
        /**
         * @brief function that extracts the source ip address from packet
         * @return std::string representing source ip address
         **/
        std::string get_source_ip() const;
        
        /**
         * @brief function that extracts the destination ip adrdress from packet
         * @return std::string representing destination ip adress
         **/
        std::string get_destination_ip() const;
        
        /**
         * @brief function that extracts the source port from packet in transport layer header 
         * @return std::string representing source port
         **/
        std::string get_source_port() const;
        
        /**
         * @brief function that extracts the destination port from packet in transport layer header
         * @return std::string representing destination port
         **/
        std::string get_destination_port() const;
        
        /**
         * @brief function that creates timestamp when packet was received according to RFC3339 format
         * @return std::string representing timestamp of received packet
         **/
        std::string get_timestamp() const;
        
        /**
         * @brief function that prints basic info about the packet 
         * and then the packet itself to stdout, non-printable characters are subtituted by dot ('.')
         **/
        void print_packet() const;
};

/**
 * @class UnexpectedProtocol
 * @brief simple class for throwing an exception if unexpected protocol ocurres
 **/
class UnexpectedProtocol : public std::exception {
    public:
        
        /**
         * @brief overidden function that creates a string describing the thrown exception
         * @return const char * representing exception message
         **/
        virtual const char * what() const noexcept { return "Unexpected protocol occured!"; }
};

#endif
