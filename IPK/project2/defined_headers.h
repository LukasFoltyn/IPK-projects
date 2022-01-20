/** Project: IPK Packet sniffer **/
/** File: defined_headers.h    **/
/** Author: Lukas Foltyn       **/

#include <pcap.h>
#include <netinet/ether.h>

#ifndef DEFINED_HEADERS_H
#define DEFINED_HEADERS_H

/*
Title: Structure for ARP header format
Date of retrieval - 20.3.2021
URL: https://stackoverflow.com/questions/41403445/how-to-structure-and-arp-request-packet-in-c?fbclid=IwAR1fyR2T8IR-8zh52YMvLBq-gQdGccLArsR1Yg3Ncbiqi4VhYVVcx9SY38k
*/

/* Ethernet ARP packet header */
typedef struct {
   uint16_t htype;   /* Format of hardware address */
   uint16_t ptype;   /* Format of protocol address */
   uint8_t hlen;    /* Length of hardware address */
   uint8_t plen;    /* Length of protocol address */
   uint16_t op;    /* ARP opcode (command) */
   uint8_t sha[ETH_ALEN];  /* Sender hardware address */
   uint32_t spa;   /* Sender IP address */
   uint8_t tha[ETH_ALEN];  /* Target hardware address */
   uint32_t tpa;   /* Target IP address */
} __attribute__((packed)) arphdr_t;

/* IPV6 Authentication header */
typedef struct {
   uint8_t nxt_hdr; /* next header */
   uint8_t pld_len; /* playload lenght */
   uint16_t res; /* reserved */
   uint32_t sec_param_idx; /* security parameteres index */
   uint32_t seq; /* sequence number */
   uint32_t ah_data; /* authentication data */
} __attribute__((packed)) ahhdr_t;

#endif
