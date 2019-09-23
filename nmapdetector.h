#ifndef _NMAP_DETECTOR_H
#define _NMAP_DETECTOR_H
#include <stdio.h>
FILE* tmpFile = NULL;
FILE* logFile = NULL;
FILE* statsFile = NULL;
FILE* tempStatsFile = NULL;
FILE * detectionsFile = NULL;
#ifdef __linux__
int raw_sock = -1;
#define IS_SYN(tcp) ((tcp)->syn)
#define IS_RST(tcp)  ((tcp)->rst)
#define IS_FIN(tcp)  ((tcp)->fin)
#define IS_ACK(tcp)  ((tcp)->ack)
#define IS_PUSH(tcp)  ((tcp)->psh)
#define IS_URG(tcp)  ((tcp)->urg)
#define GET_SADDR(ip) ((ip)->saddr)
#else
#include <pcap.h>
pcap_t * handle = NULL;
#define IS_SYN(tcp) ((tcp)->th_flags & TH_SYN)
#define IS_RST(tcp) ((tcp)->th_flags & TH_RST)
#define IS_FIN(tcp) ((tcp)->th_flags & TH_FIN)
#define IS_ACK(tcp) ((tcp)->th_flags & TH_ACK)
#define IS_PUSH(tcp) ((tcp)->th_flags & TH_PUSH)
#define IS_URG(tcp) ((tcp)->th_flags & TH_URG)
#define GET_SADDR(ip) ((ip)->ip_src.s_addr)
#endif
#endif