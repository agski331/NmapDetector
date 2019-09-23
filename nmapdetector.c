#include <stdio.h>  //printf, vprintf, fvprintf etc
#include <math.h> //pow   
#include <time.h> //time_t, time
#include <string.h> //strcpy, sprintf
#include <stdlib.h> //size_t
#include <stdarg.h> //va_list, va_start
#include <limits.h>
#include <signal.h>
#include "nmapdetector.h" //global variabless
#include "utils.h" //getMainAdapterDesc, getMainAdapterAddr
#include "file-io.h" //logSyn, logFin, logRst, setProperty, getProperty
#include "ArrayList.h" //ArrayList, add, remove, contains

#ifdef _INCLUDE_STDBOOL
#include <stdbool.h> //stdbool probably isnt very needed considering it only defines values, could define them myself
#endif
//ex of above:
//#define true 1
//#define false 0
//#define bool int 

#if !(defined _WIN32 || defined _WIN64)
#include <arpa/inet.h> //inet_ntop for bsd and linux
#else
#ifndef WIN32_LEAN_AND_MEAN //I dont want all the crap from Windows.h
#define WIN32_LEAN_AND_MEAN
#endif
#include <WinSock2.h> 
#include <WS2tcpip.h> 
#include <iphlpapi.h> 
#include <Windows.h>
#include <Shlwapi.h>

#pragma comment(lib, "librtbtstuff.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wpcap.lib")
#endif
//#define _DEBUG_MAIN
#define _DEBUG_ADDR "192.168.160.129"

#ifndef __linux__
#include <pcap.h>
#else
//linux includes
#include <sys/socket.h>
#include <unistd.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#endif


//honestly this works well enough where id be confident using it, going to suspend work once i verify it works on 
//bsd and windows, and start working on the filesystem detections and possibly a reverse shell

void beginListening(long* lastDetect, FILE* dataFile, FILE* logFile, FILE* statsFile, FILE* statsLogFile, FILE * detectionsFile);
void handleUdp(struct iphdr* iphdr, char * hostIpAddr, long* lastDetect, FILE* dataFile, FILE* logFile, FILE* statsFile, FILE* statsLogFile);
bool possibleScan(char* ipaddr, time_t ts, int type, FILE* dataFile);
bool isIterativeScan(char* ipaddr, int type, FILE* dataFile);
double standardDeviation(Timestamps* timestamps);

typedef struct {
	long * lastDetect;
	FILE * dataFile;
	FILE * logFile;
	FILE * statsFile;
	FILE * statsLogFile;
	FILE * detectionsFile;
	bool * running;
} thread_args;

#ifndef __linux__
pcap_if_t* getInterfaceFromDesc(pcap_if_t * ifa, char* desc);
#endif

#if (defined _WIN32 || defined _WIN64)
void PrintCSBackupAPIErrorMessage(DWORD dwErr);
#endif

static void sigint_handler(int signo) {
	signal(SIGINT, SIG_DFL);
	printf("\nUnregistered signal handlers.\n");
	printf("Exitting Program.\n");
	printf("Closing files and cleaning temporary files\n");
	if(logFile != NULL)
		fclose(logFile);
	if(tmpFile != NULL)
		fclose(tmpFile);
	if(statsFile != NULL)
		fclose(statsFile);
	if(tempStatsFile != NULL)
		fclose(tempStatsFile);
	if(detectionsFile != NULL)
		fclose(detectionsFile);
	remove("stats.txt");
	remove("datafile.txt");
#ifndef __linux__
	if(handle != NULL)
		pcap_close(handle);
#else
	if(raw_sock != -1){
		close(raw_sock);
	}
#endif
	printf("Goodbye\n");
	exit(0);
}

//making a udp monitor work will require massive changes, including synchronizing all file io functions to 
//prevent race conditions..... im going to focus on getting this stuff working first.
int main() {
#if (defined _WIN32 || defined _WIN64)
	char nmapDllPath[] = "C:\\Windows\\System32\\Npcap";
	if (!PathFileExistsA(nmapDllPath)) {
		printf("Npcap is not installed.  Please install to continue.\n");
		return -1;
	}

	if (SetDllDirectory(nmapDllPath) == 0) {
		printf("Unable to set dll directory %x\n", GetLastError());
		return -1;
	}

#endif
	signal(SIGINT, sigint_handler);
	tmpFile = fopen("datafile.txt", "a+");
	logFile = fopen("log.txt", "a+");
	statsFile = fopen("statslog.txt", "a+");
	tempStatsFile = fopen("stats.txt", "a+");
	detectionsFile = fopen("detections.txt", "a+");
	printf("Nmap Scan analyzer for libpcap vBETA 1\n"); //change this
	long* lastDetect = (long*)malloc(sizeof(long));
	if (lastDetect == 0) {
		printf("Unable to allocate lastDetect var\n");
		return -1;
	}
	memset(lastDetect, 0, sizeof(long)); //make sure the lastDetect is zero
	printf("Starting\n");
	//this is the beginning of pthread implementation
	//could technically use a lock on a vprintf func
	//and then have that do printing operations
	//doing this will require synchronization of funcs in file-io.h so im going
	//to wait a bit until i fix the rest of this crap
	thread_args args;
	args.dataFile = tmpFile;
	args.logFile = logFile;
	args.statsFile = tempStatsFile;
	args.statsLogFile = statsFile;
	args.detectionsFile = detectionsFile;
	bool * runningBool = (bool*) malloc(sizeof(bool));
	args.running = runningBool;
	beginListening(lastDetect, tmpFile, logFile, tempStatsFile, statsFile, detectionsFile);
	return 0;
}

void beginListening(long* lastDetect, FILE* dataFile, FILE* logFile, FILE* statsFile, FILE* statsLogFile, FILE * detectionsFile) 
{
#ifndef __linux__
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
#endif
	printf("Getting host ip address.\n");
	char * hostIpAddr = getHostIpAddr();
	printf("Host ip address has been detected as %s.  Is that correct (y/n): ", hostIpAddr);
	char input = '0'; //just some random value here
	while (true) {
		input = fgetc(stdin);
		if (input == 'y') {
			break;
		}
		else if (input == 'n') {
			printf("Please enter the correct IP Address: ");
			while (true) {
				hostIpAddr = getLine(stdin);
				if (strlen(hostIpAddr) != INET_ADDRSTRLEN) {
					printf("Invalid ip address.  Please enter a valid ip address: ");
				}
				else {
					break;
				}
			}
			printf("\nHost ip addr is %s\n", hostIpAddr);
			break;
		}
		else {
			printf("Invalid input.  Please try again. (y/n): ");
		}
	}
#ifndef __linux__
	pcap_if_t* ifa; 
#if (defined _WIN32 || defined _WIN64)
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &ifa, errbuf) == -1) {
		printf("error with pcap_findalldevs_ex: %s\n", errbuf);
		return;
	}
#else
	if(pcap_findalldevs(&ifa, errbuf) == -1){
		printf("Error with pcap_findalldevs: %s\n", errbuf);
		return;
	}
#endif
	char* mainAdapterDesc = getMainAdapterDesc();
	printf("Main adapter name has been detected as %s\n", mainAdapterDesc);
	printf("Opening packet capture handle.\n");
	pcap_if_t* mainAdapter = getInterfaceFromDesc(ifa, mainAdapterDesc);
	if(mainAdapter == NULL){
		printf("Main adapter has been detected as null\n");
		return;
	}
	handle = pcap_open_live(mainAdapter->name, 65536, 1, 0, errbuf);
	pcap_freealldevs(ifa);
	if (handle == NULL) {
#else //rawsock version
	raw_sock = socket(AF_INET,  SOCK_RAW, IPPROTO_TCP); //create a raw socket, listen to ipv4 only (linux specific)
    if(raw_sock == -1){
#endif
		perror("Failed to open listener"); //change this as well
	} else {
		ArrayList* list = create(); //create an arraylist struct to store ip addrs for open port syn scan detection
		int detections = 0; //amount of detections (not entirely used)
		printf("Starting capture loop\n");
		while (true) {
			bool detected = false;
#ifndef __linux__
			const unsigned char* packet = pcap_next(handle, &header);
			struct iphdr* ipPacket = (struct iphdr*) (packet + 14); //set addr of a iphdr struct to packet + 14 because ethernet header is still in with libpcap
			if (ipPacket->ip_p == IPPROTO_UDP) {
				handleUdp(ipPacket, hostIpAddr, lastDetect, dataFile, logFile, statsFile, statsLogFile); //move logUdp in this func
				continue;
			}
			else if (ipPacket->ip_p != IPPROTO_TCP) {
				continue;
			}
			unsigned int iphdrBytesSize = IP_HL(ipPacket) * 4; // get length of ip header in bytes
			struct tcphdr* tcp = (struct tcphdr*)(packet + 14 + iphdrBytesSize); // tcphdr = iphdr addr + len of ip hdr (should be 34 for default configuration syn scans)
			if (IP_V(ipPacket) != 4) {
				continue; //currently our headers only work for ipv4 (although version should work since they are at the same place in the header)
			}
#else
			unsigned char* packet = (unsigned char*)malloc(sizeof(unsigned char) * 65536);
			int packetSize = recvfrom(raw_sock, packet, 65536, 0, NULL, NULL);
			if (packetSize == -1) {
				perror("error reading packet from raw socket.\n");
				continue;
			}
			//of note: if packet contains the ethernet header, we may need to add 14 onto this. best be done with some testing.
			struct iphdr* ipPacket = (struct iphdr*) packet;
			if(ipPacket->version != 4){
				free(packet);
				continue;
			}
#ifndef __linux__
			if(ipPacket->protocol == IPPROTO_UDP){
				handleUdp(ipPacket, hostIpAddr, lastDetect, dataFile, logFile, statsFile, statsLogFile);
				free(packet);
				continue;
			}else if(ipPacket->protocol != IPPROTO_TCP){
				free(packet);
				continue;
			}
#else
            if(ipPacket->protocol != IPPROTO_TCP){
				free(packet);
				continue;
			}
#endif

			unsigned int iphdrBytesSize = ipPacket->ihl * 4;
			struct tcphdr* tcp = (struct tcphdr*) (packet + iphdrBytesSize);
#endif
			char* addr = (char*)malloc(sizeof(char) * INET_ADDRSTRLEN);
			char* destAddr = (char*)malloc(sizeof(char) * INET_ADDRSTRLEN);
#ifndef __linux__
			inet_ntop(AF_INET, &(ipPacket->ip_src), addr, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &(ipPacket->ip_dst), destAddr, INET_ADDRSTRLEN);
#else
			inet_ntop(AF_INET, &ipPacket->saddr, addr, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &ipPacket->daddr, destAddr, INET_ADDRSTRLEN);
#endif
            time_t ts = time(NULL); //timestamp to be used for this purpose



#ifdef _DEBUG_MAIN
			if (strcmp(addr, _DEBUG_ADDR) != 0) {
#ifdef __linux__
				free(packet);
#endif
				free(destAddr);
				free(addr);
				continue;
			}
#endif



			if (strcmp(destAddr, hostIpAddr) != 0 && strcmp(destAddr, "127.0.0.1") != 0) {
#ifdef __linux__
				free(packet);
#endif
				free(destAddr);
				free(addr);
				continue;
			}

#ifndef __linux__
			int port = ntohs(tcp->th_dport); // get a readable form of the destination port
#else
			int port = ntohs(tcp->dest);
#endif
			if (IS_SYN(tcp)) {
				//logSyn(addr, port, dataFile, logFile, statsFile, statsLogFile); // log the syn in the logfiles
				if (!contains(list, GET_SADDR(ipPacket))) { //if the list contains this already its probably some sort of mistake
					add(list, GET_SADDR(ipPacket)); //add the uint32_t representation of the saddr to the list
				}
			}else {
				if (IS_RST(tcp)) {
					//logRst(addr, port, dataFile, logFile, statsFile, statsLogFile); // log the rst in the logfiles
					if (contains(list, GET_SADDR(ipPacket))) { //if the list has a syn and then immediately gets a rst
						detections++;
						//this also seems to flag full connect scans where the conection is denied.
						//SYN scans consist of a syn, if port is open an rst is immediately sent back. as long as no fucky things
						// are going on id assume this is a near 100% detection rate.
						//printf("Detected a probable SYN Scan attempt on port %d from %s.  Amt detected: %d\n", port, addr, detections);
						if(logDetection(addr, SCAN_SYN, ts, detectionsFile) < 0){
							printf("Error logging syn scan detection from ip addr %s\n", addr);
						}
						*lastDetect = time(NULL);
						removeItem(list, GET_SADDR(ipPacket)); // remove the saddr from the arraylist - weve already detected it
						detected = true;
					}

				} else {
					if (!tcp) {
						//this may not work because the header wouldnt all be zeroes. test.
						//the theory behind this is if the entire header is zero it is a null scan, i wonder if the port bits would be set tho.
						//printf("Possible null scan attempt detected from %s on port %d.\n", addr, port);
						if(logDetection(addr, SCAN_NULL, ts, detectionsFile) < 0){
							printf("error logging null scan detection from ip addr %s\n", addr);
						}
						*lastDetect = time(NULL);
						detected = true;
					} else {
						if (IS_FIN(tcp)) {
							//logFin(addr, port, dataFile, logFile, statsFile, statsLogFile); // log the fin here
							if (IS_PUSH(tcp) && IS_URG(tcp)) {
								//xmas scans have the fin, psh and urg set to 1.  this is most likely a near 100% detect rate.
								//printf("Possible xmas scan attempt detected from %s on port %d.\n", addr, port);
								if(logDetection(addr, SCAN_XMAS, ts, detectionsFile) < 0){
									printf("Error logging xmas scan detection from ip addr %s\n", addr);
								}
								*lastDetect = time(NULL);
								detected = true;
							}
							else if (IS_ACK(tcp)) {
								//maimon scans only have fin and ack bits set
								//printf("Possible Maimon scan attempt detected from %s on port %d.\n", addr, port);
								if(logDetection(addr, SCAN_MAIMON, ts, detectionsFile) < 0){
									printf("Error logging maimon scan from ip addr %s\n", addr);
								}
								*lastDetect = time(NULL);
								detected = true;
							}
							else {
								//check the timestamps of fin sending statistics here
								//account for fin scans here.
							}
						}else {
							if (IS_ACK(tcp)) {
								//check for ACK scan here
								//probably going to need to rely on statistics as ack is a common packet.
							}
						}
					}
					//if its not a rst then theres no reason to keep it in the list, since syn scans dont send any other packets between syn-rst if open
					if (contains(list, GET_SADDR(ipPacket))) {
						removeItem(list, GET_SADDR(ipPacket));
					}

				}
			}


			//statistic analysis of packets here (need to find a better place for this, not efficient)
			char* propertyName = (char*)malloc(sizeof(char) * 13);//null terminate it to be sure
			if (propertyName == 0) {
				printf("malloc failed to allocate propertyName: closing\n");
				break;
			}

			int type = -1;
			if (IS_SYN(tcp)) {
				type = 1;
				strcpy(propertyName, "syn-packets\0");
			}
			else if (IS_RST(tcp)) {
				type = 2;
				strcpy(propertyName, "rst-packets\0");
			}
			else if (IS_FIN(tcp)) {
				type = 3;
				strcpy(propertyName, "fin-packets\0");
			}
			if (possibleScan(addr, ts, type, dataFile)) {
				//printf("Detected a possible pattern based scan from %s\n", addr);
				if(logDetection(addr, SCAN_GENERIC_PATTERN, ts, detectionsFile) < 0){
					printf("Error logging possible generic pattern of a scan from %s\n", addr);
				}
			}
			//now that this is here, we can do some sort of detection based off of current timestamp and other timestamps
			//for now im going to define a possible scan as any packet that is 1s after the previous one of that type
			if (IS_SYN(tcp)) {
				logSyn(addr, ts, port, dataFile, logFile, statsFile, statsLogFile);
			}
			else if (IS_RST(tcp)) {
				logRst(addr, ts, port, dataFile, logFile, statsFile, statsLogFile);
			}
			else if (IS_FIN(tcp)) {
				logFin(addr, ts, port, dataFile, logFile, statsFile, statsLogFile);
			}


#ifdef __linux__
			free(packet);
#endif
		}
	}
}
//the issue here is with this push the timestamps will be cleared before this is called.... figure out a way to fix that (maybe make logging happen after this is called.)
bool possibleScan(char* ipaddr, time_t ts, int type, FILE* dataFile) {
	Timestamps* synStamps = getTimestampsForIp(type, ipaddr, dataFile); //get all of the syn timestamps from datafile
	if (synStamps == NULL) {
		printf("Timestamps are null. This may mean nothing.\n");
		return false;
	}

	if (synStamps->size == 1) { //dont want to do complex operations every time a packet is recvd
	    freeTimestamps(synStamps);
        return false;
	}

	
	time_t lastTimestamp = getLastTimestamp(type, ipaddr, dataFile);
	char * property;
	switch(type){
		case SYN:
			property = "syn-packets";
			break;
		case FIN:
			property = "fin-packets";
			break;
		case RST:
			property = "rst-packets";
			break;
		case UDP:
			property = "udp-packets";
			break;
		default:
			return false; //invalid args (maybe should have this func return ints for an error code)
	}
	long propertyVal = getProperty(ipaddr, property, statsFile);
	if(lastTimestamp > 0 && ts -  lastTimestamp > 1000 || propertyVal % 30 == 0){
		double dev =  standardDeviation(synStamps);
        freeTimestamps(synStamps);
        return dev < 100;
	}
    freeTimestamps(synStamps);
	return false;
}

double standardDeviation(Timestamps* timestamps) { //calculate the standard deviation of a list of time_t
	time_t total = 0L;
	for (int i = 0; i < timestamps->size; i++) {
		//total += timestamps->info[i]-;
		total += timestamps->pktinfo[i]->timestamp;

	}

	double mean = (double)total / (double)timestamps->size;


	double totalDiff = 0L;
	for (int i = 0; i < timestamps->size; i++) {
		totalDiff += pow((timestamps->pktinfo[i]->timestamp - mean), 2);
	}

	return (double)totalDiff / (double)timestamps->size;
}

//we dont need this function unless its libpcap
#ifndef __linux__
pcap_if_t* getInterfaceFromDesc(pcap_if_t* ifa, char* desc)
{
	pcap_if_t* ptr = ifa;
	if (ifa != NULL) {
		do {
#if (defined _WIN32 || defined _WIN64)
			if (strstr(ptr->description, desc) != NULL) { //this is good enough for now, eventually i would actually parse it in order to ensure accuracy
#else //unix oses
			if(strstr(ptr->name, desc) != NULL){
#endif
				break;
			}
		} while ((ptr = ptr->next) != NULL);
	}

	return ptr;
}

#endif

//windows only function
#if (defined _WIN32 || defined _WIN64)
void PrintCSBackupAPIErrorMessage(DWORD dwErr)
{

	WCHAR   wszMsgBuff[512];  // Buffer for text.

	DWORD   dwChars;  // Number of chars returned.

	// Try to get the message from the system errors.
	dwChars = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dwErr,
		0,
		wszMsgBuff,
		512,
		NULL);

	if (0 == dwChars)
	{
		printf("Error code did not exist in system errors\n");
		// The error code did not exist in the system errors.
		// Try Ntdsbmsg.dll for the error code.

		HINSTANCE hInst;

		// Load the library.
		hInst = LoadLibrary("Ntdsbmsg.dll");
		if (NULL == hInst)
		{
			printf("cannot load Ntdsbmsg.dll\n");
			return; // Could 'return' instead of 'exit'.
		}

		// Try getting message text from ntdsbmsg.
		dwChars = FormatMessage(FORMAT_MESSAGE_FROM_HMODULE |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			hInst,
			dwErr,
			0,
			wszMsgBuff,
			512,
			NULL);

		// Free the library.
		FreeLibrary(hInst);

	}
	wprintf(L"Error Code: %x\nError message: %ls\n", dwErr, wszMsgBuff);
}

#endif

//note: iterative ports might be a decent way to detect basic scanning, add ports to logfiles
void handleUdp(struct iphdr* iphdr, char * hostIpAddr, long* lastDetect, FILE* dataFile, FILE* logFile, FILE* statsFile, FILE* statsLogFile) { //add compiler directives for linux version
	//detect udp scans here, flag beacon traffic
	printf("handling udp\n");
#ifndef __linux__
	int iphdrLen = IP_HL(iphdr) * 4;
#else
	int iphdrLen = iphdr->ihl * 4;
#endif
	struct udphdr* udp = (struct udphdr*) (iphdr + iphdrLen);
	
	char* srcAddr = (char*)malloc(sizeof(char) * INET_ADDRSTRLEN);
	char* destAddr = (char*)malloc(sizeof(char) * INET_ADDRSTRLEN);
#ifndef __linux__
	inet_ntop(AF_INET, &(iphdr->ip_src), srcAddr, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(iphdr->ip_dst), destAddr, INET_ADDRSTRLEN);
#else
	inet_ntop(AF_INET, &(iphdr->saddr), srcAddr, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(iphdr->daddr), destAddr, INET_ADDRSTRLEN);
#endif	


#ifdef _DEBUG_MAIN

	if (strcmp(srcAddr, _DEBUG_ADDR) != 0) {
		free(destAddr);
		free(srcAddr);
		return;
	}
#endif
	//beacons: outgoing traffic
	//scans: incoming traffic
        time_t ts = time(NULL);
	if (strcmp(srcAddr, hostIpAddr) == 0 || strcmp(srcAddr, "127.0.0.1") == 0) {
#ifdef __linux__
		int srcPort = ntohs(udp->source);
#else
		int srcPort = ntohs(udp->sport);
#endif
		logUdp(srcAddr, ts, srcPort, dataFile, logFile, statsFile, statsLogFile);
		//outgoing udp traffic
		printf("Outgoing udp traffic detected with destination %s on port %d\n", destAddr, srcPort);
	}
	else {
		printf("checking incoming udp traffic\n");
#ifdef __linux__
		int destPort = ntohs(udp->dest);
#else
		int destPort = ntohs(udp->dport);
#endif
        time_t lastTimestamp = getLastTimestamp(4, srcAddr, dataFile);
		if(lastTimestamp != 0 && ts - lastTimestamp  > 1000){
			if(possibleScan(srcAddr, ts, 4, dataFile)){
				printf("Possible udp scan detected from %s\n", srcAddr);
			}
		}
		logUdp(srcAddr, ts, destPort, dataFile, logFile, statsFile, statsLogFile);
		//incoming udp traffic
		//make this not fire every udp packet
		/* long prop = getProperty(srcAddr, "udp-packets", statsFile);
		if (prop % 10 == 0) {
			printf("checking possibleScan\n");
			if (possibleScan(srcAddr, 4, dataFile)) {
				printf("Possible scan detected from ip addr %s\n", srcAddr);
			}
			printf("done checking possibleScan\n");
		}

		if (prop % 20 == 0) {
			printf("checking for iterative scan\n");
			if (isIterativeScan(srcAddr, 4, dataFile)) {
				printf("Detected iteration pattern from ip addr %s\n", srcAddr);
			}
			printf("Done checking iterative scan\n");
		}*/

		printf("Done checking incoming udp traffic\n");

	}

	free(srcAddr);
	free(destAddr);
	printf("done handling udp\n");
}
//ports arent scanned in iteration with nmap
bool isIterativeScan(char* ipaddr, int type, FILE* dataFile) {
	/*int minIndex = 0;
	Timestamps* timestamps = getTimestampsForIp(type, ipaddr, dataFile);
	for (int i = timestamps->size - 1; i >= 0; i--) {
		if (i == 0) {
			break;
		}

		if (timestamps->timestamps[i] < timestamps->timestamps[i - 1]) {
			minIndex = i;
			break;
		}
	}

	int minPortNum = timestamps->ports[minIndex];
	for (int i = minPortNum; i <= 65535 && minIndex < timestamps->size; i++) {
		if (timestamps->ports[minIndex] != i) {
			return false;
		}
		minIndex++;
	}

	return true;*/

	return false;
}

//find a better way to determine where to start this.... e.x if a timestamp is marginally greater than another, same with possibleScan
//attempts to detect a pattern by checking if each port was scanned could be considered the start of the scan
bool detectPortPattern(char* ipaddr, int type, FILE* dataFile) {
	Timestamps* timestamps = getTimestampsForIp(type, ipaddr, dataFile);
	int startIndex = -1;
	for (int i = timestamps->size - 1; startIndex == -1 && i > 0; i++) {
		time_t difference = timestamps->pktinfo[i]->timestamp - timestamps->pktinfo[i - 1]->timestamp;
		if (difference > 1000) {
			startIndex = i;
		}
	}

	if (startIndex == -1) {
		printf("could not determine a port pattern for ipaddr %s and type %d\n", ipaddr, type);
		return false;
	}

	int minPort = INT_MAX;
	int maxPort = INT_MIN;
	for (int i = startIndex; i < timestamps->size; i++) {
		if (timestamps->pktinfo[i]->port > maxPort) {
			maxPort = timestamps->pktinfo[i]->port;
		}
		else if (timestamps->pktinfo[i]->port < minPort) {
			minPort = timestamps->pktinfo[i]->port;
		}
	}

	for (int i = minPort; i <= maxPort; i++) {
		bool found = false;
		for (int x = startIndex; x < timestamps->size; x++) {
			if (timestamps->pktinfo[x]->port == i) {
				found = true;
				break;
			}
		}

		if (!found) {
			return false;
		}
	}
	return true;
}
