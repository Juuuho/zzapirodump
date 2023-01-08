#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "dot11.h"
#include <cstring>
#include <vector>
#include <algorithm>
#include <iostream>

using namespace std;

#define SUBTYPE 0x80

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void printBCNS(vector<BEACON> &bcns){

	for(int i=0;i<bcns.size();i++){
		printf("%02X:%02X:%02X:%02X:%02X:%02X // %d // %s\n", bcns[i].bssid[0],bcns[i].bssid[1],bcns[i].bssid[2],bcns[i].bssid[3],bcns[i].bssid[4],bcns[i].bssid[5], bcns[i].bc_cnt, bcns[i].essid);
	}
	printf("===========================================\n");
}

void ManageBcns(vector<BEACON> &bcns, u_char* frame_start){
	u_int8_t BSSID[6]; int BC_CNT = 0; char ESSID[256];
	
	BEACON tmp;

	memcpy(BSSID, frame_start + 10, 6);
	memcpy(tmp.bssid, BSSID, sizeof(BSSID));
	memcpy(ESSID, frame_start + 38, *(frame_start + 37));
	memcpy(tmp.essid, ESSID, sizeof(ESSID));

	if(strlen(tmp.essid) == 0) memcpy(tmp.essid, "<length: 0>", 11);

	auto it = bcns.begin();
	for(it;it != bcns.end();it++){
		printf("%02X %s // %02X %s\n", it->bssid, it->essid, BSSID, ESSID);
		if(memcmp(it->bssid, BSSID, sizeof(BSSID))){
			tmp.bc_cnt += 1;
		}
		else{
			tmp.bc_cnt = 0;
		}
	}


	bcns.push_back(tmp);

	printBCNS(bcns);

	memset(BSSID, 0x00, sizeof(BSSID));
	memset(ESSID, 0x00, sizeof(ESSID));
}


int main(int argc, char* argv[]) {
	vector<BEACON> bcns;

	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		RTHEAD *rd_hdr = (RTHEAD *)packet;
		u_int16_t it_len = rd_hdr->it_len;
		u_char* frame_start = (u_char*)(packet + it_len);


		if(*frame_start != SUBTYPE){
			continue;
		}
		
		ManageBcns(bcns, frame_start);
		
	}

	pcap_close(pcap);
}