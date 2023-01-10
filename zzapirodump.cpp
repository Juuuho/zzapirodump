#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "dot11.h"
#include <cstring>
#include <vector>
#include <algorithm>
#include <iostream>
#include <ctime>

using namespace std;

#define SUBTYPE 0x80

time_t timer_1 = time(NULL);
int ch_Num = 0;

void usage() {
	printf("syntax: zzapirodump <interface>\n");
	printf("sample: zzapirodump wlan0\n");
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
    printf("\x1b[H\x1b[J");
	printf("CH  %d ]\n", ch_Num);
	printf("BSSID\t\t\tPWR\tBeacons\tESSID\n\n");
	for(int i=0;i<bcns.size();i++){
		printf("%02X:%02X:%02X:%02X:%02X:%02X\t%d\t%d\t%s\n", bcns[i].bssid[0],bcns[i].bssid[1],bcns[i].bssid[2],bcns[i].bssid[3],bcns[i].bssid[4],bcns[i].bssid[5], bcns[i].pwr[0],bcns[i].bc_cnt, bcns[i].essid);
	}
}


void ManageBcns(vector<BEACON> &bcns, u_char* frame_start, u_int16_t it_len){
	u_int8_t BSSID[6]; char ESSID[256]; int8_t PWR[1];
	bool is_new = true;

	BEACON tmp;

	memcpy(BSSID, frame_start + 10, sizeof(BSSID));
	memcpy(tmp.bssid, BSSID, sizeof(BSSID));

	memcpy(PWR, frame_start - it_len + 22, sizeof(PWR));
	memcpy(tmp.pwr, PWR, sizeof(PWR));
	
	memcpy(ESSID, frame_start + 38, *(frame_start + 37));
	memcpy(tmp.essid, ESSID, sizeof(ESSID));
	
	if(strlen(tmp.essid) == 0) memcpy(tmp.essid, "<length: 0>", 11);

	auto it = bcns.begin();
	for(auto& it: bcns){
		if(!memcmp(it.bssid, BSSID, 6)){
			it.bc_cnt += 1;
			if(tmp.pwr[0] != -1){
				it.pwr[0] = tmp.pwr[0];
			}
			is_new = false;
			break;
		}
	}


	if(is_new){
		tmp.bc_cnt = 1;
		bcns.push_back(tmp);
	}

	printBCNS(bcns);
	memset(BSSID, 0x00, sizeof(BSSID));
	memset(PWR, 0x00, sizeof(PWR));
	memset(ESSID, 0x00, sizeof(ESSID));
	
}


int main(int argc, char* argv[]) {
	vector<BEACON> bcns;
	int channels[] = {1, 3, 14, 13, 4, 2, 5, 9, 10, 8, 7, 12, 11, 6};
	int chn = 0;

	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		time_t timer_2 = time(NULL);

		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);

		if(timer_2 - timer_1 >= 0.1){
			string cmd = "iwconfig ";
			cmd += argv[1];
			cmd += " channel ";
			cmd += channels[chn];
			chn = (chn+1)%(sizeof(channels)/sizeof(int));

			timer_1 = time(NULL);
			system(cmd.c_str());
			ch_Num = channels[chn];
		}

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
		
		ManageBcns(bcns, frame_start, it_len);

	}

	pcap_close(pcap);
}