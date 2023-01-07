#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "dot11.h"
#include <cstring>

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

int main(int argc, char* argv[]) {

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
		BEACON tmp;


		if(*frame_start != SUBTYPE){
			continue;
		}
		
		memmove(tmp.bssid, frame_start + 10, 6);
		memmove(tmp.essid, frame_start + 38, *(packet + it_len + 37));
		if(strlen(tmp.essid) == 0) memmove(tmp.essid, "<length: 0>", 11);
		printf("%02X:%02X:%02X:%02X:%02X:%02X // %s\n", tmp.bssid[0],tmp.bssid[1],tmp.bssid[2],tmp.bssid[3],tmp.bssid[4],tmp.bssid[5], tmp.essid);
		memset(tmp.essid, 0, 256);
	}

	pcap_close(pcap);
}