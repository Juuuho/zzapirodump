LDLIBS += -lpcap

all: zzapirodump

pcap-test: zzapirodump.cpp

clean:
	rm -f zzapirodump *.o
