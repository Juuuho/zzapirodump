LDLIBS += -lpcap

all: main

pcap-test: main.cpp

clean:
	rm -f main *.o
