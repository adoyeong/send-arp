#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <net/if.h>
#include <sys/ioctl.h>
#include <cstring>
#include <sys/socket.h>

#pragma pack(push, 1)
struct EthArpPacket final {
        EthHdr eth_;
        ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
        printf("syntax: send-arp-test <interface>\n");
        printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char* argv[]) {
        if (argc != 4) {
                usage();
                return -1;
        }

        char* dev = argv[1];
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
        if (handle == nullptr) {
                fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
                return -1;
        }

	//#########GET MAC ADDRESS###########
    	int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
   	if (sock_fd < 0) {
       		 perror("socket");
       		 return -1;
   	}

 	struct ifreq ifr;
   	strncpy(ifr.ifr_name, argv[1], IFNAMSIZ - 1);
    	ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    	if (ioctl(sock_fd, SIOCGIFHWADDR, &ifr) < 0) {
        	perror("ioctl");
        	close(sock_fd);
        	return -1;
    	}

    	unsigned char* mac = reinterpret_cast<unsigned char*>(ifr.ifr_hwaddr.sa_data);

    	close(sock_fd);

	//###########GET SENDER's MAC ADDRESS##############
        EthArpPacket packet1;
        packet1.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
        packet1.eth_.smac_ = Mac(mac);
        packet1.eth_.type_ = htons(EthHdr::Arp);

        packet1.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet1.arp_.pro_ = htons(EthHdr::Ip4);
        packet1.arp_.hln_ = Mac::SIZE;
        packet1.arp_.pln_ = Ip::SIZE;
        packet1.arp_.op_ = htons(ArpHdr::Request);
        packet1.arp_.smac_ = Mac(mac);
        packet1.arp_.sip_ = htonl(Ip(argv[3]));
        packet1.arp_.tmac_ = Mac("00:00:00:00:00:00");
        packet1.arp_.tip_ = htonl(Ip(argv[2]));

        int res1 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet1), sizeof(EthArpPacket));
        const u_char* receive1;
        struct pcap_pkthdr* header;
        EthArpPacket *packet2;
        while(1)
        {
                int res2 = pcap_next_ex(handle, &header, &receive1);
                packet2 = (EthArpPacket *)receive1;
                if(packet2->eth_.dmac_ == Mac(mac) && packet2->eth_.type_ == 0x0608 && packet2->arp_.op_ == htons(ArpHdr::Reply)) break;
        }

	//##################SEND PACKET to SENDER############
        EthArpPacket packet;
        packet.eth_.dmac_ = packet2->arp_.smac_;
        packet.eth_.smac_ = Mac(mac);
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Reply);
        packet.arp_.smac_ = Mac(mac);
        packet.arp_.sip_ = htonl(Ip(argv[3]));
        packet.arp_.tmac_ = packet2->arp_.smac_;
        packet.arp_.tip_ = htonl(Ip(argv[2]));

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

        pcap_close(handle);
}


