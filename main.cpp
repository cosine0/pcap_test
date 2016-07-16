#include <pcap.h>

// to use ntohs
#include <arpa/inet.h>

// to use struct for each packet type
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <stdio.h>
#include <stdlib.h>

void hexdump(const u_char* data, size_t size)
{
    const size_t LINE_WIDTH = 16;
    size_t line_count = size / LINE_WIDTH;
    size_t last_line = size % LINE_WIDTH;
    for (int i = 0; i < line_count; ++i)
    {
        for (int j = 0; j < LINE_WIDTH; ++j)
            printf("%02x ", *(data++));
        printf("\n");
    }
    for (int i = 0; i < last_line; ++i)
        printf("%02x ", *(data++));
    printf("\n");
}

void got_packet(u_char *args, const pcap_pkthdr *header,
        const u_char *packet)
{
    // packet count
    static int count = 1;
    printf("# %d\n", count++);

    // * ethernet header *
    const u_char* ethernet_start = packet;
    const ether_header* ethernet = (ether_header*)ethernet_start;

    // mac address
    const uint8_t* src_mac_bytes = ethernet->ether_shost;
    const uint8_t* dst_mac_bytes = ethernet->ether_dhost;

    printf("src mac : %02x:%02x:%02x:%02x:%02x:%02x, dst mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
       src_mac_bytes[0], src_mac_bytes[1], src_mac_bytes[2],
       src_mac_bytes[3], src_mac_bytes[4], src_mac_bytes[5],

       dst_mac_bytes[0], dst_mac_bytes[1], dst_mac_bytes[2],
       dst_mac_bytes[3], dst_mac_bytes[4], dst_mac_bytes[5]
    );

    // ethernet type
    short ethernet_type = ntohs(ethernet->ether_type);
    if (ethernet_type != ETHERTYPE_IP)
    {
        printf("Ethernet type is not IP.\n\n");
        return;
    }

    // * ip header *
    const u_char* ip_start = ethernet_start + sizeof(ether_header);
    const ip* ip_packet = (ip*)ip_start;

    // ip addresses
    char ip_string[17];
    inet_ntop(AF_INET, &ip_packet->ip_src.s_addr, ip_string, sizeof(ip_string));
    printf("src ip  : %17s", ip_string);
    inet_ntop(AF_INET, &ip_packet->ip_src.s_addr, ip_string, sizeof(ip_string));
    printf(", dst ip  : %17s\n", ip_string);

    // ip protocol
    if (ip_packet->ip_p != IPPROTO_TCP)
    {
        printf("IP protocol is not TCP.\n\n");
        return;
    }

    // * tcp header *
    int ip_header_length = ip_packet->ip_hl * 4;
    const u_char* tcp_start = ip_start + ip_header_length;
    const tcphdr* tcp = (const tcphdr*)tcp_start;

    // tcp port
    printf("src port: %17d, ", ntohs(tcp->th_sport));
    printf("dst port: %17d\n", ntohs(tcp->th_dport));

    // * hex dump *
    int ip_total_length = ntohs(ip_packet->ip_len);
    int tcp_data_offset = tcp->doff * 4;
    int data_length = ip_total_length - ip_header_length - tcp_data_offset;
    printf("(data size=%d)\n", data_length);
    const u_char* data_start = tcp_start + tcp_data_offset;
    hexdump(data_start, data_length);
}

int main(int argc, char *argv[])
{
    pcap_t *handle;			/* Session handle */
    char *dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		/* The compiled filter */
    char filter_exp[] = "";	/* The filter expression */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr header;	/* The header that pcap gives us */
    const u_char *packet;		/* The actual packet */

    /* Define the device */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    /* Grab a packet */
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return(0);
}
