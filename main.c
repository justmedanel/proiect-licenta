
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#define LOG_FILE "traffic.log"

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethhdr *eth = (struct ethhdr *)packet;
    /* header pentru ora si lungimea pachetului, packet arata catre primul octet scris in ram
    eth pointeaza catre inceputul packetului unde sunt adresele mac si protocolul

    */
    if (ntohs(eth->h_proto) == ETH_P_IP) {
        struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
        char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip->saddr), src, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip->daddr), dst, INET_ADDRSTRLEN);
        /*citim si traducem campul protocol din formatul (network byte order-reteaua) in 
        (Host byte Order-procesorul), daca codul e 0x0800 avem ipv4
        alocam 2 buffere de 16 caractere src si dst
        inet... functiile thread-safe care traduc adresele ip binare direct in format text(dotted-quad)
        si le salveaza in src si dst
        
        */

        // Formatare timp HH:MM:SS
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        char ts[16];
        strftime(ts, sizeof(ts), "%H:%M:%S", t);

        FILE *f = fopen(LOG_FILE, "a");
        if (!f) return;

        // --- LOGICĂ FILTRARE ȘI ALINIERE ---
        if (ip->protocol == IPPROTO_ICMP) {
            struct icmphdr *icmp = (struct icmphdr *)(packet + sizeof(struct ethhdr) + (ip->ihl * 4));
            
            if (icmp->type == ICMP_ECHO) {
                // REQUEST: Client -> Google
                fprintf(f, "[%s] %s >>> [REQUEST] %s\n", ts, src, dst);
            } 
            else if (icmp->type == ICMP_ECHOREPLY) {
                // REPLY: Client <- Google (Inversăm ordinea la scriere pentru vizual)
                fprintf(f, "[%s] %s <<< [REPLY]   %s\n", ts, dst, src);
            }
        } 
        else if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ethhdr) + (ip->ihl * 4));
            if (tcp->syn || tcp->psh) {
                fprintf(f, "[%s] %s === [TCP DATA] %s\n", ts, src, dst);
            }
        }

        fclose(f);
    }
}

int main() {
    char *dev = "enp0s8"; 
    //pointer de tip char dev catre portul "enp0s8" 
    char errbuf[PCAP_ERRBUF_SIZE];
    // errbuf de tip char pentru erorile ulterioare care pot aparea
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    /*pointer handle de tip pcap_t din libpcap care pointeaza catre rezultatul functiei
    pcap_open_live(citeste de pe dev(enp..), pentru ca pachetele vin in viteza prea mare,
    stocheaza pachetele intr-un fisier bufsiz,modul 1 neselectiv(promiscuu), 
    asteapta 1000ms pentru a trimite pachetele adaugate in bufsiz catre procesare
    si errbuf unde sunt stocate erorile ulterioare.)
    */
    
    if (!handle) { printf("Eroare: %s\n", errbuf); return 2; }
    //daca cheia handle este null, nu am putut accesa portul dev
    remove(LOG_FILE); 
    printf("Sniffer aliniat pornit pe %s...\n", dev);
    //stergem vechiul logfile si incepem de la 0 cu textul afisat pe portul dev
    pcap_loop(handle, 0, packet_handler, NULL);
    /* bucla infinita. (0- sta la infinit, prinde pachetele cu cheia handle si le trimite
    catre packet_handler sa il decapsuleze)
    */
    pcap_close(handle);
    return 0;
}