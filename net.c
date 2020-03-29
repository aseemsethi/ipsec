#include "sim.h"

extern ipsecCfg cfg;

recvPackets() {
	int ret;
	fd_set rfds;
	int count = 0;
	unsigned char *fsmBuff = NULL;
	int countTotal = 0;
	char buff[1024];
	ikev2_hdr *ikeHdr;
	ikeStruct *ike = &cfg.ike;

	FD_ZERO(&rfds);
	FD_SET(cfg.sock, &rfds);
	while(1) {
		ret = select(cfg.sock + 1, &rfds, NULL, NULL, NULL);
		while (1) {
			printf("Pkt recvd..."); fflush(stdout);
			count = read(cfg.sock, buff, 1024);
			printf("%d", count);
			if (count == -1) {
				// If there is a signal interrupt, control comes here
				perror("\n Event Loop: Read error..continuing..");
				continue;
			} else if (count == 0) {
				printf("\n EOF");
			}
			// Save partial buffer
			memcpy(&(ike->rBuff[countTotal]), buff, count);
			countTotal += count;
			ike->rLen = countTotal;
			/* Let's check if have the complete pkt
			 * Assume for now, that we have 28/48 bytes 
			 * recvd in the first call itself.
			 */
			// Jump over IP+UDP Header
			ikeHdr = (ikev2_hdr*)(buff + IPV4_UDP_LEN);
			if (countTotal == GET_BE32(ikeHdr->length)+IPV4_UDP_LEN) {
				printf("\n Total Pkt recvd: %d Bytes",
                        GET_BE32(ikeHdr->length));
				fsmBuff = malloc(GET_BE32(ikeHdr->length));
				if(fsmBuff == NULL) {
					printf("\n Error: No mem for fsm");
					continue;
				} else {
					memcpy(fsmBuff, buff+IPV4_UDP_LEN,
						GET_BE32(ikeHdr->length));
					ikeFsmExecute(ike, DATA_EVENT, fsmBuff);
				}       
				countTotal = 0;
				break;
			} else if (countTotal < GET_BE32(ikeHdr->length)) {
				printf("\n Partial pkt recvd..%d", countTotal);
				continue;
			}
		} // end inner while
	} // end outer while
}


char* getSelfIpAddress() {
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, "enp0s3", IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    strcpy(cfg.selfIP,
        inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));
    printf("\nSelf IP Address: %s", cfg.selfIP);
}

initDataSocket() {
    struct sockaddr_in;
    char buffer[1024];
    int one = 1;
    const int *val = &one;
    struct ifreq interface, ethreq;
    struct packet_mreq mreq;
    int rc;

    if((cfg.sock=socket(PF_PACKET, SOCK_DGRAM, ETH_P_IP)) == -1) {
            perror("socket:");
            exit(1);
    }
    /* sin_port, sin_addr are in network byte order */
    memset(&interface, 0, sizeof(interface));
    strncpy(interface.ifr_ifrn.ifrn_name, "enp0s3", IFNAMSIZ);
    if ((rc = ioctl(cfg.sock, SIOCGIFINDEX, &interface)) < 0) {
        perror("Error getting IfIndex:");
        close(cfg.sock);
        return -1;
    }
    memset(&cfg.sll, 0, sizeof(cfg.sll));
    cfg.sll.sll_family = AF_PACKET;
    cfg.sll.sll_ifindex = interface.ifr_ifindex;
    cfg.sll.sll_protocol = htons(ETH_P_IP);
    /*ARP hardware identifier is ethernet*/
    cfg.sll.sll_hatype   = 1; // ARPHRD_ETHER;
    /*address length*/
    cfg.sll.sll_halen    = ETH_ALEN;
    cfg.sll.sll_addr[0]  = 0x00; cfg.sll.sll_addr[1]  = 0x0C;
    cfg.sll.sll_addr[2]  = 0x29; cfg.sll.sll_addr[3]  = 0x47;
    cfg.sll.sll_addr[4]  = 0xA6; cfg.sll.sll_addr[5]  = 0xBD;
    cfg.sll.sll_addr[6]  = 0x0; //Not used
    cfg.sll.sll_addr[7]  = 0x0; //Not used
	if (bind(cfg.sock, (struct sockaddr*)&cfg.sll, sizeof(cfg.sll)) < 0) {
        perror("  Bind failed\n");
        close(cfg.sock);
        return -1;
    }
    memset(&mreq, 0 , sizeof(mreq));
    mreq.mr_ifindex = interface.ifr_ifindex;
    mreq.mr_type    = PACKET_MR_PROMISC;
    if (setsockopt(cfg.sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
            &mreq, sizeof(mreq)) <0) {
        perror("  Setting promiscuous on Interface failed\n");
        close(cfg.sock);
        return -1;
    }

    printf("\nUDP IKE Socket createdto UT %s", cfg.utIP);
}

ushort ipcrc (ushort *p, int count)
{
    uchar *ptr = (uchar *) p;           /* damn prototypes */
    int crc;
    ushort i, *data;

    count = (count+1) >> 1;
    data = (ushort *) ptr;
    crc = 0;
    for (i = 0; i < count; i++)
        crc += *data++;         /* 2's complement add the next header word*/
    /* Add once to get first overflow */
    crc = (crc & 0xFFFF) + (crc >> 16);
    /* Add again to catch overflows caused by above */
    crc += crc >> 16;
    i = (short) crc;
    return (~i);
}


uint16_t udp_checksum(const void *buff, size_t len, in_addr_t src_addr,
                    in_addr_t dest_addr)
{
        const uint16_t *buf=buff;
        uint16_t *ip_src=(void *)&src_addr, *ip_dst=(void *)&dest_addr;
        uint32_t sum;
        size_t length=len;

        // Calculate the sum
        sum = 0;
        while (len > 1)
        {
                sum += *buf++;
                if (sum & 0x80000000)
                        sum = (sum & 0xFFFF) + (sum >> 16);
                len -= 2;
        }

        if ( len & 1 )
                // Add the padding if the packet lenght is odd 
                sum += *((uint8_t *)buf);

        // Add the pseudo-header                              
        sum += *(ip_src++);
        sum += *ip_src;

        sum += *(ip_dst++);
        sum += *ip_dst;

        sum += htons(IPPROTO_UDP);
        sum += htons(length);

        // Add the carries                                   
        while (sum >> 16)
                sum = (sum & 0xFFFF) + (sum >> 16);

        // Return the one's complement of sum               
        return ( (uint16_t)(~sum)  );
}


sendData (ikeStruct *ike, char* buff, int length) {
    unsigned char *ptr;
    struct iphdr *ip;
    struct udpheader *udp;
    int sent;

    ptr = buff-IPV4_UDP_SIZE;
    // Put an IPv4 Hdr
    //   45                 # Version / Header Length
    //   00                 # Type of service
    //   00 3c              # Total length
    //   00 a5              # Identification
    //   00 00              # Flags / Fragment offset
    //   80                 # Time to live
    //   01                 # Protocol
    //   b8 c8              # Checksum
    //   c0 a8 00 02        # Source address
    //   c0 a8 00 01        # Destination address

    ip = (struct iphdr*)ptr;
    ip->version = 4; /* version of IP used */
    ip->ihl = 5; /* Internet Header Length (IHL) */
    ip->tos = 0; /* Type Of Service (TOS) */
    ip->tot_len = htons(length+IPV4_UDP_SIZE); /* total length of the IP datagram */
    ip->id = 0; /* identification */
    ip->frag_off = htons(0x4000); /* fragmentation flag */
    ip->ttl = 64; /* Time To Live (TTL) */
    ip->check=0;
    ip->protocol = IPPROTO_UDP;
    ip->saddr = inet_addr(ike->srcIP); /* source address */
    if (ike->redirected == FALSE)
        ip->daddr = inet_addr(cfg.utIP); /* destination address */
    else
        ip->daddr = ike->redirected_ip; /* destination address */
    ip->check=ipcrc((unsigned short *)ip,sizeof(struct iphdr));
    ptr = ptr + 20;

    udp = (struct udpheader*)ptr;
    // Fabricate the UDP header
    udp->udph_srcport = htons(ike->srcPort);
    // Destination port number
    udp->udph_destport = htons(500);
    udp->udph_len = htons(sizeof(struct udpheader)+length);
    udp->udph_chksum = 0x0;
    udp->udph_chksum = (udp_checksum(ptr, length+8, ip->saddr, ip->daddr));

    printf("\n Sending %d Bytes", length);
    sent = sendto(cfg.sock, buff-IPV4_UDP_SIZE, length+IPV4_UDP_SIZE, 0,
        (struct sockaddr*)&cfg.sll, sizeof(cfg.sll));
    if(sent == -1) {
        perror("send:");
    } else {
        printf(" Sent %d Bytes", sent);
    }
    fflush(stdout);
}

