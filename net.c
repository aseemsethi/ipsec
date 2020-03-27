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
