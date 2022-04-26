#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <openssl/aes.h>

#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/socket.h>

#include <pcap.h>
#include <pcap/pcap.h>

#include <errno.h>
#include <err.h>

#include <time.h>

/**
 * Invented protocol for important data transfer
 */
struct transhdr
{
	u_char tagline[8];
	uint8_t type;
};

#define TRANS_METADATA	1	/* Metadata transfer (size 32B, name) */
#define TRANS_DATA	0		/* Data transfer */

const uint8_t tag[8] = "VUTFIT3";
const unsigned char key[] = "xtverd01xtverd01";
const short MAX_DATASIZE = 1350;

#define SIZE_SLL    16
#define SIZE_IPv6   40
#define SIZE_TRANSHDR   9
#define SIZE_ICMPHDR    8
#define MAX_DATASIZE    1350
#define MAX_DATASIZE_E  1360

#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE (256)
#endif

/* Global variables */

int n = 0;

char ip[60];

/* Variables for file metadata */
uint32_t md_size;
char md_name[255];

FILE *file;

/* Variables for counting received packets */
double counter = 0;
double datasegments = 0;

/**
 * Processes captured packets. It is called by pcap_loop()
 * @param agrs arguments 
 * @param header header of a packet
 * @param packet data of binary type
 */
void mypcap_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

/**
 * Overwrite the data in the *icmpdata to encrypted 
 * @param icmpdata data of ICMP protocol 
 * @param size size of the data
 * @return size of encrypted data
 */
uint32_t encryption(u_char *icmpdata, uint32_t size);


void mypcap_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	const struct ip *my_ip = (struct ip*) (packet+SIZE_SLL);         // pointing to the beginning of IP header

	const struct icmphdr *my_icmphdr;
	const struct transhdr *my_transhdr; 

	u_int size_ip;
	u_int size_icmp;
	u_int size_data;

	u_char protocoltype[2];
	memcpy(protocoltype, (u_char *)(packet+SIZE_SLL-2), 2);                   // the last 2 bytes of SLL header to get IP version

	if(protocoltype[0] == 0x86 && protocoltype[1] == 0xdd)                    // setting ip header size according to IP version 	
		size_ip = SIZE_IPv6;
	else
		size_ip = my_ip->ip_hl*4;
	
	size_icmp = header->len-SIZE_SLL-size_ip;           
	size_data = size_icmp-SIZE_ICMPHDR-SIZE_TRANSHDR;

	my_icmphdr = (struct icmphdr *) (packet+SIZE_SLL+size_ip);                // pointing to the beginning of ICMP header
	my_transhdr = (struct transhdr *) (packet+SIZE_SLL+size_ip+SIZE_ICMPHDR); // pointing to the beginning of TRANS header (invented protocol)

	/* Accepting packets with necessary type and tagline */
	if(((my_icmphdr->type == ICMP_ECHO) || (my_icmphdr->type == ICMP6_ECHO_REQUEST)) && !(memcmp(my_transhdr->tagline, tag, sizeof(my_transhdr->tagline))))
	{
		n++;
		// print the packet header data
		printf("\n");
		printf("Packet no. %d:\n",n);
		printf("\tLength %d, received at %s",header->len,ctime((const time_t*)&header->ts.tv_sec));  

		short data_offset = SIZE_SLL+size_ip+SIZE_ICMPHDR+SIZE_TRANSHDR;
		u_char *data = (u_char *) (packet+data_offset);                       // pointing to the beginning of data of ICMP protocol
		
		AES_KEY dkey;
		AES_set_decrypt_key(key, 128, &dkey);

		u_char *data_d = (u_char *) malloc(size_data);                        // array for decrypted data

		// data decryption
		u_char *eptr = data_d;
		for(u_int i = 0; i < size_data/AES_BLOCK_SIZE; i++)
		{
			AES_decrypt(data+i*AES_BLOCK_SIZE, eptr, &dkey);
			eptr+=AES_BLOCK_SIZE;
		}


		if(my_transhdr->type == TRANS_METADATA)                               // packet with file metadata
		{
			md_size = *((uint32_t *)(data_d));							      // file size extracting
			strcpy(md_name, (char *)(data_d+sizeof(uint32_t)));               // file name extracting

			datasegments = (double)md_size / MAX_DATASIZE;                    // number of data segments to receive

			// file creating
    		remove(md_name);
			if(!(file = fopen(md_name, "ab")))
			{ printf("File error\n"); return; }		
		}
		else if(my_transhdr->type == TRANS_DATA)							  // if it's the packet with file data
		{
			if(size_data == MAX_DATASIZE_E)									  // if packet is filled with data
			{
				fwrite(data_d, MAX_DATASIZE, 1, file);                        // writing to file
				counter++; 

				if(counter == datasegments) 								  // the last packet checking
				fclose(file); 
			}	
			else															  // if it's the last packet of sequence
			{
				fwrite(data_d, md_size % MAX_DATASIZE, 1, file);			  // writing to file
				counter+= datasegments - (uint32_t)datasegments; 

				fclose(file); 
			}
		}
		free(data_d);
	}
	else
	{
		//printf("\nSome ICMP packet isn't adressed for us. Skipping packet...\n");
	}

	if (counter == datasegments) 											  // packet loss checking
	{
		printf("\nFile has been received successfully!\n");
		counter = 0;
	}
}

uint32_t encryption(u_char *icmpdata, uint32_t size)
{
	uint32_t esize_icmp = size;
	if(size % AES_BLOCK_SIZE != 0)
		esize_icmp = size + (AES_BLOCK_SIZE - (size % AES_BLOCK_SIZE));       // calculating and setting size, which is multiple of 16
	u_char *icmpdata_e = (u_char *) malloc(esize_icmp);
	
	AES_KEY ekey;
	AES_set_encrypt_key(key, 128, &ekey);

	// data encryption
	u_char *eptr = icmpdata_e;
	for(uint32_t i = 0; i < esize_icmp/AES_BLOCK_SIZE; i++)
	{
		AES_encrypt(icmpdata+i*AES_BLOCK_SIZE, eptr, &ekey);
		eptr+=AES_BLOCK_SIZE;
	}

	memcpy(icmpdata, icmpdata_e, esize_icmp); 								  // data refreshing
	free(icmpdata_e);
	return esize_icmp;
}

int main(int argc, char **argv)
{
	FILE *file;
	char *fname;
	struct addrinfo *serverinfo;

if(argc == 5) // secret -r <file> -s <ip | hostname>
{
if(!strcmp(argv[1],"-r") && !strcmp(argv[3],"-s"))
{	
	// opening file
	char *filepath = argv[2];
	fname = basename(filepath);
	if(!(file = fopen(filepath, "rb")))
	{ printf("File error\n"); return 1; }

	struct addrinfo hints;													   // hints preparing for getaddrinfo function
	memset(&hints, 0, sizeof(hints));

	char *host = argv[4];
	int result;

	hints.ai_family = AF_UNSPEC;											   // setting unknown family for socket 
	hints.ai_socktype = SOCK_RAW;

	if ((result = getaddrinfo(host, NULL, &hints, &serverinfo)) != 0)
	{	
		fprintf(stderr, "Translation to set of socket adresses is unsuccessful\n");
		printf("%s\n", strerror(errno));
		return 1; 
	}

	int protocol;
	// version of protocol setting
	if(serverinfo->ai_family == AF_INET) 									    
		protocol = IPPROTO_ICMP;
	else
		protocol = IPPROTO_ICMPV6;

	int sock = socket(serverinfo->ai_family, serverinfo->ai_socktype, protocol);// socket creating
	// looking for an available socket
	while(sock == -1)
	{
		printf("%s\n", strerror(errno));
		
		if(serverinfo->ai_next == NULL){
			fprintf(stderr, "Socket hasn't been created\n");
			return 1;
		}		

		serverinfo = serverinfo->ai_next;
		sock = socket(serverinfo->ai_family, serverinfo->ai_socktype, protocol);
	}

	// getting length of file
	fseek(file, 0, SEEK_END);
	uint32_t fsize = ftell(file);
	fseek(file, 0, SEEK_SET);

	u_char *fdata = (u_char *) malloc(fsize);
	fread(fdata, fsize, 1, file);												 // reading file to fdata array
	fclose(file);

	u_char icmp[1400]; 															 // array with maximum size of ICMP segment
	memset(&icmp, 0, 1400);

	struct icmphdr *icmp_header = (struct icmphdr *)icmp;						 // pointing to ICMP header
	// ICMP type setting
	if(serverinfo->ai_family == AF_INET6) 
		icmp_header->type = ICMP6_ECHO_REQUEST;
	else
		icmp_header->type = ICMP_ECHO;
	icmp_header->code = 0;														 // ICMP code setting
	icmp_header->checksum = 0;													 // not considering checksum for ICMP

	struct transhdr *trans_header = (struct transhdr *)(icmp+SIZE_ICMPHDR);		 // pointing to TRANS header (in ICMP data section)
	memcpy(trans_header->tagline, tag, sizeof(trans_header->tagline));           // the tagline setting

	short data_offset = SIZE_ICMPHDR+SIZE_TRANSHDR;
	u_char *icmpdata = icmp + data_offset;										 // pointing to ICMP data

	/* Data transfer */
	// Metadata transfer
	trans_header->type = TRANS_METADATA;
	memcpy(icmpdata, &fsize, sizeof(int));										 // writing file size to ICMP data
	memcpy(icmpdata+sizeof(int), fname, strlen(fname)+1); 						 // writing file name to ICMP data

	uint32_t esize_icmp = encryption(icmpdata, sizeof(int)+strlen(fname)+1);     // data encryption
	// Data sending
	if (sendto(sock, icmp, data_offset+esize_icmp, 0, (struct sockaddr *)(serverinfo->ai_addr), serverinfo->ai_addrlen) < 0)
	{
		fprintf(stderr, "Data sending error (metadata)\n");
		printf("%s\n", strerror(errno));
		return 1;
	}

	// Data transfer
	// structure filling for poll()
	struct pollfd fds[1];
	fds[0].fd = sock;
	fds[0].events = 0;
	fds[0].events |= POLLOUT;

	trans_header->type = TRANS_DATA;
	memset(icmpdata, 0, 1400-data_offset); 										  // reset of array

	double fdatasegments = (double)fsize / MAX_DATASIZE;						  // number of data segments to send
	short fdatasegments_remainder = fsize % MAX_DATASIZE;
	u_char *carriage = fdata; 
	
	// Loop for data sending
	for (uint32_t i = 0; i < fdatasegments; i++)
	{
		if(i == (uint32_t)fdatasegments)
		{
			memcpy(icmpdata, carriage, fdatasegments_remainder);				  // icmpdata array filling
			esize_icmp = encryption(icmpdata, fdatasegments_remainder);			  

			if(poll(fds, 1, -1) == -1)											  // waiting for free space in buffer
			{
				fprintf(stderr, "Poll error (data)\n");
				printf("%s\n", strerror(errno));
				return 1;
			}

			// Data sending
			if (sendto(sock, icmp, data_offset+esize_icmp, 0, (struct sockaddr *)(serverinfo->ai_addr), serverinfo->ai_addrlen) < 0)
			{
				fprintf(stderr, "Data sending error (data)\n");
				printf("%s\n", strerror(errno));
				return 1;
			}
		}
		else
		{
			memcpy(icmpdata, carriage, MAX_DATASIZE);							  // icmpdata array filling	
			esize_icmp = encryption(icmpdata, MAX_DATASIZE);

			if(poll(fds, 1, -1) == -1)											  // waiting for free space in buffer
			{
				fprintf(stderr, "Poll error (data)\n");
				printf("%s\n", strerror(errno));
				return 1;
			}

			// Data sending
			if (sendto(sock, icmp, data_offset+esize_icmp, 0, (struct sockaddr *)(serverinfo->ai_addr), serverinfo->ai_addrlen) < 0)
			{
				fprintf(stderr, "sendto err (data)\n");
				printf("%s\n", strerror(errno));
				return 1;
			}

			carriage+=MAX_DATASIZE;
		}
	}
}
else
	{ printf("Use 'secret -r <file> -s <ip|hostname> [-l]'\n"); return 1;}
}
else if(argc == 2) // secret -l
{
/*
 * Live sniffing of packets with a filtering
 * Source: ISA - examples
 * (c) Petr Matousek, 2020
 */
if(!strcmp(argv[1],"-l"))
{	
	char errbuf[PCAP_ERRBUF_SIZE];  // constant defined in pcap.h

	pcap_if_t *alldev, *dev ;       // a list of all input devices
	char *devname;                  // a name of the device
  
	struct in_addr a,b;
	bpf_u_int32 netaddr;            // network address configured at the input device
	bpf_u_int32 mask;               // network mask of the input device
  
 	struct bpf_program fp;          // the compiled filter
  
	pcap_t *handle;                 // packet capture handle 

	// open the input devices (interfaces) to sniff data
	if (pcap_findalldevs(&alldev, errbuf))
		err(1,"Can't open input device(s)");

	printf("\n");

	// looks for "any" interface 
	for (dev = alldev; dev != NULL; dev = dev->next){
    	if(!strcmp("any", dev->name))
      devname = dev->name;
	}
  
	// get IP address and mask of the sniffing interface
  	if (pcap_lookupnet(devname,&netaddr,&mask,errbuf) == -1)
    	err(1,"pcap_lookupnet() failed");

  	a.s_addr=netaddr;
  	printf("Opening interface \"%s\" with net address %s,",devname,inet_ntoa(a));
  	b.s_addr=mask;
  	printf(" mask %s for listening...\n",inet_ntoa(b));

  	// open the interface for live sniffing
  	if ((handle = pcap_open_live(devname,BUFSIZ,1,1000,errbuf)) == NULL)
    	err(1,"pcap_open_live() failed");

  	// compile the filter
  	if (pcap_compile(handle,&fp,"icmp or icmp6",0,netaddr) == -1)
    	err(1,"pcap_compile() failed");
  
  	// set the filter to the packet capture handle
  	if (pcap_setfilter(handle,&fp) == -1)
    	err(1,"pcap_setfilter() failed");

  	// read packets from the interface in the infinite loop (count == -1)
  	// incoming packets are processed by function mypcap_handler() 
  	if (pcap_loop(handle,-1,mypcap_handler,NULL) == -1)
    	err(1,"pcap_loop() failed");

  	// close the capture device and deallocate resources
  	pcap_close(handle);
  	pcap_freealldevs(alldev);
}
else
	{ 
		printf("Use 'secret -r <file> -s <ip|hostname> [-l]'\n"); 
		return 1;
	}
}
else
{
	printf("Use 'secret -r <file> -s <ip|hostname> [-l]'\n");
	return 1;
}
	printf("File has been sent successfully!\n");
	return 0;
}