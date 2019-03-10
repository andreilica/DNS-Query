#include <fcntl.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>	
#include <string.h>
#include <ctype.h>

#define BUFLEN 512
#define A       1
#define NS      2
#define CNAME   5
#define MX      15
#define SOA     6
#define TXT     16

typedef struct {
	unsigned short id;

	unsigned char rd :1;
	unsigned char tc :1;
	unsigned char aa :1;
	unsigned char opcode :4;
	unsigned char qr :1;

	unsigned char rcode :4;
	unsigned char z :3;
	unsigned char ra :1;

	unsigned short qdcount;
	unsigned short ancount;
	unsigned short nscount;
	unsigned short arcount;
} dns_header_t;

typedef struct {
	unsigned short qtype;
	unsigned short qclass;
} dns_question_t;

typedef struct {
	unsigned short type;
	unsigned short class;
	unsigned int ttl;
	unsigned short rdlength;
} dns_rr_t;

void usage(char*file) {
	fprintf(stderr,"Usage: %s <nume_domeniu/adresa_IP> <tip_inregistrare>\n",file);
	exit(0);
}

void error(char *msg) {
    perror(msg);
    exit(1);
}

/* Functie care face conversia din hostname-ul primit ca si parametru in dns host-name
ex: www.google.com -> 3www6google3com0 */

void convert_name(unsigned char* to_question, unsigned char* new_name) 
{
    int aux = 0;
    strcat(to_question, "."); //adaugarea unui punct la finalul hostname-ului de interogat
     
    for(int i = 0 ; i < strlen(to_question) ; i++) 
    {
		/* Unde se gaseste punct se calculeaza cate caractere am parcurs pana acolo, iar in locul punctului se pune valoarea
		gasita, in hexazecimal */

        if(to_question[i] == '.')
        {
            *new_name++ = i - aux;
            while(aux < i) {
                *new_name++ = to_question[aux];
				aux++;
            }
            aux += 1;
        }
    }

	/* La finalul string-ului modificat se pune si '\0' */
    *to_question++ = '\0';
}

void dns_interogation(char *to_question, int register_type, char (*dns_servers)[16], int dns_server_count){

	int udp_sockfd, n;
	FILE *logfile;
	struct sockaddr_in serv_addr;
	unsigned char buffer[BUFLEN], result[BUFLEN];
	unsigned char *qname;

	dns_header_t *header = NULL;
	dns_question_t *question_info = NULL;

	/* Deschiderea socketului UDP pentru trimiterea interogarilor */

	udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sockfd < 0) 
        error("Eroare deschidere socket UDP!\n");
	if ( (logfile = fopen("message.log", "a")) == NULL ) {
		error("Eroare in deschiderea fisierului message.log!\n");
	}
	/* Configurarea adresei pentru server (ip-ul din fisierul de configurare si portul 53) */

	for(int i = 0; i < dns_server_count; i++){
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_port = htons(53);
		inet_aton(dns_servers[i], &(serv_addr.sin_addr));
		size_t header_size = sizeof(dns_header_t);
		size_t question_size = sizeof(dns_question_t);
		size_t servsize = sizeof(struct sockaddr_in);
		header = (dns_header_t *)&buffer; // Parcurgerea bufferului cu un pointer de dimensiunea unui pointer la structura dns_header_t 

		/* Setarea flagurilor din structura de header */

		header->id = (unsigned short) htons(1);
		header->rd = 1;
		header->tc = 0;
		header->aa = 0;
		header->opcode = 0;
		header->qr = 0;
		header->rcode = 0;
		header->z = 0;
		header->ra = 0;
		header->qdcount = htons(1);
		header->ancount = 0;
		header->nscount = 0;
		header->arcount = 0;

		/* Conversia propriu-zisa a hostname-ului in dns hostname */

		qname = &buffer[header_size];
		convert_name(to_question, qname);
		int name_length = strlen(qname) + 1;
		int total_size = header_size + name_length + question_size;
		
		question_info = (dns_question_t*)&buffer[header_size + name_length]; /* Mutarea pointerului dupa header si dupa nume */
		question_info->qtype = htons(register_type);
		question_info->qclass = htons(1);

		/* Scrierea in message.log a mesajului format din: header, nume si datele interogarii */

		

		/* Trimiterea mesajului pe socketul UDP catre serverul DNS */

		if( sendto(udp_sockfd, buffer, total_size, 0, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0){
			error("Trimitere esuata!\n");
		}

		/* Primirea de raspunsuri de la serverul DNS pe socketul UDP */
		/* In caz ca nu se primeste nimic, se trece la urmatorul server dns din lista */
		
		if( recvfrom(udp_sockfd, result, BUFLEN, 0, (struct sockaddr*) &serv_addr, (socklen_t *) &servsize) <= 0){
			continue;
		} else {
			printf("Server DNS ales: %s\n", dns_servers[i]);
			for(int i = 0; i < total_size; i++){
				fprintf(logfile, "%.2x ", buffer[i]);
			}
			fprintf(logfile, "\n");
			break;
		}
	}

	close(udp_sockfd);
	fclose(logfile);
}

int main(int argc,char**argv)
{
	if (argc < 3) {
		usage(argv[0]);
	}
	
	char to_question[50];
	char register_type[50];
	FILE* fp;
	char line[BUFLEN];
	int dns_server_count = 0;

	if(argv[1] == NULL || argv[2] == NULL){
		error("Argumente invalide\n");
	} else {
		strcpy(to_question, argv[1]);
		strcpy(register_type, argv[2]);
	}

	
	if ( (fp = fopen("dns_servers.conf", "r")) == NULL ) {
		error("Eroare in deschiderea fisierului de configurare\n");
	}

	/* Citirea serverelor DNS din fisierul de configurare */

	while(fgets(line, sizeof(line), fp) != NULL){
		if(line[0] != '#' && isdigit(line[0]))
			dns_server_count++;
	}
	
	rewind(fp);
	char dns_servers[dns_server_count][16];
	int k = 0;

	while(fgets(line, sizeof(line), fp) != NULL){
		if(line[0] != '#' && isdigit(line[0])){
			line[strlen(line) - 1] = '\0';
			strcpy(dns_servers[k++], line);
		}
	}
	fclose(fp);

	printf("=====================================================\n");
	printf("                      DNSCLIENT                      \n");
	printf("=====================================================\n");
	printf("Nume_Domeniu/Adresa_IP: %s\n", to_question);
	printf("Tip_Inregistrare: %s\n", register_type);
	printf("=====================================================\n");
	printf("                   DNS_SERVERS_USED                  \n\n");
	for(int i = 0; i < k; i++){
		printf("                     %s\n", dns_servers[i]);
	}              
	printf("=====================================================\n");

	/* Apelarea functiei de interogare in functie de tipul inregistrarii dorite */

	if(strcmp(register_type, "A\0") == 0)
		dns_interogation(to_question, A, dns_servers, dns_server_count);
	if(strcmp(register_type, "MX") == 0)
		dns_interogation(to_question, MX, dns_servers, dns_server_count);
	if(strcmp(register_type, "NS") == 0)
		dns_interogation(to_question, NS, dns_servers, dns_server_count);
	if(strcmp(register_type, "CNAME") == 0)
		dns_interogation(to_question, CNAME, dns_servers, dns_server_count);
	if(strcmp(register_type, "SOA") == 0)
		dns_interogation(to_question, SOA, dns_servers, dns_server_count);
	if(strcmp(register_type, "TXT") == 0)
		dns_interogation(to_question, TXT, dns_servers, dns_server_count);

	return 0;
}
