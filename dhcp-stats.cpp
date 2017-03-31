/*
 * File:  dhcp-stats.cpp
 * Date:   28.10.2016 
 * Author:   Miroslav Novak, xnovak1k@stud.fit.vutbr.cz
 * Project: ISA - Monitoring of dhcp 
 * Description:  Application for monitoring dhcp comunication
 *    
 */

 #include <iostream>
 #include <vector>
 #include <string>
 #include <fstream>

 #include <stdio.h>
 #include <stdlib.h>
 #include <stdbool.h>
 #include <string.h>
 #include <assert.h>
 #include <regex.h>
 #include <locale.h>
 #include <ctype.h>
 #include <math.h>       /* pow */

 #include <algorithm>
 #include <functional>
 #include <array>
 #include <iostream>
 #include <ctime>
 #include <map>

 #include <netinet/ip_icmp.h>   //Provides declarations for icmp header
 #include <netinet/udp.h>   //Provides declarations for udp header
 #include <netinet/tcp.h>   //Provides declarations for tcp header
 #include <netinet/ip.h>    //Provides declarations for ip header
 #include <netinet/if_ether.h>  //For ETH_P_ALL
 #include <net/ethernet.h>  //For ether_header
 #include <signal.h>
 #include <sys/types.h>
 #include <unistd.h>
 #include <sys/socket.h>
 #include <netinet/in.h>
 #include <netdb.h>
 #include <sys/stat.h>
 #include <sys/types.h>
 #include <sys/time.h>
 #include <sys/resource.h>
 #include <sys/wait.h>
 #include <ncurses.h>

 // 1 - Turn on the debug informations
 #define DEBUG 0
 #define MAX_SIZE_OF_SOCKET 65536
 #define UDP 17

 using namespace std;

 enum Msg_type {

    NOT_DHCP_MSG,
    DHCPDISCOVER,
    DHCPOFFER,
    DHCPREQUEST,
    DHCPDECLINE,
    DHCPACK,
    DHCPNAK,
    DHCPRELEASE,
    DHCPINFORM

 };

typedef struct ip_Addr {

    unsigned char part[4]; // ip Address split on parts
    int mask = 0; // Mask of ip preffix
    unsigned int allocated; // Count of allocated address (only for preffix) 

 } ip_addr;

 typedef struct Allc_addr {

    ip_addr* addr;
    time_t allc_time; // Time of the allocation
    time_t lease_time;

 } allc_addr;

//___________
//___________   Function declarations
//___________

void init_ip_addrs(ip_addr* addrs, int size);
int digit_to_int(char d);
void sig_handler(int sig);
 long int get_max_hosts(int mask);
void print_ip_addr(ip_addr* addr);
int get_message_type(unsigned char* data);
ip_addr* get_yiaddr(unsigned char* data);
ip_addr* get_ciaddr(unsigned char* data);
unsigned int get_lease_time(unsigned char* data);
unsigned int joinIP(ip_addr* addr);
bool is_preffix_valid(ip_addr* addr);
bool is_in_preffix(ip_addr* prefix, ip_addr* addr); 

int str_to_int(char *arg, int *ret)
{
  char *end;
  *ret = strtol(arg, &end, 10);
  if (end[0] != '\0'){ // pokud ukazuje na konec retezce, je to v poradku
    return 1;
  }
  else if (*ret < 0) { /*pokud je zaporny cislo*/
    return 1;
  }
  else return 0;
}


//___________
//___________   Global variable
//___________

int sock;
unsigned char *buffer; // Buffer for receiving sockets
map<int, allc_addr*> dhcp_table; // Map for records from dhcp messages
typedef map<int, allc_addr*>::iterator it_type;


//___________
//___________   Main
//___________

int main(int argc, char** argv) {

    buffer = NULL;
    int log = 0;
    // Set SIGINT handler
    signal(SIGINT, sig_handler);

	if (argc < 2) {
        fprintf(stderr, "%s\n", "You must input at least one prefix");
        return 1;
    }

    vector<ip_addr> preffix_list(argc - 1);

    // Parsing input IP address
    init_ip_addrs(preffix_list.data(), argc - 1);

    // If help
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        printf("%s\n","----------------Welcome in dhcp-stats help----------------" );
        printf("\n");
        printf("%s\n","Program is usefull for monitoring dhcp comunication and for getting dhcp stats.");
        printf("%s\n","Usage: dhcp-stats <ip-prefix> [ <ip-prefix> [ ... ] ]");
        printf("%s\n","ip-prefix - range of network for generating statistic");
        printf("%s\n","Example: dhcp-stats 192.168.1.0/24 192.168.0.0/22");

        return 0;
    }

    for (int i = 1; i < argc; i++) {
        unsigned int p = 0;
        unsigned int tmp = 0;
        int int_test = 0; // Test the value of input char
        if (strcmp(argv[i], "-c") == 0) {
                    if (i + 1 == argc) {
                        fprintf(stderr, "%s\n", "Bad format of input prefix1");
                        return 1;
                    }
                    else {
                        log = atoi(argv[i+1]);
                    }
                    i++;
                }
        else {

        while (1) {

            while (argv[i][tmp] != '/' && argv[i][tmp] != '.') {
   

                    int_test = preffix_list[i - 1].part[p] * 10 + digit_to_int(argv[i][tmp]);
                    if (int_test > 255) {
                        fprintf(stderr, "%s\n", "Bad format of input prefix3");
                        return 1;
                    }
                    preffix_list[i - 1].part[p] =  (unsigned char) preffix_list[i - 1].part[p] * 10 + digit_to_int(argv[i][tmp]);
                    tmp++;
                    if (tmp >= strlen(argv[i])) {
                        fprintf(stderr, "%s\n", "Bad format of input prefix4");
                        return 1;
                    }
            }

            if (argv[i][tmp] == '.') {
                p++;
                int_test = 0;
                tmp++;
                if (p > 3 || tmp >= strlen(argv[i])) {
                    fprintf(stderr, "%s\n", "Bad format of input prefix5");
                    return 1;
                }
            }
            else {
                if (strlen(argv[i]) == tmp + 2) {
                    preffix_list[i - 1].mask = digit_to_int(argv[i][tmp + 1]);
                }
                else if (strlen(argv[i]) == tmp + 3) {
                    preffix_list[i - 1].mask = digit_to_int(argv[i][tmp + 1]) * 10 + digit_to_int(argv[i][tmp + 2]);
                }
                else {
                    fprintf(stderr, "%s\n", "Bad format of input prefix6");
                    return 1;
                }
                break;
            }
        }}
    }


    // Sorting input prefixs by mask
    std::sort(preffix_list.begin(), preffix_list.end(), [](ip_addr x, ip_addr y) {
        return x.mask < y.mask;   
    });
    
    if (log > 0) {
        preffix_list.erase(preffix_list.begin());
        preffix_list.erase(preffix_list.begin());
    }

    // Validity check
    bool is_valid = true;
    for (auto a : preffix_list) {
        if (!is_preffix_valid(&a)) {
            is_valid = false;
            fprintf(stderr, "Ivalid address fuck prefix: %d.%d.%d.%d/%d\n", a.part[0], a.part[1], a.part[2], a.part[3], a.mask);
        }
    }
    if (!is_valid) {
        exit(1);
    }

	int saddr_size = 0;
	int data_size = 0;
    struct sockaddr saddr;

    unsigned char *buffer = (unsigned char *) malloc(MAX_SIZE_OF_SOCKET); 
    if (buffer == NULL) {
        fprintf(stderr, "%s\n", "Intern error with creating dynamic memory.");
        exit(1);
    }

    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
     
    if (sock < 0) {
        perror("Error in creating socket");
        return 2;
    }

    // Start ncourses
    initscr();          
    int row;
    double util;

    /******* This part was inspired by http://www.binarytides.com/packet-sniffer-code-in-c-using-linux-sockets-bsd-part-2/ *******/
    while(1) {

        // Print statistic
        clear();
        mvprintw(0, 0, "IP Prefix"); mvprintw(0, 20, "Max hosts"); mvprintw(0, 35, "Allocated addresses"); mvprintw(0, 60, "Utilization"); 
        row = 1;
        for (auto a : preffix_list) {
            mvprintw(row, 0, "%d.%d.%d.%d/%d", a.part[0], a.part[1], a.part[2], a.part[3], a.mask);
            mvprintw(row, 20, "%ld", 0);
            mvprintw(row, 20, "%ld", get_max_hosts(a.mask));

            mvprintw(row, 35, "%d", a.allocated);
            util = (double) a.allocated/ (double) get_max_hosts(a.mask) * 100.0;
            
            mvprintw(row, 60, "%.2f%%", util);
            row++;
        } 
        refresh();          /* Print it on to the real screen */

        saddr_size = sizeof(saddr);

        // Receive the incoming sockets
        data_size = recvfrom(sock , buffer , MAX_SIZE_OF_SOCKET , 0 , &saddr , (socklen_t*) &saddr_size);
        if (data_size < 0 ) {
            endwin();
            perror("Error in receive packets.\n");
            return 2;

        }

	    // Get struct which represent ip header
	    struct iphdr *ip_header = (struct iphdr*) (buffer + sizeof(struct ethhdr));

	    if (ip_header->protocol == UDP) {
	        int ip_header_len = ip_header->ihl*4;
	        struct udphdr *udp_header = (struct udphdr*)(buffer + ip_header_len  + sizeof(struct ethhdr));

            // Process only dhcp messages
	        if (ntohs(udp_header->source) == 67 || ntohs(udp_header->source) == 68 || ntohs(udp_header->source) == 5500) {
	            int header_size =  sizeof(struct ethhdr) + ip_header_len + sizeof(udp_header);

                /******* End of part *******/
                int msg_type = get_message_type(buffer + header_size + 240);

                switch (msg_type) {

                    case DHCPACK:
                    {
                        ip_addr* yiaddr = get_yiaddr(buffer + header_size);
                        if (yiaddr == NULL) {
                            fprintf(stderr, "%s\n", "Intern error with creating dynamic memory.");
                            exit(1);
                        }
                        int int_yiaddr = joinIP(yiaddr);
                        it_type iterator = dhcp_table.find(int_yiaddr);
                        if (iterator != dhcp_table.end()) {
                            free(iterator->second->addr);
                            dhcp_table.erase(iterator);
                        }
                        allc_addr* allcd = (allc_addr*) malloc(sizeof(allc_addr));
                        if (allcd == NULL) {
                            fprintf(stderr, "%s\n", "Intern error with creating dynamic memory.");
                            exit(1);
                        }
                        allcd->addr = yiaddr;
                        allcd->lease_time = get_lease_time(buffer + header_size + 240);
                        allcd->allc_time = time(0);
                        dhcp_table[int_yiaddr] = allcd;
                        break;
                    }

                    case DHCPRELEASE:
                    {
                        ip_addr* ciaddr = get_ciaddr(buffer + header_size);
                        if (ciaddr == NULL) {
                            fprintf(stderr, "%s\n", "Intern error with creating dynamic memory.");
                            exit(1);
                        }
                        int int_ciaddr= joinIP(ciaddr);
                        free(ciaddr);
                        it_type iterator = dhcp_table.find(int_ciaddr);
                        if (iterator != dhcp_table.end()) {
                            free(iterator->second->addr);
                            dhcp_table.erase(iterator);
                        }
                        break;

                    }
                }

	            //PrintData(buffer + header_size + 236, (data_size - header_size) );
            }
	    }

         // Make statistic
        for (auto &a : preffix_list) {
            a.allocated = 0;

            for (it_type iterator = dhcp_table.begin(); iterator != dhcp_table.end(); iterator++) {
                time_t actual_time = time(0);
                // Check lease time
                if (actual_time >= iterator->second->allc_time + iterator->second->lease_time) {
                    dhcp_table.erase(iterator);
                }
                else {
                    if (is_in_preffix(&a, iterator->second->addr)) {
                       // printf("%s\n", "yes");
                        a.allocated += 1;
                    }
                }
            }
        }
        
    }

    free(buffer);
    close(sock);

	return 0;
 }

/**
  *
  * Inits array of ip_addr.
  *
  * \param addrs Array of ip adress.
  * \param size Size of the array.
  *
  */
void init_ip_addrs(ip_addr* addrs, int size) {

    for (int i = 0; i < size; i++) {
        addrs[i].part[0] = 0;
        addrs[i].part[1] = 0;
        addrs[i].part[2] = 0;
        addrs[i].part[3] = 0;
        addrs[i].mask = 0;
        addrs[i].allocated = 0;
    }

}

/**
  *
  * Catch signal for end of the program - CTRL+C and ends the program.
  *
  */
void sig_handler(int sig) {

    // Only for a warning
    (void) sig; 

    endwin();
    if (buffer != NULL) {
        free(buffer);
    }     
    for (it_type iterator = dhcp_table.begin(); iterator != dhcp_table.end(); iterator++) {
        free(iterator->second->addr);
        free(iterator->second); 
    }

    close(sock);
    exit(0);

}

/**
  *
  * Function convert digit char to integer .
  *
  * \param d Char to convert.
  *
  * \return Digital in integer.
  *
  */
int digit_to_int(char d) {

     char str[2];
     if (!isdigit(d)) {
        fprintf(stderr, "%s\n", "Bad format of input prefix");
        exit(1);
     }

     str[0] = d;
     str[1] = '\0';
     return (int) strtol(str, NULL, 10);
}

  long int get_max_hosts(int mask) {

    if (mask == 31) {
      return 2;
    } 
    else if (mask == 32) {
      return 1;
    }
    else {
      return (( long int) pow(2, 32 - mask)) - 2;
    }

 }

/**
  *
  * Functions print ip address for debug reasons .
  *
  * \param addr Struct which represent ip address.
  *
  */
void print_ip_addr(ip_addr* addr) {

    printf("%d.%d.%d.%d", addr->part[0], addr->part[1], addr->part[2], addr->part[3]);
    if (addr->mask == 0) {
        printf("%c\n", '\n');
    }
    return;

}

/**
  *
  * Function return the type of DHCP message which starts after bootp header.
  *
  * \param data Data Data of DHCP message.
  *
  * \return Message type or NOT_DHCP_MSG if not a DHCP message.
  *
  */
int get_message_type(unsigned char* data) {

    if (data[0] != 53) {
        return NOT_DHCP_MSG;
    }

    if (DEBUG) {
        switch (data[2]) {

            case NOT_DHCP_MSG: 

                printf("%s\n", "NOT_DHCP_MSG");
                break;

            case DHCPDISCOVER:

                printf("%s\n", "DHCPDISCOVER");
                break;

            case DHCPOFFER:

                printf("%s\n", "DHCPOFFER");
                break;

            case DHCPREQUEST:

                printf("%s\n", "DHCPREQUEST");
                break;

            case DHCPACK:

                printf("%s\n", "DHCPACK");
                break;   

            case DHCPRELEASE:

                printf("%s\n", "DHCPRELEASE");
                break; 

            }

    }
   
    return data[2];

}

/**
  *
  * Function return ip adress which client gets.
  *
  * \param data Data Data of DHCP message.
  *
  * \return addr Message struct if ip address
  *
  */
ip_addr* get_yiaddr(unsigned char* data) {

    ip_addr* addr = (ip_addr*) malloc(sizeof(ip_addr));
    if (addr == NULL) {
        return NULL;
    }
    addr->part[0] = data[16];
    addr->part[1] = data[17];
    addr->part[2] = data[18];
    addr->part[3] = data[19];

    if (DEBUG) {
        print_ip_addr(addr);
    }

    return addr;

}

/**
  *
  * Function return ip adress which client has.
  *
  * \param data Data Data of DHCP message.
  *
  * \return addr Message struct if ip address
  *
  */
ip_addr* get_ciaddr(unsigned char* data) {

    ip_addr* addr = (ip_addr*) malloc(sizeof(ip_addr));
    if (addr == NULL) {
        return NULL;
    }
    addr->part[0] = data[12];
    addr->part[1] = data[13];
    addr->part[2] = data[14];
    addr->part[3] = data[15];

    if (DEBUG) {
        print_ip_addr(addr);
    }

    return addr;

}

/**
  *
  * Function return lease time.
  *
  * \param data Data Data of DHCP message which starts after bootp header.
  *
  * \return addr Time lease time.
  *
  */
unsigned int get_lease_time(unsigned char* data) {

    int len;
    int i = 0;
    unsigned char* tmp = data;
    while (tmp[i] != 51) {
        len = tmp[i+1];
        i += 2 + len;
    }   

    int time = ((unsigned int) tmp[i+2]) << 24;
    time += ((unsigned int) tmp[i+3]) << 16;
    time += ((unsigned int) tmp[i+4]) << 8;
    time += ((unsigned int) tmp[i+5]);
    if (DEBUG) {
         printf("Lease time is: %d\n", time);
    }
   
    return time;

}

/**
  *
  * Function return ip adress in unsigned int version.
  *
  * \param addr Struct if ip address.
  *
  * \return ip address in int.
  *
  */
unsigned int joinIP(ip_addr* addr) {

    unsigned int ip = addr->part[0] << 24;
    ip += addr->part[1] << 16;
    ip += addr->part[2] << 8;
    ip += addr->part[3];
    return ip;

}

/**
  *
  * Function checks validity of ip address.
  *
  * \param addr Struct off ip address.
  *
  * \return True if is valid, otherwise false.
  *
  */
bool is_preffix_valid(ip_addr* addr) {

    if (addr->mask > 32) {
        fprintf(stderr, "%s\n", "Bad format of input prefix - please enter mask in range 0-32");
        exit(1);
    }
    if (addr->mask == 32) {
      return true;
    }

    unsigned int int_preffix = joinIP(addr);
    if ((int_preffix << addr->mask) == 0) {
        return true;
    }
    else {
        return false;
    }
}

/**
  *
  * Function return if addr belongs to ip prefix.
  *
  * \param prefix Prefix if the network.
  *
  * \return addr client address.
  *
  */
bool is_in_preffix(ip_addr* preffix, ip_addr* addr) {

    long int int_preffix = joinIP(preffix);
    long int int_addr = joinIP(addr);
    //unsigned int int_addr = 167772161;
    int mask_opposite = 32 - preffix->mask;

    if (preffix->mask == 32) {
      if (int_preffix == int_addr) {
        return true;
      }
      else {
        return false;
      }
    }
    else if ((int_preffix >> mask_opposite) == (int_addr >> mask_opposite)) {
        if (preffix->mask == 31) {
          return true;
        }
        long int bitwise_mask = (long int) pow(2, mask_opposite) - 1;

        int_addr &= bitwise_mask;

        if (int_addr == 0 ||  int_addr == get_max_hosts(preffix->mask) + 1) {
            return false;
        }
        else {
            return true;
        }
    }
    else {
        return false;
    }

}
