#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <uv.h>
#include <glib.h>
#include <getopt.h>
#include <time.h>
#include <maxminddb.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#define MAX_RULE_LENGTH 256




// Define the structure to hold the IP information
typedef struct IP_Info {
    char *country_iso_code;
    char *search_engine;
} IP_Info;
MMDB_s *geoip2_country_mmdb ;
MMDB_s *geoip2_domain_mmdb ;
// Your global database instances

MMDB_s *open_ok(const char *db_file, int mode, const char *mode_desc) {
    MMDB_s *mmdb = (MMDB_s *)calloc(1, sizeof(MMDB_s));
    if (NULL == mmdb) {
        printf("could not allocate memory for our MMDB_s struct");
    }
    int status = MMDB_open(db_file, (uint32_t)mode, mmdb);
    if (MMDB_SUCCESS == status){
        return mmdb;
    }else{
        printf("Open mmdb fail!\n");
        free(mmdb);
        return NULL;
    }    
}

// Function to get country ISO code
char *get_country_iso_code(const char *ip_str) {
    
    
    int gai_error, mmdb_error;
    MMDB_lookup_result_s result = MMDB_lookup_string(geoip2_country_mmdb, ip_str, &gai_error, &mmdb_error);
    if (result.found_entry) {
        MMDB_entry_data_s entry_data;
        if (MMDB_get_value(&result.entry, &entry_data, "city", "names","en", NULL) == MMDB_SUCCESS) {
            if (entry_data.has_data) {
                char *country_iso_code = strndup(entry_data.utf8_string, entry_data.data_size);
                return country_iso_code;
            }
        }
    }
    return NULL;
}

// Function to check if the IP belongs to a search engine
char *search_engine_crawler(const char *ip_str) {
    
    int gai_error, mmdb_error;
    MMDB_lookup_result_s result = MMDB_lookup_string(geoip2_domain_mmdb, ip_str, &gai_error, &mmdb_error);
    if (result.found_entry) {
        MMDB_entry_data_s entry_data;
        if (MMDB_get_value(&result.entry, &entry_data, "domain", NULL) == MMDB_SUCCESS) {
            if (entry_data.has_data) {
                char *search_engine = strndup(entry_data.utf8_string, entry_data.data_size);
                return search_engine;
            }
        }
    }
    return NULL;
}

// Function to check IP and return country ISO code and search engine status
IP_Info *check_ip(const char *ip_str) {
    IP_Info *ip_info = malloc(sizeof(IP_Info));
    char *country_iso_code = get_country_iso_code(ip_str);
    ip_info->country_iso_code = malloc((strlen(country_iso_code ? country_iso_code : "aaaa") + 1) * sizeof(char));
    if (country_iso_code) {
        strcpy(ip_info->country_iso_code, country_iso_code);
        free(country_iso_code);
    } else {
        strcpy(ip_info->country_iso_code, "aaaa");
    }
    char *search_engine = search_engine_crawler(ip_str);
    ip_info->search_engine = malloc((strlen(search_engine ? search_engine : "aaaa") + 1) * sizeof(char));
    
    if (search_engine) {
        strcpy(ip_info->search_engine, search_engine);
        free(search_engine);
    } else {
        strcpy(ip_info->search_engine, "aaaa");
    }
    return ip_info;
}





GHashTable *ip_conn_table = NULL;
GHashTable *blocked_ip_table = NULL;
GHashTable *ip_whitelist_table = NULL;
GHashTable *printed_ip_table = NULL;
int block_interval = 600;  // Block for 10 minutes by default
int unblock_interval = 86400;  // Unblock after 1 day by default
char *whitelist_file = NULL;




// Add a function to add an IP address to the iptables
void block_ip(const char *ip_str) {
    char rule[MAX_RULE_LENGTH];
    printf("Blocked IP: %s\n", ip_str);
    snprintf(rule, sizeof(rule), "ipset add blockip %s", ip_str);  // Add IP to the 'myset' IP set
    system(rule);
}

// Add a function to remove an IP address from the ipset
void unblock_ip(const char *ip_str) {
    char rule[MAX_RULE_LENGTH];
    printf("Unblocked IP: %s\n", ip_str);
    snprintf(rule, sizeof(rule), "ipset del myset %s", ip_str);  // Remove IP from the 'myset' IP set
    system(rule);
}


// Read the whitelist from the file
void read_whitelist(const char *file_name) {
    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    FILE *file = fopen(file_name, "r");
    if (file == NULL) {
        fprintf(stderr, "Can't open whitelist file: %s\n", file_name);
        exit(1);
    }

    while ((read = getline(&line, &len, file)) != -1) {
        // Remove the newline character
        line[strcspn(line, "\n")] = 0;
        printf("Whitelist IP: %s\n", line);
        g_hash_table_insert(ip_whitelist_table, g_strdup(line), NULL);
    }

    fclose(file);
    if (line) {
        free(line);
    }
}
// Forward declaration of the function
static unsigned short tcp_checksum(unsigned int source_ip, unsigned int dest_ip, unsigned short *tcp, unsigned short tcp_len);

unsigned short window_sa = 1;
unsigned short window_a = 1;
unsigned short window_pa = 1;
unsigned short window_fa = 1;
static int handle_packet(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(nfa);

    unsigned char *packet_data;
    int packet_len = nfq_get_payload(nfa, &packet_data);

    if (packet_len >= (sizeof(struct iphdr) + sizeof(struct tcphdr))) {
        struct iphdr *iph = (struct iphdr *) packet_data;
        struct tcphdr *tcph = (struct tcphdr *) (packet_data + iph->ihl * 4);

         // Convert source IP to string
        struct in_addr ip_addr;
        ip_addr.s_addr = iph->daddr; // change iph->saddr to iph->daddr
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip_addr, ip_str, sizeof(ip_str));

        // Check if the IP is in the whitelist
       

        time_t *first_conn_time = (time_t*)g_hash_table_lookup(ip_conn_table, ip_str);
        time_t current_time = time(NULL);

        if (first_conn_time == NULL) {
            // This is the first time we see this IP
            first_conn_time = malloc(sizeof(time_t));
            *first_conn_time = current_time;
            g_hash_table_insert(ip_conn_table, g_strdup(ip_str), first_conn_time);
        } else if (current_time - *first_conn_time > block_interval && !g_hash_table_contains(ip_whitelist_table, ip_str)) {
            if (!g_hash_table_contains(blocked_ip_table, ip_str)) {
                g_hash_table_insert(blocked_ip_table, g_strdup(ip_str), NULL);
            }
            // return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_DROP, 0, NULL);
        }
        if (tcph->ack & !(tcph->fin | tcph->syn | tcph->rst | tcph->psh | tcph->urg)) {
            // Handle ACK=1
            // printf("Handle ACK=1\n");
            return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, packet_len, packet_data);
        }
        else if (tcph->syn & tcph->ack) {
            // Handle SYN=1 and ACK=1
            // printf("Handle SYN=1 and ACK=1\n");
            tcph->window = htons(window_sa);
        }
        else if (tcph->psh & tcph->ack) {
            // Handle PSH=1 and ACK=1
            // printf("Handle PSH=1 and ACK=1\n");
            tcph->window = htons(window_pa);
        }
        else if (tcph->fin & tcph->ack) {
            // Handle FIN=1 and ACK=1
            // printf("Handle FIN=1 and ACK=1\n");
            tcph->window = htons(window_fa);
        }
        else {
            return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, packet_len, packet_data);
        }

        // Recompute TCP checksum
        tcph->check = 0;
        unsigned short tcp_len = ntohs(iph->tot_len) - iph->ihl*4;
        tcph->check = tcp_checksum(iph->saddr, iph->daddr, (unsigned short *)tcph, tcp_len);

        return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, packet_len, packet_data);
    }

    return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
}

static unsigned short tcp_checksum(unsigned int source_ip, unsigned int dest_ip, unsigned short *tcp, unsigned short tcp_len) {
    unsigned int cksum;
    unsigned short *source_ip_parts = (unsigned short *) &source_ip;
    unsigned short *dest_ip_parts = (unsigned short *) &dest_ip;

    cksum = 0;
    cksum += *(source_ip_parts++);
    cksum += *source_ip_parts;
    cksum += *(dest_ip_parts++);
    cksum += *dest_ip_parts;
    cksum += htons(IPPROTO_TCP);
    cksum += htons(tcp_len);

    while (tcp_len > 1) {
        cksum += *tcp++;
        tcp_len -= 2;
    }

    if (tcp_len > 0) {
        cksum += *(unsigned char *)tcp;
    }

    while (cksum >> 16) {
        cksum = (cksum & 0xffff) + (cksum >> 16);
    }

    return (unsigned short) ~cksum;
}
uv_loop_t *loop;
uv_poll_t poll_handle;

void on_read(uv_poll_t* handle, int status, int events) {
    int rv;
    char buf[4096] __attribute__ ((aligned));
    rv = recv(nfq_fd((struct nfq_handle *) handle->data), buf, sizeof(buf), 0);
    if (rv >= 0) {
        nfq_handle_packet((struct nfq_handle *) handle->data, buf, rv);
    }
}


void print_ip(gpointer key) {
    if (!g_hash_table_contains(printed_ip_table, key)) {
        IP_Info *ip_info = check_ip(key);
        if (strstr(ip_info->country_iso_code, "BeiJing") == NULL && strstr(ip_info->search_engine, "google") == NULL && strstr(ip_info->search_engine, "baidu") == NULL && strstr(ip_info->search_engine, "sm.cn") == NULL && strstr(ip_info->search_engine, "sogou") == NULL) {
            // printf("Blocked IP: %s\n", ip_info->country_iso_code);
            block_ip(key);
        }
        free(ip_info->country_iso_code);
        free(ip_info->search_engine);
        free(ip_info);
        g_hash_table_insert(printed_ip_table, g_strdup(key), NULL);
    }
    time_t *first_conn_time = (time_t*)g_hash_table_lookup(ip_conn_table, key);
    time_t current_time = time(NULL);
    if (current_time - *first_conn_time > unblock_interval) {
        unblock_ip(key);
        g_hash_table_remove(blocked_ip_table, key);
        g_hash_table_remove(ip_conn_table, key);
    }
}
// The function to be run in the new thread
void *print_blocked_ip_table(void *arg) {
    geoip2_country_mmdb = open_ok("/etc/GeoIP/GeoIP2-City.mmdb", MMDB_MODE_MMAP, "mmap mode");
    if (!geoip2_country_mmdb){
        return NULL;
    }
    geoip2_domain_mmdb = open_ok("/etc/GeoIP/GeoIP2-Domain.mmdb", MMDB_MODE_MMAP, "mmap mode");
    if (!geoip2_domain_mmdb){
        return NULL;
    }
    while (1) {
        // Print the blocked_ip_table here
        
        printf("Contents of blocked_ip_table:\n");
        // Create a copy of all the keys in blocked_ip_table
        GList *keys = g_hash_table_get_keys(blocked_ip_table);

        // Iterate over the keys
        for (GList *element = keys; element != NULL; element = element->next) {
            print_ip(element->data);
        }

        // Free the list of keys
        g_list_free(keys);

        // Sleep for 60 seconds
        sleep(60);
    }
    MMDB_close(geoip2_country_mmdb);
    free(geoip2_country_mmdb);
    MMDB_close(geoip2_domain_mmdb);
    free(geoip2_domain_mmdb);
    return NULL;
}

int main(int argc, char **argv) {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    pthread_t thread_id;
    int fd;
    int opt;
    while ((opt = getopt(argc, argv, "t:u:w:")) != -1) {
        switch (opt) {
        case 't':
            block_interval = atoi(optarg);
            break;
        case 'u':
            unblock_interval = atoi(optarg);
            break;
        case 'w':
            whitelist_file = optarg;
            break;
        default:
            fprintf(stderr, "Usage: %s [-t block_interval] [-u unblock_interval] [-w whitelist_file]\n", argv[0]);
            exit(1);
        }
    }

   
    
    // Initialize the hash tables
    ip_conn_table = g_hash_table_new_full(g_str_hash, g_str_equal, free, free);
    blocked_ip_table = g_hash_table_new_full(g_str_hash, g_str_equal, free, NULL);
    ip_whitelist_table = g_hash_table_new(g_str_hash, g_str_equal);
    printed_ip_table = g_hash_table_new_full(g_str_hash, g_str_equal, free, NULL);
    // If a whitelist file was specified, read it
    if (whitelist_file != NULL) {
        read_whitelist(whitelist_file);
    }
    printf("FuckGFW V0.0.6\n");
    printf("Opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "Error during nfq_open()\n");
        exit(1);
    }
    
    int err = pthread_create(&thread_id, NULL, print_blocked_ip_table, blocked_ip_table);
    if (err != 0) {
        fprintf(stderr, "Error creating thread: %s\n", strerror(err));
        exit(1);
    }
    
    printf("Unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "Error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("Binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "Error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("Binding this socket to queue '0'\n");
    qh = nfq_create_queue(h, 0, &handle_packet, NULL);
    if (!qh) {
        fprintf(stderr, "Error during nfq_create_queue()\n");
        exit(1);
    }

    printf("Setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "Can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);
    
    loop = uv_default_loop();
    uv_poll_init(loop, &poll_handle, fd);
    poll_handle.data = h;
    uv_poll_start(&poll_handle, UV_READABLE, on_read);
    uv_run(loop, UV_RUN_DEFAULT);

    printf("Unbinding from queue 0\n");
    nfq_destroy_queue(qh);

    printf("Closing library handle\n");
    nfq_close(h);
    g_hash_table_destroy(ip_conn_table);
    g_hash_table_destroy(blocked_ip_table);
    g_hash_table_destroy(ip_whitelist_table);
    
    pthread_join(thread_id, NULL);
    return 0;
}
