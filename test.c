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


// Forward declaration of the function
static unsigned short tcp_checksum(unsigned int source_ip, unsigned int dest_ip, unsigned short *tcp, unsigned short tcp_len);

unsigned short window_sa = 17;
unsigned short window_a = 17;
unsigned short window_pa = 17;
unsigned short window_fa = 17;

static int handle_packet(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(nfa);

    unsigned char *packet_data;
    int packet_len = nfq_get_payload(nfa, &packet_data);

    if (packet_len >= (sizeof(struct iphdr) + sizeof(struct tcphdr))) {
        struct iphdr *iph = (struct iphdr *) packet_data;
        struct tcphdr *tcph = (struct tcphdr *) (packet_data + iph->ihl * 4);

       
       if (tcph->ack & !(tcph->fin | tcph->syn | tcph->rst | tcph->psh | tcph->urg)) {
            // Handle ACK=1
            // printf("Handle ACK=1\n");
            //return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, packet_len, packet_data);
           tcph->window = htons(window_a);
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

int main(int argc, char **argv) {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;

    printf("Opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "Error during nfq_open()\n");
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

    return 0;
}
