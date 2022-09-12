/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2019 George Washington University
 *            2015-2019 University of California Riverside
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * The name of the author may not be used to endorse or promote
 *       products derived from this software without specific prior
 *       written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * monitor.c - an example using onvm. Print a message each p package received
 ********************************************************************/

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "../shared_buffer/shared_memory.h"
#include<sys/ipc.h>
#include<sys/shm.h>
#include<sys/types.h>

#define NF_TAG "isolated_nf"
#define PKTMBUF_POOL_NAME "MProc_pktmbuf_pool"

/* number of package between each print */
static uint32_t print_delay = 1000000;

static uint32_t total_packets = 0;
static uint64_t last_cycle;
static uint64_t cur_cycles;


/* Shared Memory */
struct circular_buffer* upstream_cb;

/* shared data structure containing host port info */
extern struct port_info *ports;

/*
 * Print a usage message
 */
static void
usage(const char *progname) {
        printf("Usage:\n");
        printf("%s [EAL args] -- [NF_LIB args] -- -p <print_delay>\n", progname);
        printf("%s -F <CONFIG_FILE.json> [EAL args] -- [NF_LIB args] -- [NF args]\n\n", progname);
        printf("Flags:\n");
        printf(" - `-p <print_delay>`: number of packets between each print, e.g. `-p 1` prints every packets.\n");
}

/*
 * Parse the application arguments.
 */
static int
parse_app_args(int argc, char *argv[], const char *progname) {
        int c;

        while ((c = getopt(argc, argv, "p:")) != -1) {
                switch (c) {
                        case 'p':
                                print_delay = strtoul(optarg, NULL, 10);
                                RTE_LOG(INFO, APP, "print_delay = %d\n", print_delay);
                                break;
                        case '?':
                                usage(progname);
                                if (optopt == 'p')
                                        RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                                else if (isprint(optopt))
                                        RTE_LOG(INFO, APP, "Unknown option `-%c'.\n", optopt);
                                else
                                        RTE_LOG(INFO, APP, "Unknown option character `\\x%x'.\n", optopt);
                                return -1;
                        default:
                                usage(progname);
                                return -1;
                }
        }
        return optind;
}

/*
 * This function displays stats. It uses ANSI terminal codes to clear
 * screen when called. It is called from a single non-master
 * thread in the server process, when the process is run with more
 * than one lcore enabled.
 */
static void
do_stats_display(struct rte_mbuf *pkt) {
        const char clr[] = {27, '[', '2', 'J', '\0'};
        const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};
        static uint64_t pkt_process = 0;
        struct rte_ipv4_hdr *ip;

        pkt_process += print_delay;

        /* Clear screen and move to top left */
        printf("%s%s", clr, topLeft);

        printf("PACKETS\n");
        printf("-----\n");
        printf("Port : %d\n", pkt->port);
        printf("Size : %d\n", pkt->pkt_len);
        printf("Hash : %u\n", pkt->hash.rss);
        printf("N°   : %" PRIu64 "\n", pkt_process);
        printf("\n\n");

        ip = onvm_pkt_ipv4_hdr(pkt);
        if (ip != NULL) {
                onvm_pkt_print(pkt);
        } else {
                printf("No IP4 header found\n");
        }
}

static int
callback_handler(__attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        cur_cycles = rte_get_tsc_cycles();

        if (((cur_cycles - last_cycle) / rte_get_timer_hz()) > 5) {
                printf("Total packets received: %" PRIu32 "\n", total_packets);
                last_cycle = cur_cycles;
        }

        return 0;
}

static int
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
  static uint32_t counter = 0;
  total_packets++;
  if (++counter == print_delay) {
          //do_stats_display(pkt);
          counter = 0;
  }

  meta->action = ONVM_NF_ACTION_DROP;
  /*
  if (onvm_pkt_is_ipv4(pkt) & onvm_pkt_is_tcp(pkt)){
    RTE_LOG(INFO, APP, "TCP Packet received\n");
    // Extracting headers of the packet
    struct rte_ether_hdr* eth_header = onvm_pkt_ether_hdr(pkt);
    struct rte_ipv4_hdr* ipv4_header = onvm_pkt_ipv4_hdr(pkt);
    struct rte_tcp_hdr* tcp_header = onvm_pkt_tcp_hdr(pkt);
    
    // Getting the header length.
    uint16_t eth_header_len = (uint16_t) sizeof(struct rte_ether_hdr); 
    uint16_t ipv4_header_len = (uint16_t) sizeof(struct rte_ipv4_hdr); 
    uint16_t tcp_header_len = onvm_pkt_tcp_hdr_len(pkt); 
    
    // Extracting payload of the packet
    int payload_len = onvm_pkt_payload_len(pkt);
    if(payload_len < 0){
      printf("There is a problem with getting payload_len.\n");
      return 0; 
    } 
    unsigned char* payload = onvm_pkt_payload(pkt);

    // Creating a packet container to save the packet in our shared memory
    struct pkt_container pc = {.tcphdr_len_ = tcp_header_len,
                               .iphdr_len_ = ipv4_header_len,
                               .ethhdr_len_ = eth_header_len,
                               .payload_len_ = payload_len,
                               .tcphdr_ = tcp_header,
                               .iphdr_ = ipv4_header,
                               .ethhdr_ = eth_header,
                               .payload_ = payload                           
    };
    if(cb_push_back(upstream_cb, &pc) < 0){
      printf("Failed to push packet upstream_cb!\n");
    }
    


    //rte_pktmbuf_dump(stdout, pkt, 1500);        
    int pkt_payload_len = onvm_pkt_payload_len(pkt);
    printf("the tcp header len: %u\n", tcp_header_len);
    printf("The tcp packet payload len: %d\n", pkt_payload_len);
    // meta->action = ONVM_NF_ACTION_DROP;
    //return 0;
  }
  */


    if (pkt->port == 0)
      meta->destination = 1; // Connected to 418
    else
      meta->destination = 0; // Connected to 416
    return 0;
}

void nf_setup(struct onvm_nf_local_ctx *nf_local_ctx){

  struct rte_mempool *pktmbuf_pool;
  pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
  printf("Flag in send\n"); 
  if(pktmbuf_pool == NULL){
    onvm_nflib_stop(nf_local_ctx);
    rte_exit(EXIT_FAILURE, "cannot find mbuf pool!\n"); 
  }
  
  struct rte_mbuf* pkt;
  struct onvm_pkt_meta *pmeta;
  struct rte_ether_hdr eth_header;
  struct rte_ipv4_hdr ipv4_header;
  struct rte_tcp_hdr tcp_header;

  pkt = rte_pktmbuf_alloc(pktmbuf_pool);
  if (pkt == NULL){
    printf("Failded to allocate packet\n");
  }

  /* let's try to send a packet*/
  struct pkt_container pc;
  printf("Tail cell size in upstream_cb is: %zu\n", upstream_cb->tail_ind);

        
  if(cb_pop_front(upstream_cb, &pc) < 0){
    printf("Failed to pop from the circular buffer\n"); 
  }
  // Ethernet Header
  struct rte_ether_hdr *eth = (struct rte_ether_hdr*) rte_pktmbuf_append(pkt, pc.ethhdr_len_);
  memcpy(eth, pc.ethhdr_, pc.ethhdr_len_);
  
  // IP header
  struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr*) rte_pktmbuf_append(pkt, pc.iphdr_len_);
  memcpy(ip, pc.iphdr_, pc.iphdr_len_);

  // TCP header
  struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr*) rte_pktmbuf_append(pkt, pc.tcphdr_len_);
  memcpy(tcp, pc.tcphdr_, pc.tcphdr_len_);

  // Payload of the packet
  unsigned char *payload = (unsigned char*) rte_pktmbuf_append(pkt, pc.payload_len_);
  memcpy(payload, pc.payload_, pc.payload_len_);

  // Writing the metadata for packet
  pmeta = onvm_get_pkt_meta(pkt);
  pmeta-> destination = 0; // send it to 416
  pmeta-> action = ONVM_NF_ACTION_OUT;
  
  // Something about hash and rss that I haven't done here.
  // Hopefully it won't be a problem :D

  // Send packet 
  onvm_nflib_return_pkt(nf_local_ctx->nf, pkt);


  // Now let's try to extract 125 bytes from the circular buffer;
  size_t data_size = 125;
  unsigned char* data_ptr = (unsigned char*) malloc(data_size);
  printf("The current size of the circular buffer is: %zu.\n", upstream_cb->aggregated_size);
  if(cb_pop_data_bysize(upstream_cb, data_ptr, data_size) < 0){
    printf("You buddy, you really thought you can implement it in your first trial? heh, good luck\n"); 
  }
  printf("The current size of the circular buffer is: %zu.\n", upstream_cb->aggregated_size);
}


int
main(int argc, char *argv[]) {
        struct onvm_nf_local_ctx *nf_local_ctx;
        struct onvm_nf_function_table *nf_function_table;
        int arg_offset;
        const char *progname = argv[0];

        // Shared memory initialization
        printf("The size of circular_buffer is: %zu\n", sizeof(struct circular_buffer)); 
        int shmid = shmget(SHM_KEY, sizeof(struct circular_buffer), 0644|IPC_CREAT);
        if (shmid == -1) {
          perror("Shared memory");
          return 1;
        }

        upstream_cb =  shmat(shmid, NULL, 0);
        if (upstream_cb == (void *) -1) {
          perror("Shared memory attach");
          return 1;
        }
        printf("Shared memory created without error\n"); 
        
        nf_local_ctx = onvm_nflib_init_nf_local_ctx();
        
        onvm_nflib_start_signal_handler(nf_local_ctx, NULL);

        nf_function_table = onvm_nflib_init_nf_function_table();
        nf_function_table->pkt_handler = &packet_handler;
        nf_function_table->user_actions = &callback_handler;
        nf_function_table->setup = &nf_setup; 

        

        if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG, nf_local_ctx, nf_function_table)) < 0) {
                onvm_nflib_stop(nf_local_ctx);
                if (arg_offset == ONVM_SIGNAL_TERMINATION) {
                        printf("Exiting due to user termination\n");
                        return 0;
                } else {
                        rte_exit(EXIT_FAILURE, "Failed ONVM init\n");
                }
        }
        

        argc -= arg_offset;
        argv += arg_offset;

        if (parse_app_args(argc, argv, progname) < 0) {
                onvm_nflib_stop(nf_local_ctx);
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
        }

        cur_cycles = rte_get_tsc_cycles();
        last_cycle = rte_get_tsc_cycles();

        onvm_nflib_run(nf_local_ctx);

        onvm_nflib_stop(nf_local_ctx);
        printf("If we reach here, program is ending\n");
        return 0;
}
