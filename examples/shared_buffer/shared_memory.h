#define IP_DF 0x4000
#define BUFF_CELL_SIZE 1800
#define BUFF_CAP 1000
#define SHM_KEY 0x1234

// **************** Helper functions ***********************//
void change_address_to_string(unsigned int addr,char * ip_string){
  int i;
  for(i=0; i<4; i++)
    ip_string[i] = (addr >> i*8) & 0xFF;
}

unsigned int inet_addr(char *str){
  int a, b, c, d;
  char arr[4];
  sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d);
  arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d;
  return *(unsigned int *)arr;
}


//****************** Circular buffer ************************//
typedef struct pkt_container{
  uint16_t tcphdr_len_;
  uint16_t iphdr_len_;
  uint16_t ethhdr_len_;
  uint16_t payload_len_;
  struct rte_tcp_hdr* tcphdr_;
  struct rte_ipv4_hdr* iphdr_;
  struct rte_ether_hdr* ethhdr_;
  unsigned char* payload_;
} pkt_container;

typedef struct metadata{
  uint16_t size;
  uint32_t pkt_final_dst;
} metadata;


typedef struct buffer_cell{
  char cell_content[BUFF_CELL_SIZE];
  struct metadata cell_metadata;
}buffer_cell;


typedef struct circular_buffer{
  struct buffer_cell buffer[BUFF_CAP];     // data buffer
  struct buffer_cell* buffer_end; // end of data buffer
  size_t count;     // number of items in the buffer
  struct buffer_cell* head;       // pointer to head
  struct buffer_cell* tail;       // pointer to tail
} circular_buffer;


static int cb_init(circular_buffer *cb){
  printf("CircularBuffer: starting initialization function for circular buffer.\n");
  cb->buffer_end = cb->buffer + BUFF_CAP;

  cb->count = 0;

  cb->head = cb->buffer;
  cb->tail = cb->buffer;
  printf("CircularBuffer: Initialization function for circular buffer executed.\n");
  return 0;
}


static int cb_push_back(circular_buffer *cb, struct pkt_container* pkt){
  if(cb->count == BUFF_CAP){
    // handle error (error handling should move to the actual module)
    printf("CircularBuffer: There is no more capacity in the circular buffer.\n");
    return -1;
  }
  char* tmp_head_pointer  = (char*) cb->head->cell_content;

  // Here, we received a pointer to a packet container with a packet inside it.
  // We want to write the different parts of container one-by-one to be able to
  // extract it at the receiving point.
  memcpy(tmp_head_pointer, (char*)&(pkt->tcphdr_len_), sizeof(pkt->tcphdr_len_));
  tmp_head_pointer =  (char*)tmp_head_pointer + sizeof(pkt->tcphdr_len_);

  
  memcpy(tmp_head_pointer, (char*)&(pkt->iphdr_len_), sizeof(pkt->iphdr_len_));
  tmp_head_pointer =  (char*)tmp_head_pointer + sizeof(pkt->iphdr_len_);


  memcpy(tmp_head_pointer, (char*)&(pkt->ethhdr_len_), sizeof(pkt->ethhdr_len_));
  tmp_head_pointer =  (char*)tmp_head_pointer + sizeof(pkt->ethhdr_len_);

  memcpy(tmp_head_pointer, (char*)&(pkt->payload_len_), sizeof(pkt->payload_len_));
  tmp_head_pointer =  (char*)tmp_head_pointer + sizeof(pkt->payload_len_);

  memcpy(tmp_head_pointer, (char*)(pkt->tcphdr_), pkt->tcphdr_len_);
  tmp_head_pointer =  (char*)tmp_head_pointer + pkt->tcphdr_len_;

  memcpy(tmp_head_pointer, (char*)(pkt->iphdr_), pkt->iphdr_len_);
  tmp_head_pointer =  (char*)tmp_head_pointer + pkt->iphdr_len_;
  
  memcpy(tmp_head_pointer, (char*)(pkt->ethhdr_), pkt->ethhdr_len_);
  tmp_head_pointer =  (char*)tmp_head_pointer + pkt->ethhdr_len_;
  
  memcpy(tmp_head_pointer, (char*)(pkt->payload_), pkt->payload_len_);
  tmp_head_pointer = (char*)tmp_head_pointer + pkt->payload_len_;


  uint16_t data_size = sizeof(unsigned int)*4 + pkt->tcphdr_len_ + pkt->iphdr_len_ + pkt->ethhdr_len_ + pkt->payload_len_;
  cb->head->cell_metadata.size = data_size;
  cb->head->cell_metadata.pkt_final_dst = rte_be_to_cpu_32(pkt->iphdr_->dst_addr); 

  // Now we coppied all information we had in the packet container to one cell of the ring buffer.
  // The next step is to update the pointer to point to the next cell of the ring buffer.
  
  cb->head = cb->head ++;

  if(cb->head == cb->buffer_end){
    cb->head = cb->buffer;
  }

  cb->count++;
  printf( "CircularBuffer: One element with the size of %d has been pushed to the circular buffer successfully, number of elements: %zu.\n", data_size, cb->count);
  return 0;
}


static int cb_pop_front(circular_buffer *cb, struct pkt_container* pkt){
  if(cb->count == 0){
    printf( "CircularBuffer: There is no more data in the circular buffer.\n");
    // handle error (error handling should move to the actual module)
    return -1;
  }

  // Here we received an empty packet container struct and we want to fill its different
  // fields one-by-one based on the raw memory.
  char* tmp_tail_pointer = (char*) cb->tail->cell_content;

  pkt->tcphdr_len_ = *((uint16_t*)tmp_tail_pointer); 
  tmp_tail_pointer = (char*)tmp_tail_pointer + sizeof(pkt->tcphdr_len_);

  pkt->iphdr_len_ = *((uint16_t*)tmp_tail_pointer ); 
  tmp_tail_pointer = (char*)tmp_tail_pointer + sizeof(pkt->iphdr_len_);

  pkt->ethhdr_len_ = *((uint16_t*)tmp_tail_pointer); 
  tmp_tail_pointer = (char*)tmp_tail_pointer + sizeof(pkt->ethhdr_len_);

  pkt->payload_len_ = *((uint16_t*)tmp_tail_pointer); 
  tmp_tail_pointer = (char*)tmp_tail_pointer + sizeof(pkt->payload_len_);

  pkt->tcphdr_ = (struct rte_tcp_hdr*)tmp_tail_pointer;
  tmp_tail_pointer = (char*)tmp_tail_pointer + pkt->tcphdr_len_;

  pkt->iphdr_ = (struct rte_ipv4_hdr*)tmp_tail_pointer;
  tmp_tail_pointer = (char*)tmp_tail_pointer + pkt->iphdr_len_;
  
  pkt->ethhdr_ = (struct rte_ether_hdr*)tmp_tail_pointer;
  tmp_tail_pointer = (char*)tmp_tail_pointer + pkt->ethhdr_len_;

  pkt->payload_ = (unsigned char*)tmp_tail_pointer;
  tmp_tail_pointer = (char*)tmp_tail_pointer + pkt->payload_len_;

  // Now we extract all members of packet container one-by-one from the memory.
  // We should move the tail to the next cell of the ring buffer.
  int data_size = (int) cb->tail->cell_metadata.size;
  cb->tail = cb->tail ++;

  if(cb->tail == cb->buffer_end){
    cb->tail = cb->buffer;
  }
  cb->count--;
 
  printf( "CircularBuffer: One element with size of %d has been poped from the circular buffer successfully, number of elements: %zu.\n", data_size, cb->count);
  return data_size;
}

static int cb_push_back_raw(struct circular_buffer* cb, char* item, size_t item_size){
  if(cb->count == BUFF_CAP){
    // handle error (error handling should move to the actual module)
    printf( "CircularBuffer: There is no more capacity in the circular buffer.\n");
    return -1;
  }
  memcpy(cb->head->cell_content, item, item_size);
  cb->head->cell_metadata.size = item_size;
  cb->head->cell_metadata.pkt_final_dst = 0;
  // Now we coppied all information we had in the packet container to one cell of the ring buffer.
  // The next step is to update the pointer to point to the next cell of the ring buffer.
  cb->head = cb->head ++;

  if(cb->head == cb->buffer_end){
    cb->head = cb->buffer;
  }

  cb->count++;
  printf( "CircularBuffer: One element has been pushed to the circular buffer successfully, number of elements: %zu.\n", cb->count);
  return 0;

}

static int cb_pop_front_raw(struct circular_buffer* cb, struct buffer_cell* bc){
  if(cb->count == 0){
    printf( "CircularBuffer: There is no more data in the circular buffer.\n");
    // handle error (error handling should move to the actual module)
    return -1;
  }
  if(cb->tail->cell_metadata.pkt_final_dst == 0){
    printf( "CircularBuffer: The final destination in metadata field hasn't been specified.\n");
    return -1;
  }
  
  memcpy(bc->cell_content, cb->tail->cell_content, cb->tail->cell_metadata.size); 
  bc->cell_metadata.size = cb->tail->cell_metadata.size;
  bc->cell_metadata.pkt_final_dst = cb->tail->cell_metadata.pkt_final_dst;
  
  // Now we extract all members of packet container one-by-one from the memory.
  // We should move the tail to the next cell of the ring buffer.
  cb->tail = cb->tail ++;

  if(cb->tail == cb->buffer_end){
    cb->tail = cb->buffer;
  }
  cb->count--;
 
  printf( "CircularBuffer: One element has been poped from the circular buffer successfully, number of elements: %zu.\n", cb->count);
  return cb->tail->cell_metadata.size;
}


// ***************** End-hosts specifications ***************//
/*
typedef struct host{
  uint8_t MACaddr[ETH_ALEN];
  uint32_t IPaddr;
  uint16_t TCPaddr;
  uint8_t middleBox_MAC[ETH_ALEN];
  uint32_t middleBox_IP;
  uint16_t middleBox_UDP;
}host;

typedef struct hosts{
  unsigned int capacity;
  unsigned int count;
  struct host* hosts_head;
  struct host* hosts_ptr;
}hosts; 

static int hosts_initialization(struct hosts* hosts_info, unsigned int init_capacity){
  hosts_info->capacity = init_capacity; 
  hosts_info->count = 0;
  hosts_info->hosts_head = (struct host*)kmalloc(init_capacity*sizeof(host),  GFP_KERNEL);
  if(hosts_info->hosts_head == NULL){
    printf( "Hosts_info: Initialization function for hosts_info has failed.\n");
    return -ENOMEM;
  }
  hosts_info->hosts_ptr = hosts_info->hosts_head;
  return 0;
}

static void hosts_termination(struct hosts* hosts_info){
  kfree(hosts_info->hosts_head);  
}

static int add_host(struct hosts* hosts_info, struct host host_info){
  if(hosts_info->count == hosts_info->capacity){
    printf( "Hosts_info: No more capacity for new hosts, Falied to add a new host.\n");
    return -1;
  }
  memcpy(hosts_info->hosts_ptr, &host_info, sizeof(struct host));
  hosts_info->hosts_ptr ++; 
  hosts_info->count ++;
  printf( "Hosts_info: number of hosts is: %u.\n", hosts_info->count);
  return 0;
}

static int get_host(struct hosts* hosts_info, struct host* host_info, unsigned int index){
  if(index >= hosts_info->count){
    printf( "Hosts_info: The index to get host is out of valid range.\n");
    return -1;
  }
  struct host* tmp_host_ptr = hosts_info->hosts_head + index;
  memcpy(host_info->MACaddr, tmp_host_ptr->MACaddr, ETH_ALEN*sizeof(uint8_t));
  host_info->IPaddr = tmp_host_ptr->IPaddr;
  host_info->TCPaddr = tmp_host_ptr->TCPaddr;
  memcpy(host_info->middleBox_MAC, tmp_host_ptr->middleBox_MAC, ETH_ALEN*sizeof(uint8_t));
  host_info->middleBox_IP = tmp_host_ptr->middleBox_IP;
  host_info->middleBox_UDP = tmp_host_ptr->middleBox_UDP;
  return 0;
}
*/


