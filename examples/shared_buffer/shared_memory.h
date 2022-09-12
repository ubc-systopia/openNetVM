#define IP_DF 0x4000
#define BUFF_CELL_SIZE 1800
#define BUFF_CAP 1000
#define SHM_KEY 0x1234

#define min(a,b) \
     ({ __typeof__ (a) _a = (a); \
        __typeof__ (b) _b = (b); \
        _a < _b ? _a : _b; })
#define max(a,b) \
     ({ __typeof__ (a) _a = (a); \
        __typeof__ (b) _b = (b); \
        _a > _b ? _a : _b; })


// **************** test shared mamory ***********************//
struct shmseg{
 int cnt;
 int complete;
 char buf[1024];
};


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
  uint16_t cell_head_ind;
  uint16_t size;
  uint32_t pkt_final_dst;
} metadata;


typedef struct buffer_cell{
  char cell_content[BUFF_CELL_SIZE];
  struct metadata cell_metadata;
}buffer_cell;


typedef struct circular_buffer{
  struct buffer_cell buffer[BUFF_CAP];     // data buffer
  size_t count;     // number of items in the buffer
  size_t head_ind;       // pointer to head
  size_t tail_ind;       // pointer to tail
  size_t aggregated_size;
} circular_buffer;


static int cb_init(circular_buffer *cb){
  printf("CircularBuffer: starting initialization function for circular buffer.\n");

  cb->count = 0;

  cb->head_ind = 0;
  cb->tail_ind = 0;
  cb->aggregated_size = 0;
  printf("CircularBuffer: Initialization function for circular buffer executed.\n");
  return 0;
}


static int cb_push_back(circular_buffer *cb, struct pkt_container* pkt){
  if(cb->count == BUFF_CAP){
    // handle error (error handling should move to the actual module)
    printf("CircularBuffer: There is no more capacity in the circular buffer.\n");
    return -1;
  }
  char* tmp_head_pointer  = (char*) cb->buffer[cb->head_ind].cell_content;
  cb->buffer[cb->head_ind].cell_metadata.cell_head_ind = 0;

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
  cb->buffer[cb->head_ind].cell_metadata.size = data_size;
  cb->buffer[cb->head_ind].cell_metadata.pkt_final_dst = rte_be_to_cpu_32(pkt->iphdr_->dst_addr); 

  // Now we coppied all information we had in the packet container to one cell of the ring buffer.
  // The next step is to update the pointer to point to the next cell of the ring buffer.
  cb->aggregated_size += data_size; 
  cb->head_ind = (cb->head_ind + 1) % BUFF_CAP;
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
  if(cb->buffer[cb->tail_ind].cell_metadata.cell_head_ind != 0){
    printf("CircularBuffer: The packet has been fragmented before, you cannot pop it as a complete packet.");
    return -1; 
  }
  // Here we received an empty packet container struct and we want to fill its different
  // fields one-by-one based on the raw memory.
  char* tmp_tail_pointer = (char*) cb->buffer[cb->tail_ind].cell_content;
  
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

  printf("trying to read a packet form cb\n");
  // Now we extract all members of packet container one-by-one from the memory.
  // We should move the tail to the next cell of the ring buffer.
  int data_size = (int) cb->buffer[cb->tail_ind].cell_metadata.size;
  cb->aggregated_size -= data_size;
  cb->tail_ind = (cb->tail_ind + 1) % BUFF_CAP;
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

  char* tmp_head_pointer  = (char*) cb->buffer[cb->head_ind].cell_content;
  cb->buffer[cb->head_ind].cell_metadata.cell_head_ind = 0;

  memcpy(tmp_head_pointer, item, item_size);
  cb->buffer[cb->head_ind].cell_metadata.size = item_size;
  cb->buffer[cb->head_ind].cell_metadata.pkt_final_dst = 0;
  // Now we coppied all information we had in the packet container to one cell of the ring buffer.
  // The next step is to update the pointer to point to the next cell of the ring buffer.
  cb->aggregated_size += item_size;
  cb->head_ind = (cb->head_ind + 1) % BUFF_CAP;
  cb->count++;

  printf( "CircularBuffer: One element has been pushed to the circular buffer successfully, number of elements: %zu.\n", cb->count);
  return 0;

}

static int cb_pop_front_raw(struct circular_buffer* cb, unsigned char* data_ptr, size_t item_size){
  if(cb->count == 0){
    printf( "CircularBuffer: There is no more data in the circular buffer.\n");
    // handle error (error handling should move to the actual module)
    return -1;
  }
  if(cb->buffer[cb->tail_ind].cell_metadata.size < item_size){
    printf("Circular buffer: there is less data than your request in this cell\n"); 
    return -1;
  }

  if(cb->buffer[cb->tail_ind].cell_metadata.pkt_final_dst == 0){
    printf( "CircularBuffer: The final destination in metadata field hasn't been specified.\n");
    return -1;
  }
 
  uint16_t cell_content_head_ind = cb->buffer[cb->tail_ind].cell_metadata.cell_head_ind;
  char* tmp_tail_pointer = (char*) cb->buffer[cb->tail_ind].cell_content + cell_content_head_ind;
 

  // Provding the requested data 
  memcpy(data_ptr, tmp_tail_pointer, item_size); 
  
  // Updating cell metadata after (potentially) partial dequeue
  cb->buffer[cb->tail_ind].cell_metadata.size = cb->buffer[cb->tail_ind].cell_metadata.size - item_size;
  cb->buffer[cb->tail_ind].cell_metadata.cell_head_ind = cb->buffer[cb->tail_ind].cell_metadata.cell_head_ind + item_size;
 
  // We are done with this cell if there is no more data in it
  cb->aggregated_size -= item_size;
  if(cb->buffer[cb->tail_ind].cell_metadata.size == 0){
    cb->tail_ind = (cb->tail_ind + 1) % BUFF_CAP;
    cb->count--;
  }
 
  printf( "CircularBuffer: One element has been poped from the circular buffer successfully, number of elements: %zu.\n", cb->count);
  return item_size;
}

static int cb_pop_data_bysize(circular_buffer *cb,  unsigned char* data_ptr, size_t data_size){
  if(cb->aggregated_size < data_size){
    printf("CircularBuffer: There is less data in circular buffer than requested amount.\n"); 
    return -1;
  }
  unsigned char* tmp_data_ptr = data_ptr;
  size_t remaining_data = data_size;
  size_t tail_cell_size;
  size_t data_size_needed_from_cell;


  while (remaining_data != 0){
    tail_cell_size = cb->buffer[cb->tail_ind].cell_metadata.size;
    data_size_needed_from_cell = min(tail_cell_size, remaining_data);

    if( cb_pop_front_raw(cb, tmp_data_ptr, data_size_needed_from_cell) < 0){
      printf("CircularBuffer: Something bad happened when trying to extract raw data from the queue.\n"); 
      return -1;
    } 
    // We extracted some data and write it to the allocated memory, let's move the pointer for next writes.
    tmp_data_ptr += data_size_needed_from_cell;

    // We extracted some data from the ceell, let's update remaining data required to be extracted in the next rounds
    remaining_data -= data_size_needed_from_cell;
  } 
  
  printf("CircularBuffer: %zu bytes has been poped from the circular buffer and there is %zu bytes in it.\n", data_size, cb->aggregated_size);
  return data_size;
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


