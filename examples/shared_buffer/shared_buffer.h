#define IP_DF 0x4000
#define BUFF_SIZE 1800
#define BUFF_CAP 1000

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
  unsigned int tcphdr_len_;
  unsigned int iphdr_len_;
  unsigned int ethhdr_len_;
  unsigned int payload_len_;
  struct tcphdr* tcphdr_;
  struct iphdr* iphdr_;
  struct ethhdr* ethhdr_;
  unsigned char* payload_;
} pkt_container;

typedef struct metadata{
  size_t cell_size;
  uint32_t pkt_final_dst;
} metadata;

typedef struct cb_metadata{
  struct metadata* cb_md;
  size_t capacity;
  struct metadata* head;
  struct metadata* tail;
}cb_metadata;

typedef struct circular_buffer{
  void *buffer;     // data buffer
  void *buffer_end; // end of data buffer
  size_t capacity;  // maximum number of items in the buffer
  size_t count;     // number of items in the buffer
  size_t sz;        // size of each item in the buffer
  void *head;       // pointer to head
  void *tail;       // pointer to tail
  struct cb_metadata buffer_metadata; // pointer to metadata buffer;
} circular_buffer;


static int cb_init(circular_buffer *cb, size_t capacity, size_t sz){
  printk(KERN_INFO "CircularBuffer: starting initialization function for circular buffer.\n");
  cb->buffer = kmalloc(capacity * sz, GFP_KERNEL);
  if(cb->buffer == NULL){
    // handle error
    printk(KERN_INFO "CircularBuffer: Initialization function for circular buffer has failed.\n");
    return -ENOMEM;
  }
  printk(KERN_INFO "CircularBuffer: cb is allocated.\n");
  cb->buffer_metadata.cb_md = (struct metadata*)kmalloc(capacity * sizeof(struct metadata) , GFP_KERNEL);
  if(cb->buffer_metadata.cb_md == NULL){
    // handle error
    printk(KERN_INFO "CircularBuffer: Initialization function for circular buffer metadata has failed.\n");
    return -ENOMEM;
  }
  printk(KERN_INFO "CircularBuffer: metadata cb is allocated.\n");
  cb->buffer_end = (char *)cb->buffer + capacity * sz;

  cb->capacity = capacity;
  cb->buffer_metadata.capacity = capacity;

  cb->count = 0;

  cb->sz = sz;

  cb->head = cb->buffer;
  cb->buffer_metadata.head = cb->buffer_metadata.cb_md;

  cb->tail = cb->buffer;
  cb->buffer_metadata.tail = cb->buffer_metadata.cb_md;
  printk(KERN_INFO "CircularBuffer: Initialization function for circular buffer executed.\n");
  return 0;
}

static void cb_free(circular_buffer *cb){
  kfree(cb->buffer);
  kfree(cb->buffer_metadata.cb_md);
  // clear out other fields too, just to be safe
}

static int cb_push_back(circular_buffer *cb, struct pkt_container* pkt){
  if(cb->count == cb->capacity){
    // handle error (error handling should move to the actual module)
    printk(KERN_INFO "CircularBuffer: There is no more capacity in the circular buffer.\n");
    return -1;
  }
  char* tmp_head_pointer  = cb->head;

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


  int data_size = sizeof(unsigned int)*4 + pkt->tcphdr_len_ + pkt->iphdr_len_ + pkt->ethhdr_len_ + pkt->payload_len_;
  cb->buffer_metadata.head->cell_size = data_size;
  cb->buffer_metadata.head->pkt_final_dst = pkt->iphdr_->daddr;
  // Now we coppied all information we had in the packet container to one cell of the ring buffer.
  // The next step is to update the pointer to point to the next cell of the ring buffer.
  
  cb->buffer_metadata.head ++; 
  cb->head = (char*)cb->head + cb->sz;

  if(cb->head == cb->buffer_end){
    cb->head = cb->buffer;
    cb->buffer_metadata.head = cb->buffer_metadata.cb_md;
  }

  cb->count++;
  printk(KERN_INFO "CircularBuffer: One element with the size of %d has been pushed to the circular buffer successfully, number of elements: %zu.\n", data_size, cb->count);
  return 0;
}


static int cb_pop_front(circular_buffer *cb, struct pkt_container* pkt){
  if(cb->count == 0){
    printk(KERN_INFO "CircularBuffer: There is no more data in the circular buffer.\n");
    // handle error (error handling should move to the actual module)
    return -1;
  }

  // Here we received an empty packet container struct and we want to fill its different
  // fields one-by-one based on the raw memory.
  char* tmp_tail_pointer = cb->tail;

  pkt->tcphdr_len_ = *( (unsigned int*)tmp_tail_pointer ); 
  tmp_tail_pointer = (char*)tmp_tail_pointer + sizeof(unsigned int);

  pkt->iphdr_len_ = *( (unsigned int*)tmp_tail_pointer ); 
  tmp_tail_pointer = (char*)tmp_tail_pointer + sizeof(unsigned int);

  pkt->ethhdr_len_ = *( (unsigned int*)tmp_tail_pointer ); 
  tmp_tail_pointer = (char*)tmp_tail_pointer + sizeof(unsigned int);

  pkt->payload_len_ = *( (unsigned int*)tmp_tail_pointer ); 
  tmp_tail_pointer = (char*)tmp_tail_pointer + sizeof(unsigned int);

  pkt->tcphdr_ = (struct tcphdr*)tmp_tail_pointer;
  tmp_tail_pointer = (char*)tmp_tail_pointer + pkt->tcphdr_len_;

  pkt->iphdr_ = (struct iphdr*)tmp_tail_pointer;
  tmp_tail_pointer = (char*)tmp_tail_pointer + pkt->iphdr_len_;
  
  pkt->ethhdr_ = (struct ethhdr*)tmp_tail_pointer;
  tmp_tail_pointer = (char*)tmp_tail_pointer + pkt->ethhdr_len_;

  pkt->payload_ = (unsigned char*)tmp_tail_pointer;
  tmp_tail_pointer = (char*)tmp_tail_pointer + pkt->payload_len_;

  // Now we extract all members of packet container one-by-one from the memory.
  // We should move the tail to the next cell of the ring buffer.
  int data_size = cb->buffer_metadata.tail->cell_size;
  cb->buffer_metadata.tail ++;
  cb->tail = (char*)cb->tail + cb->sz;

  if(cb->tail == cb->buffer_end){
    cb->tail = cb->buffer;
    cb->buffer_metadata.tail = cb->buffer_metadata.cb_md;
  }
  cb->count--;
 
  printk(KERN_INFO "CircularBuffer: One element with size of %d has been poped from the circular buffer successfully, number of elements: %zu.\n", data_size, cb->count);
  return data_size;
}

static int cb_push_back_raw(struct circular_buffer* cb, char* item, size_t item_size){
  if(cb->count == cb->capacity){
    // handle error (error handling should move to the actual module)
    printk(KERN_INFO "CircularBuffer: There is no more capacity in the circular buffer.\n");
    return -1;
  }
  memcpy(cb->head, item, item_size);
  cb->buffer_metadata.head->cell_size = item_size;
  cb->buffer_metadata.head->pkt_final_dst = 0;
  // Now we coppied all information we had in the packet container to one cell of the ring buffer.
  // The next step is to update the pointer to point to the next cell of the ring buffer.
  cb->buffer_metadata.head ++; 
  cb->head = (char*)cb->head + cb->sz;

  if(cb->head == cb->buffer_end){
    cb->head = cb->buffer;
    cb->buffer_metadata.head = cb->buffer_metadata.cb_md;
  }

  cb->count++;
  printk(KERN_INFO "CircularBuffer: One element has been pushed to the circular buffer successfully, number of elements: %zu.\n", cb->count);
  return 0;

}

static int cb_pop_front_raw(struct circular_buffer* cb, char** item, struct metadata* md){
  if(cb->count == 0){
    printk(KERN_INFO "CircularBuffer: There is no more data in the circular buffer.\n");
    // handle error (error handling should move to the actual module)
    return -1;
  }
  if(cb->buffer_metadata.tail->pkt_final_dst == 0){
    printk(KERN_INFO "CircularBuffer: The final destination in metadata field hasn't been specified.\n");
    return -1;
  }
  
  *item = (char*)cb->tail;
  int item_size = cb->buffer_metadata.tail->cell_size;
  
  md->cell_size = cb->buffer_metadata.tail->cell_size;
  md->pkt_final_dst = cb->buffer_metadata.tail->pkt_final_dst;

  // Now we extract all members of packet container one-by-one from the memory.
  // We should move the tail to the next cell of the ring buffer.
  int data_size = cb->buffer_metadata.tail->cell_size;
  cb->buffer_metadata.tail ++;
  cb->tail = (char*)cb->tail + cb->sz;

  if(cb->tail == cb->buffer_end){
    cb->tail = cb->buffer;
    cb->buffer_metadata.tail = cb->buffer_metadata.cb_md;
  }
  cb->count--;
 
  printk(KERN_INFO "CircularBuffer: One element has been poped from the circular buffer successfully, number of elements: %zu.\n", cb->count);
  return item_size;
}


// ***************** End-hosts specifications ***************//
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
    printk(KERN_INFO "Hosts_info: Initialization function for hosts_info has failed.\n");
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
    printk(KERN_INFO "Hosts_info: No more capacity for new hosts, Falied to add a new host.\n");
    return -1;
  }
  memcpy(hosts_info->hosts_ptr, &host_info, sizeof(struct host));
  hosts_info->hosts_ptr ++; 
  hosts_info->count ++;
  printk(KERN_INFO "Hosts_info: number of hosts is: %u.\n", hosts_info->count);
  return 0;
}

static int get_host(struct hosts* hosts_info, struct host* host_info, unsigned int index){
  if(index >= hosts_info->count){
    printk(KERN_INFO "Hosts_info: The index to get host is out of valid range.\n");
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



