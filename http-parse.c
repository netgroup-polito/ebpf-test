#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define IP_TCP 	6   
#define ETH_HLEN 14

/*
//definitions are already included in <bcc/proto.h> 
//here there is a copy for a better understanding of the code

struct ethernet_t {
  unsigned long long  dst:48;
  unsigned long long  src:48;
  unsigned int        type:16;
} BPF_PACKET_HEADER;

struct ip_t {
  unsigned char   ver:4;           // byte 0
  unsigned char   hlen:4;
  unsigned char   tos;
  unsigned short  tlen;
  unsigned short  identification; // byte 4
  unsigned short  ffo_unused:1;
  unsigned short  df:1;
  unsigned short  mf:1;
  unsigned short  foffset:13;
  unsigned char   ttl;             // byte 8
  unsigned char   nextp;
  unsigned short  hchecksum;
  unsigned int    src;            // byte 12
  unsigned int    dst;            // byte 16
} BPF_PACKET_HEADER;

struct udp_t {
  unsigned short sport;
  unsigned short dport;
  unsigned short length;
  unsigned short crc;
} BPF_PACKET_HEADER;

struct tcp_t {
  unsigned short  src_port;   // byte 0
  unsigned short  dst_port;
  unsigned int    seq_num;    // byte 4
  unsigned int    ack_num;    // byte 8
  unsigned char   offset:4;    // byte 12
  unsigned char   reserved:4;
  unsigned char   flag_cwr:1;
  unsigned char   flag_ece:1;
  unsigned char   flag_urg:1;
  unsigned char   flag_ack:1;
  unsigned char   flag_psh:1;
  unsigned char   flag_rst:1;
  unsigned char   flag_syn:1;
  unsigned char   flag_fin:1;
  unsigned short  rcv_wnd;
  unsigned short  cksum;      // byte 16
  unsigned short  urg_ptr;
} BPF_PACKET_HEADER;
*/

/*eBPF program.
  Filter IP and TCP packets, having payload not empty
  and containing "HTTP", "GET", "POST" ... as first bytes of payload
  if the program is loaded as PROG_TYPE_SOCKET_FILTER
  and attached to a socket
  return  0 -> DROP the packet
  return -1 -> KEEP the packet and return it to user space (userspace can read it from the socket_fd )
*/
int http_filter(struct __sk_buff *skb) {

	u8 *cursor = 0;

	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
	//filter IP packets (ethernet type = 0x0800)
  if (!(ethernet->type == 0x0800)){
		goto DROP;	
	}

	struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
	//filter TCP packets (ip next protocol = 0x06)
  if (ip->nextp != IP_TCP) {
		goto DROP;
	}

  u32  tcp_header_length = 0;
  u32  ip_header_length = 0;
  u32  payload_offset = 0;
  u32  payload_length = 0;

  struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

  //calculate ip header length
  //value to multiply * 4
  //e.g. ip->hlen = 5 ; IP Header Length = 5 x 4 byte = 20 byte
	ip_header_length = ip->hlen << 2;    //SHL 2 -> *4 multiply
  
  //calculate tcp header length
  //value to multiply *4
  //e.g. tcp->offset = 5 ; TCP Header Length = 5 x 4 byte = 20 byte
  tcp_header_length = tcp->offset << 2; //SHL 2 -> *4 multiply

  //calculate patload offset and lenght
	payload_offset = ETH_HLEN + ip_header_length + tcp_header_length; 
  payload_length = ip->tlen - ip_header_length - tcp_header_length;
    
  //http://stackoverflow.com/questions/25047905/http-request-minimum-size-in-bytes
  //minimum lenght of http request is always geater than 7 bytes
  //avoid invalid access memory
  //include empty payload
  if(payload_length < 7){
      goto DROP;
  }

  //load firt 7 byte of payload into payload_array
  //direct access to skb not allowed
  unsigned long payload_array[7];
  int i = 0;
  int j = 0;
  for (i = payload_offset ; i < (payload_offset + 7) ; i++){
    payload_array[j] = load_byte(skb , i);
    j++;
  }

  //find a match with an HTTP message
  //HTTP
  if ( (payload_array[0] == 'H') && (payload_array[1] == 'T') && (payload_array[2] == 'T') && (payload_array[3] == 'P')){
    goto KEEP;
  }
  //GET
  if ( (payload_array[0] == 'G') && (payload_array[1] == 'E') && (payload_array[2] == 'T') ){
    goto KEEP;
  }
  //POST
  if ( (payload_array[0] == 'P') && (payload_array[1] == 'O') && (payload_array[2] == 'S') && (payload_array[3] == 'T')){
    goto KEEP;
  }
  //PUT
  if ( (payload_array[0] == 'P') && (payload_array[1] == 'U') && (payload_array[2] == 'T') ){
    goto KEEP;
  }
  //DELETE
  if ( (payload_array[0] == 'D') && (payload_array[1] == 'E') && (payload_array[2] == 'L') && (payload_array[3] == 'E') && (payload_array[4] == 'T') && (payload_array[5] == 'E')){
    goto KEEP;
  }
  //HEAD
  if ( (payload_array[0] == 'H') && (payload_array[1] == 'E') && (payload_array[2] == 'A') && (payload_array[3] == 'D')){
    goto KEEP;
  }

  //no HTTP match
  goto DROP;

  //keep the packet and send it to userspace retruning -1
  KEEP:
  return -1;

//drop the packet returning 0
DROP:
return 0;

}