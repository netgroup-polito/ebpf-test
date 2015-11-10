#!/usr/bin/python
#
#eBPF application that parses HTTP packets 
#and extracts (and prints on screen) the URL contained in the GET/POST request.

from __future__ import print_function
from bcc import BPF
from pyroute2 import IPRoute, NetNS, IPDB, NSPopen

from time import sleep
import sys

ipr = IPRoute()

#it's possible to write a separated .c file but sometimes crashes, so I used inline c code
# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
//#include <bpf.h>

#define IP_TCP 	6
#define ETH_HLEN 14

/*
//definitions are already included in <bcc/proto.h>

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

int handle_ingress(struct __sk_buff *skb) {

	u32 ifindex_in, *ifindex_p;
	u8 *cursor = 0;

	/*FILTER "ip and tcp"*/
	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));

	if (!(ethernet->type == 0x0800)){
		//not ip -> ignore pkt
		//bpf_trace_printk("no_ip_-->ignore\\n");
		goto EOP;	
	}

	struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));

  	if (ip->nextp != IP_TCP) {
    	//not tcp -> ignore pkt
    	//bpf_trace_printk("no_tcp-->ignore\\n");
    	goto EOP;
    }

  //Begin processing

  struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

  u32  tcp_hlen = 0;
  u32  ip_hlen = 0;
  u32  payload_offset = 0;
  u32 payload_len = 0;
  u32 payload_end = 0;
  u32 payload_ptr = 0;

	u32 dip = ip->dst;
	u32 sip = ip->src;
	u64 dmac = ethernet->dst;
	u64 smac = ethernet->src;
	unsigned short sport = tcp->src_port;
	unsigned short dport = tcp->dst_port;

	/* retireve the position of the payload of the tcp packet */
  ip_hlen = ip->hlen << 2;
  tcp_hlen = tcp->offset << 2;
	payload_offset = ETH_HLEN + ip_hlen + tcp_hlen; 
  payload_len = ip->tlen - ip_hlen -tcp_hlen;
  payload_end = payload_offset + payload_len; //Starting from byte 0 of the eth frame
  payload_ptr = payload_offset;

  if(payload_len == 0){
      goto EOP;
  }
  
  unsigned long dat[7];
  int i = 0;
  int j = 0;
  for (i=payload_offset;i<(payload_offset+7);i++){
    dat[j] = load_byte(skb,i);
    j++;
  }

  //HTTP
  if ( (dat[0] == 'H') && (dat[1] == 'T') && (dat[2] == 'T') && (dat[3] == 'P')){
    bpf_trace_printk("HTTP ------------------------------------------------\\n");
    goto KEEP;
  }
  //GET
  if ( (dat[0] == 'G') && (dat[1] == 'E') && (dat[2] == 'T') ){
    bpf_trace_printk("GET -------------------------------------------------\\n");
    goto KEEP;
  }
  //POST
  if ( (dat[0] == 'P') && (dat[1] == 'O') && (dat[2] == 'S') && (dat[3] == 'T')){
    bpf_trace_printk("POST ------------------------------------------------\\n");
    goto KEEP;
  }
  //PUT
  if ( (dat[0] == 'P') && (dat[1] == 'U') && (dat[2] == 'T') ){
    bpf_trace_printk("PUT -------------------------------------------------\\n");
    goto KEEP;
  }
  //DELETE
  if ( (dat[0] == 'D') && (dat[1] == 'E') && (dat[2] == 'L') && (dat[3] == 'E') && (dat[4] == 'T') && (dat[5] == 'E')){
    bpf_trace_printk("DELETE ------------------------------------------------\\n");
    goto KEEP;
  }
  //HEAD
  if ( (dat[0] == 'H') && (dat[1] == 'E') && (dat[2] == 'A') && (dat[3] == 'D')){
    bpf_trace_printk("HEAD ------------------------------------------------\\n");
    goto KEEP;
  }

  goto EOP;

  KEEP:
  //Do something to send packet to userspace!

  return 1;

EOP:
  return -1;
}
"""

# initialize BPF
b = BPF(text=bpf_text)

#load function in kernel ebpf vm
fn = b.load_func("handle_ingress", BPF.SOCKET_FILTER)

#attach function to pysical interface
BPF.attach_raw_socket(fn, "eth0")

# format output
while 1:

	#(task, pid, cpu, flags, ts, msg) = b.trace_fields()
	(t,p,c,f,t,m) = b.trace_fields()

	#DEBUG ONLY - not stable
	#print bpf_trace_printk
	print("%s" % m)
  #b.trace_print()
