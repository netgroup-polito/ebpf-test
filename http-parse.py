#!/usr/bin/python
#
#eBPF application that parses HTTP packets 
#and extracts (and prints on screen) the URL contained in the GET/POST request.

from __future__ import print_function
from bcc import BPF
from pyroute2 import IPRoute, NetNS, IPDB, NSPopen

#from builtins import input
from time import sleep
from simulation import Simulation
import sys

ipr = IPRoute()

#it's possible to write a separated .c file but sometimes crashes, so I used inline c code
# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/ctype.h>

#define IP_TCP 	6
#define DEBUG 	1

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

struct IPKey {
  u32 dip;
  u32 sip;
  unsigned short sport;
  unsigned short dport;
};

struct IPLeaf {
  int is_header_splitted;
  long last_use;
};

BPF_TABLE("hash", struct IPKey, struct IPLeaf, sessions, 1024);

int handle_ingress(struct __sk_buff *skb) {
	bpf_trace_printk("--PKT----\\n");

	u32 ifindex_in, *ifindex_p;
	u8 *cursor = 0;

	/*FILTER "ip and tcp"*/
	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));

	if (!(ethernet->type == 0x0800)){
		//not ip -> ignore pkt
		bpf_trace_printk("no_ip_-->ignore\\n");
		goto EOP;	
	}

	struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));

  	if (ip->nextp != IP_TCP) {
    	//not tcp -> ignore pkt
    	bpf_trace_printk("no_tcp-->ignore\\n");
    	goto EOP;
    }
    //Begin processing

    struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

    struct IPKey ipkey;
    struct IPLeaf ipleaf;
    u32  tcp_header_len = 0;
    unsigned char *  payload;

  	u32 dip = ip->dst;
  	u32 sip = ip->src;
  	u64 dmac = ethernet->dst;
  	u64 smac = ethernet->src;
  	unsigned short sport = tcp->src_port;
  	unsigned short dport = tcp->dst_port;

  	ipkey.sip=ip->src;
  	ipkey.dip=ip->dst;
  	ipkey.sport=tcp->src_port;
  	ipkey.dport=tcp->dst_port;

  	/*TO CHECK (zeros not printed) && DEBUG*/
	bpf_trace_printk("macsrc:%x\\n",ethernet->src);
	bpf_trace_printk("macdst:%x\\n",ethernet->dst);
	bpf_trace_printk("ethtyp:%x\\n",ethernet->type);
	bpf_trace_printk("ipsrc:%x\\n",ip->src);
  	bpf_trace_printk("ipdst:%x\\n",ip->dst);
  	bpf_trace_printk("portsrc:%d\\n",sport);
  	bpf_trace_printk("portdst:%d\\n",dport);

  	ipleaf.is_header_splitted = 0;

  	/* retireve the position of the payload of the tcp packet */
	tcp_header_len = tcp->offset << 2;
	bpf_trace_printk("tcp->offset-u32:%d\\n",tcp_header_len);
	payload = ((unsigned char *) tcp + tcp_header_len);
	
	//problems with ebpf addressing - find another way to use pointer
	
  	return 1;

EOP:
  return 0;
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
