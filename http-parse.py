#!/usr/bin/python
#
#Bertrone Matteo - Polytechnic of Turin
#November 2015
#
#eBPF application that parses HTTP packets 
#and extracts (and prints on screen) the URL contained in the GET/POST request.
#
#eBPF is used as SOCKET_FILTER attached to eth0 interface.
#only packet of type ip and tcp containing HTTP GET/POST are returned to userspace, others dropped
#
#python userspace script prints on stdout the first line of the HTTP GET/POST


from __future__ import print_function
from bcc import BPF

import sys
import socket
import os

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

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

	/*filter "ip and tcp"*/
	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
	if (!(ethernet->type == 0x0800)){
		goto DROP;	
	}

	struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
  if (ip->nextp != IP_TCP) {
    goto DROP;
  }

  //begin processing

  struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

  u32  tcp_hlen = 0;
  u32  ip_hlen = 0;
  u32  payload_offset = 0;
  u32 payload_len = 0;
  u32 payload_end = 0;
  u32 payload_ptr = 0;

	//retrieve the position of the payload of the tcp packet
  ip_hlen = ip->hlen << 2;
  tcp_hlen = tcp->offset << 2;
	payload_offset = ETH_HLEN + ip_hlen + tcp_hlen; 
  payload_len = ip->tlen - ip_hlen -tcp_hlen;
  payload_end = payload_offset + payload_len; //Starting from byte 0 of the eth frame
  payload_ptr = payload_offset;

  if(payload_len == 0){
      goto DROP;
  }
  
  //load first 7 payload bytes in dat array -> for the http filter
  unsigned long dat[7];
  int i = 0;
  int j = 0;
  for (i = payload_offset ; i < (payload_offset + 7) ; i++){
    dat[j] = load_byte(skb , i);
    j++;
  }

  //HTTP
  if ( (dat[0] == 'H') && (dat[1] == 'T') && (dat[2] == 'T') && (dat[3] == 'P')){
    goto KEEP;
  }
  //GET
  if ( (dat[0] == 'G') && (dat[1] == 'E') && (dat[2] == 'T') ){
    goto KEEP;
  }
  //POST
  if ( (dat[0] == 'P') && (dat[1] == 'O') && (dat[2] == 'S') && (dat[3] == 'T')){
    goto KEEP;
  }
  //PUT
  if ( (dat[0] == 'P') && (dat[1] == 'U') && (dat[2] == 'T') ){
    goto KEEP;
  }
  //DELETE
  if ( (dat[0] == 'D') && (dat[1] == 'E') && (dat[2] == 'L') && (dat[3] == 'E') && (dat[4] == 'T') && (dat[5] == 'E')){
    goto KEEP;
  }
  //HEAD
  if ( (dat[0] == 'H') && (dat[1] == 'E') && (dat[2] == 'A') && (dat[3] == 'D')){
    goto KEEP;
  }

  goto DROP;

  KEEP:
  //-1 return the packet to userspace listening on the socket
  return -1;

DROP:
  //0 drop the packet
  return 0;
}
"""

#convert string to hex
#for debug - to print raw packet in hex
def toHex(s):
    lst = []
    for ch in s:
        hv = hex(ord(ch)).replace('0x', '')
        if len(hv) == 1:
            hv = '0'+hv
        lst.append(hv)
    
    return reduce(lambda x,y:x+y, lst)

# initialize BPF
b = BPF(text=bpf_text)

#load function
fn = b.load_func("handle_ingress", BPF.SOCKET_FILTER)

#attach function to pysical interface
BPF.attach_raw_socket(fn, "eth0")

#get socket fd
sfd = fn.sock
s = socket.fromfd(sfd,socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP)
s.setblocking(True)

while 1:
  #print ("Reading Packet ...")
  str = os.read(sfd,2048)

  #DEBUG - print raw packet in hex
  #hexstr = toHex(str)
  #print ("%s" % hexstr)

  #convert into bytearray
  ba = bytearray(str)
  
  ETH_HLEN = 14
  
  #total length
  ip_tlen = ba[ETH_HLEN + 2]
  ip_tlen = ip_tlen << 8
  ip_tlen =ip_tlen + ba[ETH_HLEN+3]
  
  #ip headet lenght
  ip_hlen = ba[ETH_HLEN]
  ip_hlen = ip_hlen & 0x0F
  ip_hlen = ip_hlen << 2

  #tcp header lenght
  tcp_hlen = ba[ETH_HLEN + ip_hlen + 12]
  tcp_hlen = tcp_hlen & 0xF0
  tcp_hlen = tcp_hlen >> 2
  
  #payload offset
  payload_offset = ETH_HLEN + ip_hlen + tcp_hlen
  
  #print only first line of HTTP GET/POST - terminate with 0xOD 0xOA (\r\n)
  #if we want to print all the header print until \r\n\r\n
  for i in range (payload_offset-1,len(ba)):
    if (ba[i]== 0x0A):
      if (ba[i-1] == 0x0D):
        break
    print ("%c" % chr(ba[i]), end = "")
  print("")

