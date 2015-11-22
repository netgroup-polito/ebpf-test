#Application-layer traffic processing with eBPF

The eBPF has been recently proposed as an extension of the BPF virtual machine, defined many years ago and still used for packet filtering. The eBPF comes with additional features (e.g., more powerful virtual machines) as well as an accompanying compiler (LLVM) that can generate directly eBPF code. Furthermore, eBPF is now part of the standard Linux kernel, named as "BPF".
This project aims at:
- studying the architecture of the eBPF
- evaluating the possible applications of the eBPF (e.g., through the available samples) and its degree of interaction with the LLVM compiler
- making a proof of concept of an eBPF application that parses HTTP packets and extracts (and prints on screen) the URL contained in the GET/POST request.

[http://par.frisso.net/home/projects](http://par.frisso.net/home/projects)

#http-parse

eBPF application that parses HTTP packets and extracts (and prints on screen) the URL contained in the GET/POST request. Truncate url if too long.

[http-parse.c](http-parse.c)

eBPF socket filter.
Filter IP and TCP packets, having payload not empty and containing "HTTP", "GET", "POST"
the program is loaded as PROG_TYPE_SOCKET_FILTER and attached to a socket (bind to eth0) <br />
return  0 -> drop the packet <br />
return -1 -> keep the packet and return it to user space (userspace can read it from the socket_fd )

[http-parse.py](http-parse.py)

Python script loads eBPF program into in-kernel virtual machine, create raw socket, bind it to eth0 interface and attach eBPF program to socket created. <br />
Python script read filtered raw packets from the socket and prints on stdout the first line of the HTTP GET/POST request

#http-parse v2

eBPF application that parses HTTP packets and extracts (and prints on screen) the URL contained in the GET/POST request. Complete version: manage long url splitted in N packets.

[http-parse-v2.c](http-parse.c)

eBPF socket filter.
Filter IP and TCP packets, having payload not empty and containing "HTTP", "GET", "POST" 
AND all other packets having same (ip_src,ip_dst,port_src,port_dst). This means beloging to the same "session". <br />
this additional check avoids url truncation, if url is too long userspace script, if necessary, reassembles urls splitted in 2 or more packets.<br />
the program is loaded as PROG_TYPE_SOCKET_FILTER and attached to a socket (bind to eth0) <br />
return  0 -> drop the packet <br />
return -1 -> keep the packet and return it to user space (userspace can read it from the socket_fd )

[http-parse-v2.py](http-parse.py)

Python script loads eBPF program into in-kernel virtual machine, create raw socket, bind it to eth0 interface and attach eBPF program to socket created. <br />
Python script read filtered raw packets from the socket, and after some computation, prints on stdout the first line of the HTTP GET/POST request <br />
It uses shared ebpf map bpf_sessions to keep trace of all the packets of an HTTP session.

# Usage

Require:
- BPF Compiler Collection [BCC](https://github.com/iovisor/bcc)
- Follow [INSTALL](https://github.com/iovisor/bcc/blob/master/INSTALL.md) guide

To run:

```Shell
$ sudo python http-parse.py
$ sudo python http-parse-v2.py
```