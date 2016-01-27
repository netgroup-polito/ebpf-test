#Application-layer traffic processing with eBPF

The eBPF has been recently proposed as an extension of the BPF virtual machine, defined many years ago and still used for packet filtering. The eBPF comes with additional features (e.g., more powerful virtual machines) as well as an accompanying compiler (LLVM) that can generate directly eBPF code. Furthermore, eBPF is now part of the standard Linux kernel, named as "BPF".
This project aims at:
- studying the architecture of the eBPF
- evaluating the possible applications of the eBPF (e.g., through the available samples) and its degree of interaction with the LLVM compiler
- making a proof of concept of an eBPF application that parses HTTP packets and extracts (and prints on screen) the URL contained in the GET/POST request.

[http://par.frisso.net/home/projects](http://par.frisso.net/home/projects)

#http-parse

eBPF application that parses HTTP packets and extracts (and prints on screen) the URL contained in the GET/POST request. This simple version truncates url if not entirely contained in only one packet.

[http-parse.c](http-parse.c) <br />
[http-parse.py](http-parse.py)

eBPF socket filter. <br />
Filters IP and TCP packets, containing "HTTP", "GET", "POST" in payload. <br />
Program is loaded as PROG_TYPE_SOCKET_FILTER and attached to a socket, bind to eth0. <br />
Matching packets are forwarded to user space, others dropped by the filter.<br />
<br />
Python script loads eBPF program, creates raw socket, bind it to eth0 interface and attach eBPF program to the socket created. <br />
Reads filtered raw packets from the socket and prints on stdout the first line of the HTTP GET/POST request.

#http-parse v2

eBPF application that parses HTTP packets and extracts (and prints on screen) the URL contained in the GET/POST request. Complete version: manage also long urls splitted in multiple packets.

[http-parse-v2.c](http-parse-v2.c) <br />
[http-parse-v2.py](http-parse-v2.py)

eBPF socket filter.<br />
Filters IP and TCP packets, containing "HTTP", "GET", "POST" in payload and all subsequent packets belonging to the same session, having the same (ip_src,ip_dst,port_src,port_dst).<br />
Program is loaded as PROG_TYPE_SOCKET_FILTER and attached to a socket, bind to eth0. <br />
Matching packets are forwarded to user space, others dropped by the filter.<br />
<br />
Python script reads filtered raw packets from the socket, if necessary reassembles packets belonging to the same session, and prints on stdout the first line of the HTTP GET/POST request. <br />

# Usage

Require:
- BPF Compiler Collection [BCC](https://github.com/iovisor/bcc)
- Follow [INSTALL](https://github.com/iovisor/bcc/blob/master/INSTALL.md) guide

# Example

```Shell
matteo@ebpf-env:~/ebpf-test$ sudo python http-parse-v2.py 
GET /pipermail/iovisor-dev/ HTTP/1.1
HTTP/1.1 200 OK
GET /favicon.ico HTTP/1.1
HTTP/1.1 404 Not Found
GET /pipermail/iovisor-dev/2016-January/thread.html HTTP/1.1
HTTP/1.1 200 OK
GET /pipermail/iovisor-dev/2016-January/000046.html HTTP/1.1
HTTP/1.1 200 OK
```

# To run:

```Shell
$ sudo python http-parse.py
$ sudo python http-parse-v2.py
```