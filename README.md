#Application-layer traffic processing with eBPF

The eBPF has been recently proposed as an extension of the BPF virtual machine, defined many years ago and still used for packet filtering. The eBPF comes with additional features (e.g., more powerful virtual machines) as well as an accompanying compiler (LLVM) that can generate directly eBPF code. Furthermore, eBPF is now part of the standard Linux kernel, named as "BPF".
This project aims at:
- studying the architecture of the eBPF
- evaluating the possible applications of the eBPF (e.g., through the available samples) and its degree of interaction with the LLVM compiler
- making a proof of concept of an eBPF application that parses HTTP packets and extracts (and prints on screen) the URL contained in the GET/POST request.

[http://par.frisso.net/home/projects](http://par.frisso.net/home/projects)

#http-parse

eBPF application that parses HTTP packets and extracts (and prints on screen) the URL contained in the GET/POST request.

eBPF program 'http_filter' is used as SOCKET_FILTER attached to eth0 interface.
Only packet of type ip and tcp containing HTTP GET/POST are returned to userspace, others dropped

Python script uses bcc BPF Compiler Collection by iovisor (https://github.com/iovisor/bcc) and prints on stdout the first line of the HTTP GET/POST request containing the url

# Usage

Require:
- BPF Compiler Collection [BCC](https://github.com/iovisor/bcc)
- Follow [INSTALL](https://github.com/iovisor/bcc/blob/master/INSTALL.md) guide

To run:

```Shell
$ sudo python http-parse.py
```