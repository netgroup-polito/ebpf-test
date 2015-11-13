# ebpf-test

eBPF application that parses HTTP packets and extracts (and prints on screen) the URL contained in the GET/POST request. (not completed yet)

eBPF is used as SOCKET_FILTER attached to eth0 interface. only packet of type ip and tcp containing HTTP GET/POST are returned to userspace, others dropped

python script prints on stdout the first line of the HTTP GET/POST

# Usage

Need BPF Compiler Collection [BCC](https://github.com/iovisor/bcc)
Follow [INSTALL](https://github.com/iovisor/bcc/blob/master/INSTALL.md)

To run:

```Shell
$ sudo python http-parse.py
```