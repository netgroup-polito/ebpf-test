# ebpf-test

eBPF application that parses HTTP packets and extracts (and prints on screen) the URL contained in the GET/POST request. (not completed yet)

# Usage

Need BPF Compiler Collection [BCC](https://github.com/iovisor/bcc)
Follow [INSTALL guide](https://github.com/iovisor/bcc/blob/master/INSTALL.md)

To run:

```Shell
# sudo python http-parse.py
```