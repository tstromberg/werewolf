# pcap-feed

pcap-feed copies one interface's packets into a pcap fifo. It opens the
packet socket and sets promiscuous mode as root, writes a pcap header,
then becomes `_pcap` with no capabilities and a seccomp filter of `read`,
`write`, `poll`, `ppoll`, `clock_gettime` and `exit_group`. The reader named
in `/etc/werewolf/pcap-feed` is the only other process that can open the
fifo. That open, and each open after the previous reader has closed, is
given its own header.

Suricata and Zeek take it. They analyze. They never hold the capability
that captures.
