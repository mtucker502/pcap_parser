# pcap_parser

## Description
This script came from a need to quickly analzye PCAP files for total packets, total packets from a specific source, retransmissions count.

If multiple files are provided they will be diffed to show packet loss between the two capture points.

## Example 

This example is a ftp-data flow so data is sent from the server to the client.

```bash
$ python pcap_parser.py 1.1.1.1 server.pcap client.pcapng

---------------

Examining server.pcap
PCAP format detected
Total Packets: 71764
Total Packets From 1.1.1.1: 51901
Total Sequence Numbers From 1.1.1.1 51901
Total Unique Sequence Nubmers From 1.1.1.1: 51221
Total Retransmissions from 1.1.1.1: 680
Processed in 2.045785 seconds

---------------

Examining client.pcapng
PCAP-NG format detected
Total Packets: 71502
Total Packets From 1.1.1.1: 51389
Total Sequence Numbers From 1.1.1.1: 51389
Total Unique Sequence Nubmers From 1.1.1.1: 51171
Total Retransmissions from 1.1.1.1: 218
Processed in 5.926773 seconds

---------------

Multiple PCAP files detected. Performing analysis....
Packets lost between Capture Point 1 and 2: 512
```

## TODO

Add more analysis for multiple PCAPs
