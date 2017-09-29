# Mike Tucker - matucker@juniper.net - 2017-09-28
"""
This program expects the PCAP files to only contain one TCP stream. If there are multiple streams, they will be considered one.
"""
import dpkt
import socket
import time
import sys

class pcap_parser(object):
    def __init__(self, file, src):
        self.packet_count = 0
        self.src_count = 0
        self.seq = []
        self.seq_unique = []
        self.processtime = 0.0
        self.src_retransmissions = 0
        self.file = file
        self.src = src
        self.processpcap(self.file)


    def processpcap(self, pcapfile):
        """
        Processes the PCAP file.
        Is run by __init__ automatically
        """
        start = time.time()
        f = open(pcapfile)

        if pcapfile.split('.')[-1] == 'pcap':
            print "PCAP format detected"
            pcap = dpkt.pcap.Reader(f)
        elif pcapfile.split('.')[-1] == 'pcapng':
            print "PCAP-NG format detected"
            pcap = dpkt.pcapng.Reader(f)

        for ts, buf in pcap: #ts, buffer

            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP: # validate valid IP header exists, otherwise skip to next packet
                continue
            ip = eth.data
            if ip.p != dpkt.ip.IP_PROTO_TCP: # validate valid TCP header exists, otherwise skip to next packet
                continue
            tcp = ip.data

            if socket.inet_ntoa(ip.src) == self.src:
                self.seq.append(tcp.seq)
                self.src_count += 1

            self.packet_count += 1
            #print "Packet #", self.packet_count
        self.seq_unique = list(set(self.seq))
        f.close()
        self.processtime = time.time() - start
        self.src_retransmissions = len(self.seq)-len(self.seq_unique) # retransmission = duplicate SEQ number

    def psummary(self):
        """
        Prints a summary of the PCAP file
        """
        print "Total Packets: %d" % (self.packet_count)
        print "Total Packets From %s: %d" % (self.src, self.src_count)
        print "Total Sequence Numbers From %s: %d" % (self.src, len(self.seq))
        print "Total Unique Sequence Nubmers From %s: %d" % (self.src, len(self.seq_unique))
        print "Total Retransmissions from %s: %d" % (self.src, self.src_retransmissions)
        print "Processed in %f seconds" % (self.processtime)

def main():
    if len(sys.argv) < 3:
        print 'ERROR: Please provide the source IP, and the PCAP filename(s)'
        print 'Example: pcap_parser 1.1.1.1 file1 file2...'
        sys.exit(1)

    print "\n---------------\n"
    source = sys.argv[1]

    stats = {}
    for x in range(len(sys.argv)-2, len(sys.argv)):
        print "Examining %s" % (sys.argv[x])
        pcap = pcap_parser(sys.argv[x],source)
        pcap.psummary()
        print "\n---------------\n"
        stats[sys.argv[x]+"_src_count"] = pcap.src_count
        stats[sys.argv[x]+"_src_retransmissions"] = pcap.src_retransmissions

    if len(sys.argv) > 3: # if there are at least 2 PCAP files
        print "Multiple PCAP files detected. Performing analysis...."
        for i in range(len(sys.argv)-1, len(sys.argv)):
            difference = stats[sys.argv[i-1]+"_src_count"] - stats[sys.argv[i]+"_src_count"]
            print "Packets lost between Capture Point %d and %d: %d" % (i-2, i-1, difference)
            #print "Source retransmitted %d packets but only %d were lost. Differnce is %d" % (stats[sys.argv[i-1]+"_src_retransmissions"], difference, stats[sys.argv[i]+"_src_retransmissions"] - difference)

    #todo: add difference between two captures, with delta from transmissions

if __name__ == '__main__':
  main()
