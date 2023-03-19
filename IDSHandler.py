from os import listdir, remove
from os.path import isfile, join, exists, getsize
from scapy.all import rdpcap
from psutil import process_iter
from signal import SIGTERM
import subprocess
from scapy.utils import wrpcap


class IDSHandler:
    def __init__(self, parent=None):
        self.parent = parent
        self.path = self.parent.snortPath
        self.threats = []

    def scanOnce(self):
        if exists("temp.pcap"):
            remove("temp.pcap")
        wrpcap("temp.pcap", self.parent.packetHandler.fullPacketList)
        print(self.parent.snortConfPath)
        s = subprocess.Popen(["snort", "-Afull", "-X", "-c", self.parent.snortConfPath, "-r", "temp.pcap", "-q"])
        s.communicate()
        self.scanAllPackets()

    def scanAllPackets(self):
        if not self.parent.packetHandler.fullPacketList:
            return
        filesInDir = [f for f in listdir(self.path) if isfile(join(self.path, f))]
        lastPacketTime = self.parent.packetHandler.fullPacketList[-1].time
        firstPacketTime = self.parent.packetHandler.fullPacketList[0].time
        for file in filesInDir:
            if "snort.log" in file:
                if getsize(self.path+'/'+file) == 0:
                    continue
                pcap = rdpcap(self.path + "/" + file)
                if pcap[-1].time < firstPacketTime or pcap[0].time > lastPacketTime:
                    continue
                for packet in pcap:
                    try:
                        index = self.parent.packetHandler.fullPacketList.index(packet)
                    except ValueError:
                        continue
                    self.parent.packetListView.markAsThreat(index)
        print("scan complete")

    def scanHandle(self):
        if not self.parent.packetHandler.fullPacketList:
            return
        if self.parent.actionBar.started:
            self.scanAllPackets()
        else:
            self.scanOnce()

    def killConversation(self, packet):
        if "TCP" not in packet and "UDP" not in packet:
            return
        for proc in process_iter():
            for conns in proc.connections(kind='inet'):
                if (conns.laddr.port == packet.sport or conns.laddr.port == packet.dport) and conns.laddr.ip == self.parent.IPAddr:
                    proc.send_signal(SIGTERM)


    def blockIP(self, packet):
        ipToBlock = packet.payload.src if hasattr(packet.payload, "src") and packet.payload.src != self.parent.IPAddr else None
        ipToBlock = packet.payload.dst if hasattr(packet.payload, "dst") and packet.payload.dst != self.parent.IPAddr else ipToBlock
        if ipToBlock is None:
            return
        subprocess.Popen(["iptables", "-A", "INPUT", "-s", ipToBlock, "-j", "DROP"])
