from os import listdir
from os.path import isfile, join
from scapy.all import rdpcap


class IDSHandler():
    def __init__(self, parent=None):
        self.parent = parent
        self.path = self.parent.snortPath
        self.threats = []

    def scanAllPackets(self):
        if not self.parent.packetHandler:
            return
        filesInDir = [f for f in listdir(self.path) if isfile(join(self.path, f))]
        lastPacketTime = self.parent.packetHandler.fullPacketList[-1].time
        firstPacketTime = self.parent.packetHandler.fullPacketList[0].time
        for file in filesInDir:
            if "snort.log" in file:
                time = int(file.split(".")[-1])
                if time > lastPacketTime:
                    continue
                pcap = rdpcap(self.path + "/" + file)
                if pcap[-1].time < firstPacketTime or pcap[0].time > lastPacketTime:
                    continue
                for packet in pcap:
                    if packet in self.parent.packetHandler.fullPacketList:
                        pass
