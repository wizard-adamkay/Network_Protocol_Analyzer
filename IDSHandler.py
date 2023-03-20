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
        self.scanIndexes = [0, 0]
        self.lastReachedAlertLine = 0

    def scanOnce(self):
        self.reset()
        if exists("temp.pcap"):
            remove("temp.pcap")
        wrpcap("temp.pcap", self.parent.packetHandler.fullPacketList)
        s = subprocess.Popen(["snort", "-Afull", "-X", "-c", self.parent.snortConfPath, "-r", "temp.pcap", "-q"])
        s.communicate()
        self.scanAllPackets()
        if exists("temp.pcap"):
            remove("temp.pcap")

    def scanAllPackets(self):
        if not self.parent.packetHandler.fullPacketList:
            return
        filesInDir = [f for f in listdir(self.path) if isfile(join(self.path, f))]
        lastPacketTime = self.parent.packetHandler.fullPacketList[-1].time
        firstPacketTime = self.parent.packetHandler.fullPacketList[self.scanIndexes[0]].time
        for file in filesInDir:
            if "snort.log" in file:
                if getsize(self.path+'/'+file) == 0:
                    continue
                pcap = rdpcap(self.path + "/" + file)
                if pcap[-1].time < firstPacketTime or pcap[0].time > lastPacketTime:
                    continue
                for packet in pcap:
                    try:
                        index = self.parent.packetHandler.fullPacketList.index(packet, self.scanIndexes[0], -1)
                    except ValueError:
                        continue
                    self.parent.packetListView.markAsThreat(index)
        self.scanIndexes[0] = self.scanIndexes[1]
        self.scanIndexes[1] = len(self.parent.packetHandler.fullPacketList) - 1

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

    def addThreat(self, packet):
        alertFile = self.parent.snortPath + "/alert"
        if not exists(alertFile):
            return
        file = open(alertFile, 'r')
        for index in range(self.lastReachedAlertLine):
            file.readline()
        while True:
            try:
                line = file.readline()
                if not line:
                    break
                header = line.strip()
                classification = file.readline().strip()
                dateSrcDest = file.readline().strip()
                proto = file.readline().strip()
                flags = file.readline().strip()
                print(f"header: {header}")
                print(f"classification: {classification}")
                print(f"dateSrcDest: {dateSrcDest}")
                print(f"proto: {proto}")
                print(f"flags: {flags}")
                file.readline()
                self.lastReachedAlertLine += 6
            except:
                break
        file.close()


    def reset(self):
        self.threats = []
        self.scanIndexes = [0, 0]
        self.lastReachedAlertLine = 0
