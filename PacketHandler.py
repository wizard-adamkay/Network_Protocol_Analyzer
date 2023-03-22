class PacketHandler:
    def __init__(self, parent):
        self.parent = parent
        self.fullPacketList = []
        self.sessions = {}

    def handleNewPacket(self, packet):
        self.fullPacketList.append(packet)
        if "TCP" in packet:
            key = self.getSessionKey(packet)
            if key in self.sessions:
                self.sessions[key].append(len(self.fullPacketList)-1)
            else:
                self.sessions[key] = [len(self.fullPacketList)-1]
        if self.parent.filterBar.filterPacket(packet, len(self.fullPacketList)):
            self.parent.packetListView.addToList(len(self.fullPacketList), packet)

    def clear(self):
        self.parent.IDSHandler.reset()
        self.fullPacketList.clear()
        self.sessions.clear()
        if self.parent.actionBar.started:
            self.parent.actionBar.stopCapture()
        self.parent.packetListView.clear()
        self.parent.packetListView.markedPackets.clear()
        self.parent.packetListView.threatsPacketNum.clear()

    def getSessionKey(self, packet):
        s=""
        if "IP" in packet:
            s = str(sorted([packet.payload.src, packet["TCP"].sport, packet.payload.dst, packet["TCP"].dport], key=str))
        return s

    def fromSessionGet(self, dictNum):
        sender = []
        receiver = []
        if dictNum < 0 or dictNum >= len(self.sessions):
            return sender, receiver
        packetNums = list(self.sessions.values())[dictNum]
        firstPacket = self.fullPacketList[packetNums[0]]
        senderIP = firstPacket.payload.src
        for packetNum in packetNums:
            packet = self.fullPacketList[packetNum]
            if packet.payload.src == senderIP:
                sender.append(packet)
            else:
                receiver.append(packet)
        return sender, receiver
