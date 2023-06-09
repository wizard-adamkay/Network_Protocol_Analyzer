import tkinter as tk
from Sniffer import Sniffer


class ActionBar(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(**kw)
        self.parent = parent
        self.started = False
        self.sniffer = Sniffer()

        def startCapture():
            self.parent.packetListView.markedPackets.clear()
            self.parent.packetListView.threatsPacketNum.clear()
            self.parent.packetHandler.clear()
            self.started = True
            queue = self.sniffer.start()
            self.parent.root.after(0, self.packet_adder, queue)
            self.parent.root.after(5000, self.activeScanning)
            self.stopCapture["state"] = "normal"
            self.startCapture["state"] = "disabled"
            self.parent.menu.fileName = ""

        def stopCapture():
            self.started = False
            self.startCapture["state"] = "normal"
            self.stopCapture["state"] = "disabled"
            self.sniffer.stop()

        self.startCapture = tk.Button(self, text="Start", command=startCapture)
        self.stopCapture = tk.Button(self, text="Stop", command=stopCapture)
        self.stopCapture["state"] = "disabled"
        self.startCapture.grid(row=0, column=0, sticky=tk.NW)
        self.stopCapture.grid(row=0, column=1, sticky=tk.NW)


    def packet_adder(self, q):
        while not q.empty():
            self.parent.packetHandler.handleNewPacket(q.get_nowait())
        if self.started:
            self.parent.root.after(1, self.packet_adder, q)

    def activeScanning(self):
        pass
        # if self.started:
        #     self.parent.IDSHandler.scanAllPackets()
        #     self.parent.root.after(5000, self.activeScanning)