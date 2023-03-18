import tkinter as tk
from scapy.all import *
from tkinter import filedialog
from Graph import GraphWindow


class MenuHeader(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(**kw)
        self.parent = parent
        def saveToPcapCallBack():
            for pkt in parent.packetHandler.fullPacketList:
                wrpcap('filtered.pcap', pkt, append=True)

        def saveSelectedToPcapCallBack():
            for pkt in parent.packetDetailListView.displayedPackets:
                wrpcap('filtered.pcap', pkt, append=True)

        def loadFromPcap():
            filename = filedialog.askopenfilename(initialdir="/",
                                                      title="Select a File",
                                                      filetypes=(("pcap files",
                                                                  "*.pcap*"),
                                                                 ("all files",
                                                                  "*.*")))
            pcap = rdpcap(filename)
            self.parent.packetHandler.clear()
            for packet in pcap:
                self.parent.packetHandler.handleNewPacket(packet)

        def graphStart(graphType):
            if len(self.parent.packetHandler.sessions) == 0:
                print("no sessions to graph")
                return
            GraphWindow(graphType, self.parent)

        def IDSPathSelectStart():
            directory = self.parent.snortPath if os.path.exists(self.parent.snortPath) else "/"
            self.parent.snortPath = filedialog.askdirectory(initialdir=directory)

        def IDSScan():
            self.parent.IDSHandler.scanAllPackets()

        self.menuBar = tk.Menu(self)
        self.fileMenu = tk.Menu(self.menuBar, tearoff=0)
        self.fileMenu.add_command(label="Save All", command=saveToPcapCallBack)
        self.fileMenu.add_command(label="Save Filtered", command=saveSelectedToPcapCallBack)
        self.fileMenu.add_command(label="Load", command=loadFromPcap)
        self.fileMenu.add_separator()
        self.fileMenu.add_command(label="Exit", command=self.parent.root.destroy)

        self.analyzeMenu = tk.Menu(self.menuBar, tearoff=0)
        self.analyzeMenu.add_command(label="Summary", command=saveToPcapCallBack)
        self.analyzeMenu.add_command(label="Report", command=saveToPcapCallBack)
        self.analyzeMenu.add_separator()
        self.analyzeMenu.add_command(label="Time sequence", command=lambda: graphStart("Time sequence"))
        self.analyzeMenu.add_command(label="Round trip time", command=lambda: graphStart("Round trip time"))
        self.analyzeMenu.add_command(label="Window scaling", command=lambda: graphStart("Window scaling"))
        self.analyzeMenu.add_command(label="Throughput", command=lambda: graphStart("Throughput"))

        self.IPSMenu = tk.Menu(self.menuBar, tearoff=0)
        self.IPSMenu.add_command(label="Alert Directory Select", command=IDSPathSelectStart)
        self.IPSMenu.add_command(label="Threat Handling", command=saveToPcapCallBack)
        self.IPSMenu.add_command(label="Scan Now", command=IDSScan)

        self.menuBar.add_cascade(label="File", menu=self.fileMenu)
        self.menuBar.add_cascade(label="Analyze", menu=self.analyzeMenu)
        self.menuBar.add_cascade(label="IPS", menu=self.IPSMenu)
        parent.root.config(menu=self.menuBar)
