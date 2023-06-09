import tkinter as tk
from scapy.all import *
from tkinter import filedialog
from Graph import GraphWindow
from Summary import Summary
from Report import Report


class MenuHeader(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(**kw)
        self.parent = parent
        self.fileName = ""
        def saveToPcapCallBack():
            fileName = filedialog.asksaveasfilename(initialdir=os.getcwd(), defaultextension=".pcap", title="Save as", filetypes=(("PCAP Files", "*.pcap*"),("All Files", "*.*")))
            wrpcap(fileName, self.parent.packetHandler.fullPacketList)
            self.fileName = fileName

        def saveSelectedToPcapCallBack():
            fileName = filedialog.asksaveasfilename(initialdir=os.getcwd(), defaultextension=".pcap",
                                                    title="Save as",
                                                    filetypes=(("PCAP Files", "*.pcap*"), ("All Files", "*.*")))
            displayedPackets = []
            for index in self.parent.packetListView.displayedPacketsNum:
                displayedPackets.append(self.parent.packetHandler.fullPacketList[index - 1])
            wrpcap(fileName, displayedPackets)
            self.fileName = fileName

        def loadFromPcap():
            filename = filedialog.askopenfilename(initialdir="/",
                                                      title="Select a File",
                                                      filetypes=(("pcap files",
                                                                  "*.pcap*"),
                                                                 ("all files",
                                                                  "*.*")))
            pcap = rdpcap(filename)
            self.parent.packetListView.markedPackets.clear()
            self.parent.packetHandler.clear()
            for packet in pcap:
                self.parent.packetHandler.handleNewPacket(packet)
            self.fileName = filename

        def graphStart(graphType):
            if len(self.parent.packetHandler.sessions) == 0:
                print("no sessions to graph")
                return
            GraphWindow(graphType, self.parent)

        def summaryStart():
            if len(self.parent.packetHandler.fullPacketList) == 0:
                print("no packets to summarize")
                return
            Summary(self)

        def reportStart():
            if len(self.parent.packetHandler.fullPacketList) == 0:
                print("no packets to report")
                return
            Report(self)

        def IDSPathSelectStart():
            directory = self.parent.snortPath if os.path.exists(self.parent.snortPath) else "/"
            self.parent.snortPath = filedialog.askdirectory(initialdir=directory)

        def IDSSnortConfPathSelect():
            directory = self.parent.snortConfPath if os.path.exists(self.parent.snortConfPath) else "/"
            self.parent.snortConfPath = filedialog.askopenfilename(initialdir=directory, filetypes=(('Config Files', '*.conf'), ('All Files','*.*')))


        def IDSScan():
            self.parent.IDSHandler.scanHandle()

        self.menuBar = tk.Menu(self)
        self.fileMenu = tk.Menu(self.menuBar, tearoff=0)
        self.fileMenu.add_command(label="Save All", command=saveToPcapCallBack)
        self.fileMenu.add_command(label="Save Filtered", command=saveSelectedToPcapCallBack)
        self.fileMenu.add_command(label="Load", command=loadFromPcap)
        self.fileMenu.add_separator()
        self.fileMenu.add_command(label="Exit", command=self.parent.root.destroy)

        self.analyzeMenu = tk.Menu(self.menuBar, tearoff=0)
        self.analyzeMenu.add_command(label="Summary", command=summaryStart)
        self.analyzeMenu.add_command(label="Report", command=reportStart)
        self.analyzeMenu.add_separator()
        self.analyzeMenu.add_command(label="Time sequence", command=lambda: graphStart("Time sequence"))
        self.analyzeMenu.add_command(label="Round trip time", command=lambda: graphStart("Round trip time"))
        self.analyzeMenu.add_command(label="Window scaling", command=lambda: graphStart("Window scaling"))
        self.analyzeMenu.add_command(label="Throughput", command=lambda: graphStart("Throughput"))

        self.IPSMenu = tk.Menu(self.menuBar, tearoff=0)
        self.IPSMenu.add_command(label="Alert Directory Select", command=IDSPathSelectStart)
        self.IPSMenu.add_command(label="Snort Conf Select", command=IDSSnortConfPathSelect)
        self.IPSMenu.add_command(label="Scan Now", command=IDSScan)

        self.menuBar.add_cascade(label="File", menu=self.fileMenu)
        self.menuBar.add_cascade(label="Analyze", menu=self.analyzeMenu)
        self.menuBar.add_cascade(label="IPS", menu=self.IPSMenu)
        parent.root.config(menu=self.menuBar)

# for testing
    def loadPcap(self, filename):
        pcap = rdpcap(filename)
        self.parent.packetListView.markedPackets.clear()
        self.parent.packetHandler.clear()
        for packet in pcap:
            self.parent.packetHandler.handleNewPacket(packet)
        self.fileName = filename