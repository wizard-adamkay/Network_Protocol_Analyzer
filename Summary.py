import datetime
import tkinter as tk
from os import remove, stat
from os.path import exists, splitext
from scapy.utils import wrpcap
import hashlib
from tkinter import ttk


class Summary(tk.Toplevel):
    def __init__(self, master=None):
        super().__init__(master=master)
        self.title("Summary")
        self.geometry("600x450")
        fileName = self.master.fileName
        if self.master.fileName == "":
            fileFormat = "PCAP"
            fileName = "temp2.pcap"
        else:
            fileFormat = splitext(self.master.fileName)[1]
        if exists("temp2.pcap"):
            remove("temp2.pcap")
        wrpcap("temp2.pcap", self.master.parent.packetHandler.fullPacketList)
        file_stats = stat(fileName)
        fileBytes = file_stats.st_size
        hasher = hashlib.sha1()
        with open(fileName, 'rb') as file:
            chunk = 0
            while chunk != b'':
                chunk = file.read(1024)
                hasher.update(chunk)
        fileHash = hasher.hexdigest()
        packetList = self.master.parent.packetHandler.fullPacketList
        displayedPacketList = []
        for index in self.master.parent.packetListView.displayedPacketsNum:
            displayedPacketList.append(self.master.parent.packetHandler.fullPacketList[index - 1])
        firstPacketTime = datetime.datetime.fromtimestamp(float(packetList[0].time)).strftime('%Y-%m-%d %H:%M:%S')
        lastPacketTime = datetime.datetime.fromtimestamp(float(packetList[-1].time)).strftime('%Y-%m-%d %H:%M:%S')
        elapsedTime = float(packetList[-1].time) - float(packetList[0].time)
        elapsedTime = 1.0 if elapsedTime == 0 else elapsedTime
        capturedPackets = len(packetList)
        displayedPackets = len(displayedPacketList)
        capturedTimeSpan = elapsedTime
        displayedTimeSpan = float(displayedPacketList[-1].time) - float(displayedPacketList[0].time)
        displayedTimeSpan = 1.0 if displayedTimeSpan == 0 else displayedTimeSpan
        capturedPacketsPerSecond = capturedPackets / capturedTimeSpan
        displayedPacketsPerSecond = displayedPackets / displayedTimeSpan
        capturedPacketSize = 0
        displayedPacketSize = 0
        for packet in packetList:
            capturedPacketSize += len(packet)
        for packet in displayedPacketList:
            displayedPacketSize += len(packet)
        capturedAverageSize = capturedPacketSize / capturedPackets
        displayedAverageSize = displayedPacketSize / displayedPackets
        capturedBytesPerSecond = capturedPacketSize / elapsedTime
        displayedBytesPerSecond = displayedPacketSize / displayedTimeSpan
        self.fileLabel = tk.Label(self, text="File:", font='bold')
        self.nameLabel = tk.Label(self, text=("\tName:\t\t" + self.master.fileName))
        self.lengthLabel = tk.Label(self, text=("\tLength(bytes):\t" + str(fileBytes)))
        self.hashLabel = tk.Label(self, text=("\tHash(sha-1):\t" + fileHash))
        self.formatLabel = tk.Label(self, text=("\tFormat:\t\t" + fileFormat))

        self.timeLabel = tk.Label(self, text="Time:", font='bold')
        self.firstPacketLabel = tk.Label(self, text=("\tFirst Packet:\t"+firstPacketTime))
        self.LastPacketLabel = tk.Label(self, text=("\tLastPacket:\t"+lastPacketTime))
        self.ElapsedLabel = tk.Label(self, text=("\tElapsed(Seconds):\t"+str(elapsedTime)))

        self.statsLabel = tk.Label(self, text="Statistics:", font='bold')
        self.statsTable = ttk.Treeview(self, column=("1", "2", "3"), show='headings', height=6)
        self.statsTable.column("1", anchor=tk.CENTER)
        self.statsTable.heading("1", text="Measurement")
        self.statsTable.column("2", anchor=tk.CENTER)
        self.statsTable.heading("2", text="Captured")
        self.statsTable.column("3", anchor=tk.CENTER)
        self.statsTable.heading("3", text="Displayed")

        self.statsTable.insert('', index=tk.END, values=("Packets", capturedPackets, displayedPackets))
        self.statsTable.insert('', index=tk.END, values=("Time Span (seconds)", capturedTimeSpan, displayedTimeSpan))
        self.statsTable.insert('', index=tk.END, values=("Average PPS", capturedPacketsPerSecond, displayedPacketsPerSecond))
        self.statsTable.insert('', index=tk.END, values=("Bytes", capturedPacketSize, displayedPacketSize))
        self.statsTable.insert('', index=tk.END, values=("Average Packet Size", capturedAverageSize, displayedAverageSize))
        self.statsTable.insert('', index=tk.END, values=("Average Bytes/s", capturedBytesPerSecond, displayedBytesPerSecond))
        self.grid_columnconfigure(0, weight=1)
        self.fileLabel.grid(row=0, column=0, sticky=tk.NW, pady=(10, 0))
        self.nameLabel.grid(row=1, column=0, sticky=tk.NW)
        self.lengthLabel.grid(row=2, column=0, sticky=tk.NW)
        self.hashLabel.grid(row=3, column=0, sticky=tk.NW)
        self.formatLabel.grid(row=4, column=0, sticky=tk.NW)
        self.timeLabel.grid(row=5, column=0, sticky=tk.NW, pady=(10, 0))
        self.firstPacketLabel.grid(row=6, column=0, sticky=tk.NW)
        self.LastPacketLabel.grid(row=7, column=0, sticky=tk.NW)
        self.ElapsedLabel.grid(row=8, column=0, sticky=tk.NW)
        self.statsLabel.grid(row=9, column=0, sticky=tk.NW, pady=(10, 0))
        self.statsTable.grid(row=10, column=0, sticky=tk.NW)
        if exists("temp2.pcap"):
            remove("temp2.pcap")
