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
        if self.master.fileName == "":
            fileFormat = "PCAP"
        else:
            fileFormat = splitext(self.master.fileName)[1]

        if exists("temp2.pcap"):
            remove("temp2.pcap")
        wrpcap("temp2.pcap", self.master.parent.packetHandler.fullPacketList)
        file_stats = stat("temp2.pcap")
        fileBytes = file_stats.st_size
        hasher = hashlib.sha1()
        with open("temp2.pcap", 'rb') as file:
            chunk = 0
            while chunk != b'':
                chunk = file.read(1024)
                hasher.update(chunk)
        fileHash = hasher.hexdigest()
        packetList = self.master.parent.packetHandler.fullPacketList
        displayedPacketList = self.master.parent.packetListView.displayedPackets
        firstPacketTime = datetime.datetime.fromtimestamp(packetList[0].time).strftime('%Y-%m-%d %H:%M:%S')
        lastPacketTime = datetime.datetime.fromtimestamp(packetList[-1].time).strftime('%Y-%m-%d %H:%M:%S')
        elapsedTime = packetList[-1].time - packetList[0].time
        capturedPackets = len(packetList)
        displayedPackets = len(displayedPacketList)
        capturedTimeSpan = elapsedTime
        displayedTimeSpan = displayedPacketList[-1].time - displayedPacketList[0].time
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
        fileLabel = tk.Label(self, text="File:", font='bold')
        nameLabel = tk.Label(self, text=("\tName:\t\t\t" + self.master.fileName))
        lengthLabel = tk.Label(self, text=("\tLength(bytes):\t" + str(fileBytes)))
        hashLabel = tk.Label(self, text=("\tHash(sha-1):\t" + fileHash))
        formatLabel = tk.Label(self, text=("\tFormat:\t\t" + fileFormat))

        timeLabel = tk.Label(self, text="Time:", font='bold')
        firstPacketLabel = tk.Label(self, text=("\tFirst Packet:\t"+firstPacketTime))
        LastPacketLabel = tk.Label(self, text=("\tLastPacket:\t"+lastPacketTime))
        ElapsedLabel = tk.Label(self, text=("\tElapsed(Seconds):\t"+str(elapsedTime)))

        statsLabel = tk.Label(self, text="Statistics:", font='bold')
        statsTable = ttk.Treeview(self, column=("1", "2", "3"), show='headings', height=6)
        statsTable.column("1", anchor=tk.CENTER)
        statsTable.heading("1", text="Measurement")
        statsTable.column("2", anchor=tk.CENTER)
        statsTable.heading("2", text="Captured")
        statsTable.column("3", anchor=tk.CENTER)
        statsTable.heading("3", text="Displayed")

        statsTable.insert('', index=tk.END, values=("Packets", capturedPackets, displayedPackets))
        statsTable.insert('', index=tk.END, values=("Time Span (seconds)", capturedTimeSpan, displayedTimeSpan))
        statsTable.insert('', index=tk.END, values=("Average PPS", capturedPacketsPerSecond, displayedPacketsPerSecond))
        statsTable.insert('', index=tk.END, values=("Bytes", capturedPacketSize, displayedPacketSize))
        statsTable.insert('', index=tk.END, values=("Average Packet Size", capturedAverageSize, displayedAverageSize))
        statsTable.insert('', index=tk.END, values=("Average Bytes/s", capturedBytesPerSecond, displayedBytesPerSecond))
        self.grid_columnconfigure(0, weight=1)
        fileLabel.grid(row=0, column=0, sticky=tk.NW, pady=(10, 0))
        nameLabel.grid(row=1, column=0, sticky=tk.NW)
        lengthLabel.grid(row=2, column=0, sticky=tk.NW)
        hashLabel.grid(row=3, column=0, sticky=tk.NW)
        formatLabel.grid(row=4, column=0, sticky=tk.NW)
        timeLabel.grid(row=5, column=0, sticky=tk.NW, pady=(10, 0))
        firstPacketLabel.grid(row=6, column=0, sticky=tk.NW)
        LastPacketLabel.grid(row=7, column=0, sticky=tk.NW)
        ElapsedLabel.grid(row=8, column=0, sticky=tk.NW)
        statsLabel.grid(row=9, column=0, sticky=tk.NW, pady=(10, 0))
        statsTable.grid(row=10, column=0, sticky=tk.NW)
        if exists("temp2.pcap"):
            remove("temp2.pcap")
