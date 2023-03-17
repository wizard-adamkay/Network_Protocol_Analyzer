import tkinter as tk
from tkinter import ttk
import scapy.all as scapy


class PacketDetailListView(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(**kw)
        self.parent = parent
        self.packetDetailList = ttk.Treeview(self)
        self.grid_columnconfigure(0,weight=1,minsize=300)
        self.grid_columnconfigure(1,weight=1,minsize=300)
        self.grid_rowconfigure(0,weight=1)
        self.packetDetailList.grid(row=0, column=0, sticky=tk.NSEW)
        self.packetBytesDisplay = tk.Text(self, width=71)
        self.packetBytesDisplay.grid(row=0, column=1, sticky=tk.EW)

    def displayPacketDetails(self, packet):
        self.packetDetailList.delete(*self.packetDetailList.get_children())
        p = packet.show(dump=True).split("\n")
        root = ""
        for line in p:
            if line[0:3] == "###":
                root = self.packetDetailList.insert('', tk.END, text=line)
            else:
                self.packetDetailList.insert(root, tk.END, text=line.strip())

    def displayBytes(self, packet):
        self.packetBytesDisplay.delete(1.0, tk.END)
        self.packetBytesDisplay.insert(tk.END, scapy.hexdump(packet, dump=True))
