#!/usr/bin/env python
import tkinter as tk
from scapy.all import *
from MenuBar import MenuHeader
from PacketList import PacketListView
from ActionBar import ActionBar
from Filter import FilterBar
from PacketHandler import PacketHandler
from PacketDetailList import PacketDetailListView

class MainApp(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(**kw)
        self.root = parent
        self.root.geometry("900x650")
        self.root.title("Wirewhale")
        self.root.grid_columnconfigure(0, weight=1)
        self.packetHandler = PacketHandler(self)
        self.packetDetailListView = PacketDetailListView(self)
        self.menu = MenuHeader(self)
        self.actionBar = ActionBar(self)
        self.packetListView = PacketListView(self)
        self.filterBar = FilterBar(self)

        self.menu.grid(row=0, sticky=tk.NW)
        self.actionBar.grid(row=1, sticky=tk.NW)
        self.filterBar.grid(row=2, sticky=tk.EW)
        self.packetListView.grid(row=3, sticky=tk.NSEW)
        self.packetDetailListView.grid(row=4,sticky=tk.NSEW)


if __name__ == '__main__':
    root = tk.Tk()
    MainApp(root).grid(sticky=tk.NSEW)
    root.mainloop()
    sys.exit()
