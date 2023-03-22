#!/usr/bin/env python
import sys
import tkinter as tk
from scapy.arch import get_if_addr
from scapy.config import conf
from MenuBar import MenuHeader
from PacketList import PacketListView
from ActionBar import ActionBar
from Filter import FilterBar
from PacketHandler import PacketHandler
from PacketDetailList import PacketDetailListView
from IDSHandler import IDSHandler


class MainApp(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(**kw)
        self.snortPath = "/var/log/snort"
        self.snortConfPath = "/root/Downloads/snort/snort-2.9.20/etc/snort.conf"
        self.root = parent
        self.root.geometry("900x650")
        self.root.title("Wirewhale")
        self.root.grid_columnconfigure(0, weight=1)
        self.packetHandler = PacketHandler(self)
        self.packetDetailListView = PacketDetailListView(self)
        self.IDSHandler = IDSHandler(self)
        self.menu = MenuHeader(self)
        self.actionBar = ActionBar(self)
        self.packetListView = PacketListView(self)
        self.filterBar = FilterBar(self)
        self.IPAddr = get_if_addr(conf.iface)

        self.menu.grid(row=0, sticky=tk.NW)
        self.actionBar.grid(row=1, sticky=tk.NW)
        self.filterBar.grid(row=2, sticky=tk.EW)
        self.packetListView.grid(row=3, sticky=tk.NSEW)
        self.packetDetailListView.grid(row=4, sticky=tk.NSEW)


if __name__ == '__main__':
    root = tk.Tk()
    MainApp(root).grid(sticky=tk.NSEW)
    root.mainloop()
    sys.exit()
