import time
import tkinter as tk
from tkinter import ttk
import threading


class PacketListView(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(**kw)
        self.parent = parent
        self.navigating = False
        self.markedPackets = []
        self.grid_columnconfigure(0, weight=3)
        self.grid_columnconfigure(0, weight=1)
        self.displayedPackets = []
        self.displayedPacketsNum = []
        self.threatsPacketNum = []
        self.packetList = ttk.Treeview(self, selectmode='browse')
        self.verscrlbar = tk.Scrollbar(self,
                                   orient="vertical",
                                   command=self.packetList.yview)
        self.packetList.configure(yscroll=self.verscrlbar.set)
        self.popupMenu = tk.Menu(self, tearoff=0)
        self.popupMenu.add_command(label="Toggle Mark", command=self.toggleMark)
        self.popupMenu.add_command(label="Kill", command=self.killConversation)
        self.popupMenu.add_command(label="Block IP", command=self.blockIP)
        self.packetList["columns"] = ("0", "1", "2", "3", "4", "5", "6")
        self.columnNames = ("Packet Number", "time","Source IP", "Destination IP", "Source Port", "Destination Port", "Flags")
        self.packetList['show'] = 'headings'
        for count, column in enumerate(self.packetList["columns"]):
            self.packetList.column(str(count), width=100, anchor='c')
            self.packetList.heading(str(count), text=self.columnNames[count])
        self.packetList.tag_configure("Mark", background="yellow")
        self.packetList.tag_configure("Threat", background="red")
        self.packetList.tag_configure("TCP", background="green")
        self.packetList.tag_configure("UDP", background="cyan")
        self.packetList.tag_configure("ARP", background="orange")

        self.packetList.bind("<<TreeviewSelect>>", self.selectPacket)
        self.packetList.bind("<Button-3>", self.popup)
        self.packetList.bind("<Button-2>", self.middleClickNav)
        self.packetList.grid(row=0, column=0, sticky=tk.EW)
        self.verscrlbar.grid(row=0, column=1, sticky=tk.NS)
        self.unlistedPackets = 0
        self.ipProtos = (
        "HOPOPT", "ICMP", "IGMP", "GGP", "IP-in-IP", "ST", "TCP", "CBT", "EGP", "IGP", "BBN-RCC-MON", "NVP-II", "PUP",
        "ARGUS", "EMCON", "XNET", "CHAOS", "UDP", "MUX", "DCN-MEAS", "HMP", "PRM", "XNS-IDP", "TRUNK-1", "TRUNK-2",
        "LEAF-1", "LEAF-2", "RDP", "IRTP", "ISO-TP4", "NETBLT", "MFE-NSP", "MERIT-INP", "DCCP", "3PC", "IDPR", "XTP",
        "DDP", "IDPR-CMTP", "TP++", "IL", "IPv6", "SDRP", "IPv6-Route", "IPv6-Frag", "IDRP", "RSVP", "GRE", "DSR",
        "BNA", "ESP", "AH", "I-NLSP", "SwIPe", "NARP", "MOBILE", "TLSP", "SKIP", "IPv6-ICMP", "IPv6-NoNxt", "IPv6-Opts",
        "", "CFTP", "", "SAT-EXPAK", "KRYPTOLAN", "RVD", "IPPC", "", "SAT-MON", "VISA", "IPCU", "CPNX", "CPHB", "WSN",
        "PVP", "BR-SAT-MON", "SUN-ND", "WB-MON", "WB-EXPAK", "ISO-IP", "VMTP", "SECURE-VMTP", "VINES", "TTP", "IPTM",
        "NSFNET-IGP", "DGP", "TCF", "EIGRP", "OSPF", "Sprite-RPC", "LARP", "MTP", "AX.25", "OS", "MICP", "SCC-SP",
        "ETHERIP", "ENCAP", "", "GMTP", "IFMP", "PNNI", "PIM", "ARIS", "SCPS", "QNX", "A/N", "IPComp", "SNP",
        "Compaq-Peer", "IPX-in-IP", "VRRP", "PGM", "", "L2TP", "DDX", "IATP", "STP", "SRP", "UTI", "SMP", "SM", "PTP",
        "IS-IS over IPv4", "FIRE", "CRTP", "CRUDP", "SSCOPMCE", "IPLT", "SPS", "PIPE", "SCTP", "FC", "RSVP-E2E-IGNORE",
        "Mobility Header", "UDPLite", "MPLS-in-IP", "manet", "HIP", "Shim6", "WESP", "ROHC", "Ethernet",)

    def selectPacket(self, event):
        try:
            item = self.packetList.selection()[0]
            index = self.packetList.item(item)["values"][0] - 1
            packet = self.parent.packetHandler.fullPacketList[index]
            self.parent.packetDetailListView.displayPacketDetails(packet)
            self.parent.packetDetailListView.displayBytes(packet)
        except Exception:
            pass

    def addToList(self, num, packet):
        bottom = True if self.packetList.yview()[1] == 1 else False
        self.displayedPackets.append(packet)
        self.displayedPacketsNum.append(num)
        try:
            time = packet.time
            srcport = ""
            dstport = ""
            flags = ""
            tag = ()
            if "IP" in packet:
                srcIP = packet["IP"].src
                dstIP = packet["IP"].dst
                proto = packet["IP"].proto
                tag = (self.ipProtos[proto],)
                if proto == 6 or proto == 17:
                    srcport = packet["IP"].sport
                    dstport = packet["IP"].dport
                if proto == 6:
                    flags = packet["TCP"].flags

            elif "ARP" in packet:
                srcIP = packet["ARP"].psrc
                dstIP = packet["ARP"].pdst
                tag = ("ARP",)
            elif "IPv6" in packet:
                srcIP = packet["IPv6"].src
                dstIP = packet["IPv6"].dst
                proto = packet["IPv6"].nh
                tag = (self.ipProtos[proto],)
                if proto == 17 or proto == 6:
                    srcport = packet["IPv6"].sport
                    dstport = packet["IPv6"].dport
                if proto == 6:
                    flags = packet["TCP"].flags
            else:
                srcIP = packet.src if hasattr(packet, "src") else ""
                dstIP = packet.dst if hasattr(packet, "dst") else ""
            if num - 1 in self.markedPackets:
                tag += ("Mark",)
            if num - 1 in self.threatsPacketNum:
                tag += ("Threat",)
            self.packetList.insert(parent="", index=tk.END,
                               values=(num, time, srcIP, dstIP, srcport,
                                       dstport, flags), tags=tag)

        except Exception as e:
            print("Packet not handled!")
            self.unlistedPackets += 1
            print(f"{self.unlistedPackets} found so far")
            packet.show()
        if bottom:
            self.packetList.yview_moveto(1)

    def popup(self, event):
        iid = self.packetList.identify_row(event.y)
        if iid:
            self.packetList.selection_set(iid)
            try:
                self.popupMenu.tk_popup(event.x_root, event.y_root)
            finally:
                self.popupMenu.grab_release()

    def toggleMark(self):
        iid = self.packetList.selection()
        if not iid:
            return
        index = self.packetList.item(iid[0])["values"][0] - 1
        tags = self.packetList.item(iid[0], "tags")
        if "Mark" in tags:
            taglist = list(tags)
            taglist.remove("Mark")
            tags = tuple(taglist)
            self.markedPackets.remove(index)
        else:
            taglist = list(tags)
            taglist.append("Mark")
            tags = tuple(taglist)
            self.markedPackets.append(index)
        self.packetList.item(iid[0], tags=tags)


    def killConversation(self):
        iid = self.packetList.selection()
        if not iid:
            return
        index = self.packetList.item(iid[0])["values"][0] - 1
        packet = self.parent.packetHandler.fullPacketList[index]
        self.parent.IDSHandler.killConversation(packet)

    def blockIP(self):
        iid = self.packetList.selection()
        if not iid:
            return
        index = self.packetList.item(iid[0])["values"][0] - 1
        packet = self.parent.packetHandler.fullPacketList[index]
        self.parent.IDSHandler.blockIP(packet)

    def nav(self, initialY):
        while self.navigating:
            mousePosition = self.parent.root.winfo_pointery() - self.parent.root.winfo_rooty() - 46
            direction = mousePosition - initialY
            self.packetList.yview_scroll(int(direction/10), "units")
            time.sleep(.1)

    def middleClickNav(self, event):
        self.navigating = False if self.navigating else True
        if self.navigating:
            threading.Thread(target=self.nav, args=(event.y,)).start()

    def markAsThreat(self, index):
        if index in self.threatsPacketNum:
            return
        self.threatsPacketNum.append(index)
        if index not in self.displayedPacketsNum:
            return
        iid = self.packetList.get_children()[index]
        tags = self.packetList.item(iid, "tags")
        tagsList = list(tags)
        tagsList.append("Threat")
        tags = tuple(tagsList)
        self.packetList.item(iid, tags=tags)

    def clear(self):
        self.packetList.delete(*self.packetList.get_children())
        self.displayedPackets = []
        self.displayedPacketsNum = []
