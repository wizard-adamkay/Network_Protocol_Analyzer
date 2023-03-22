import tkinter as tk


class Report(tk.Toplevel):
    def __init__(self, master=None):
        super().__init__(master=master)
        self.title("Threat Report")
        self.geometry("700x600")
        threatsPacketNum = self.master.parent.packetListView.threatsPacketNum
        packetList = self.master.parent.packetHandler.fullPacketList
        ipSet = {""}
        for threatNum in threatsPacketNum:
            ipSet.add(packetList[threatNum].payload.src) if hasattr(packetList[threatNum].payload, "src") else ""
        ipSet.discard("")
        threatsUniqueIP = len(ipSet)
        ipsUsed = ""
        for index, ip in enumerate(ipSet):
            if index + 1 % 5 == 0:
                ipsUsed += "\n\t\t\t\t"
            ipsUsed += ip + ', '
        ipsUsed = ipsUsed[0:-2]
        self.threatsLabel = tk.Label(self, text="Threats:", font='bold')
        self.threatsFoundLabel = tk.Label(self, text=("\tThreats Found:\t\t" + str(len(threatsPacketNum))))
        self.uniqueThreatsLabel = tk.Label(self, text=("\tdifferent Attacks Found:\t"))
        self.typesOfAttacksLabel = tk.Label(self, text=("\tTypes of Attacks:\t"))
        self.uniqueIPThreatsLabel = tk.Label(self, text=("\tUnique Malicious IPs:\t" + str(threatsUniqueIP)))
        self.ipsUsedLabel = tk.Label(self, text="\tMalicious IPs:\t\t" + ipsUsed)

        self.grid_columnconfigure(0, weight=1)
        self.threatsLabel.grid(row=0, column=0, sticky=tk.NW, pady=(10, 0))
        self.threatsFoundLabel.grid(row=1, column=0, sticky=tk.NW)
        self.uniqueThreatsLabel.grid(row=2, column=0, sticky=tk.NW)
        self.uniqueIPThreatsLabel.grid(row=3, column=0, sticky=tk.NW)
        self.typesOfAttacksLabel.grid(row=4, column=0, sticky=tk.NW)
        self.ipsUsedLabel.grid(row=5, column=0, sticky=tk.NW)
