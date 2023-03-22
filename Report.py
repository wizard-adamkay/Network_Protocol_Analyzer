import tkinter as tk
from tkinter import ttk


class Report(tk.Toplevel):
    def __init__(self, master=None):
        super().__init__(master=master)
        self.title("Threat Report")
        self.geometry("700x600")
        self.threatDict = self.master.parent.IDSHandler.threatsByIP
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
        ipsUsed = ipsUsed[0:-2] if len(ipsUsed) != 0 else ""
        uniqueAttacks = set()
        for malIp, attacks in self.threatDict.items():
            for attack in attacks:
                uniqueAttacks.add(attack)
        uniqueAttackString = ""
        for index, attack in enumerate(uniqueAttacks):
            if index + 1 % 5 == 0:
                uniqueAttackString += "\n\t\t\t\t"
            uniqueAttackString += attack + ', '
        uniqueAttackString = uniqueAttackString[0:-2] if len(uniqueAttackString) != 0 else ""

        self.statsTable = ttk.Treeview(self, column=("1", "2"), show='headings', height=10)
        self.statsTable.column("1", anchor=tk.CENTER)
        self.statsTable.heading("1", text="IP Address")
        self.statsTable.column("2", anchor=tk.CENTER)
        self.statsTable.heading("2", text="Detected Attack")
        for malIp, attacks in self.threatDict.items():
            for index, attack in enumerate(attacks):
                if index == 0:
                    self.statsTable.insert('', index=tk.END, values=(malIp, attack))
                    continue
                self.statsTable.insert('', index=tk.END, values=("", attack))

        self.threatsLabel = tk.Label(self, text="Threats:", font='bold')
        self.threatsFoundLabel = tk.Label(self, text=("\tThreats Found:\t\t" + str(len(threatsPacketNum))))
        self.uniqueThreatsLabel = tk.Label(self, text=("\tUnique Attacks Found:\t" + str(len(uniqueAttacks))))
        self.typesOfAttacksLabel = tk.Label(self, text=("\tTypes of Attacks:\t\t"+uniqueAttackString))
        self.uniqueIPThreatsLabel = tk.Label(self, text=("\tUnique Malicious IPs:\t" + str(threatsUniqueIP)))
        print(ipsUsed)
        self.ipsUsedLabel = tk.Label(self, text=("\tMalicious IPs:\t\t" + ipsUsed))
        self.threatsByIPLabel = tk.Label(self, text="Threats By IP:", font='bold')

        self.grid_columnconfigure(0, weight=1)
        self.threatsLabel.grid(row=0, column=0, sticky=tk.NW, pady=(10, 0))
        self.threatsFoundLabel.grid(row=1, column=0, sticky=tk.NW)
        self.uniqueThreatsLabel.grid(row=2, column=0, sticky=tk.NW)
        self.uniqueIPThreatsLabel.grid(row=3, column=0, sticky=tk.NW)
        self.typesOfAttacksLabel.grid(row=4, column=0, sticky=tk.NW)
        self.ipsUsedLabel.grid(row=5, column=0, sticky=tk.NW)
        self.threatsByIPLabel.grid(row=6, column=0, sticky=tk.NW, pady=(10, 0))
        self.statsTable.grid(row=7, column=0, sticky=tk.NW)
