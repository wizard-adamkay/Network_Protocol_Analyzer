import tkinter as tk


class Report(tk.Toplevel):
    def __init__(self, master=None):
        super().__init__(master=master)
        self.title("Threat Report")
        self.geometry("700x600")
        threatsLabel = tk.Label(self, text="Threats:", font='bold')
        threatsFoundLabel = tk.Label(self, text=("\tThreats Found:\t\t\t" + self.master.fileName))
        uniqueThreatsLabel = tk.Label(self, text=("\tUnique Threats Found:\t\t\t" + self.master.fileName))
        uniqueIPThreatsLabel = tk.Label(self, text=("\tUnique Malicious IPs:\t\t\t" + self.master.fileName))

        threatsLabel.grid(row=0, column=0, sticky=tk.NW, pady=(10, 0))
        threatsFoundLabel.grid(row=1, column=0, sticky=tk.NW)
        uniqueThreatsLabel.grid(row=2, column=0, sticky=tk.NW)
        uniqueIPThreatsLabel.grid(row=3, column=0, sticky=tk.NW)
