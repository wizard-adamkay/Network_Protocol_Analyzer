import tkinter as tk
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


class GraphWindow(tk.Toplevel):
    def __init__(self, gType, master=None):
        super().__init__(master=master)
        self.title("Graphs")
        self.geometry("1000x600")
        self.options = ["Time sequence", "Round trip time", "Window scaling", "Throughput"]
        self.direction = 0
        self.line1 = None
        self.line2 = None
        self.graphType = tk.StringVar()
        self.graphType.set(gType)
        def updateGraphCB(a):
            self.updateGraph()
        dropDown = tk.OptionMenu(self, self.graphType, *self.options, command = updateGraphCB)
        self.spinval = tk.StringVar()
        self.spinval.set(0)

        self.s = tk.Spinbox(self, from_=0, to=len(master.packetHandler.sessions)-1, textvariable=self.spinval)
        fig = Figure(figsize=(10, 5),
                     dpi=100)

        def switchDir():
            self.direction = 0 if self.direction else 1
            self.updateGraph()

        switchDirButton = tk.Button(self, text="Switch Direction", command=switchDir)

        def spinBoxChange(a, b, c):
            self.s.configure(to=len(master.packetHandler.sessions)-1)
            self.updateGraph()

        self.topLabel = tk.Label(self, text="")
        self.spinval.trace_add('write', spinBoxChange)
        self.plot1 = fig.add_subplot(111)
        self.grid_columnconfigure(0, weight=1)
        self.canvas = FigureCanvasTkAgg(fig, master=self)
        self.topLabel.grid(row=0, sticky=tk.N)
        self.canvas.get_tk_widget().grid(row=1,sticky=tk.NW)
        switchDirButton.grid(row=2, sticky=tk.NW)
        dropDown.grid(row=2, sticky=tk.NE)
        self.s.grid(row=3, sticky=tk.NE)
        self.updateGraph()

    def updateGraph(self):
        self.plot1.clear()
        self.topLabel.configure(text= "")
        sender, receiver = self.master.packetHandler.fromSessionGet(int(self.spinval.get()))
        selected = sender if self.direction == 0 else receiver
        other = receiver if self.direction == 0 else sender
        if len(selected) == 0:
            self.plot1.clear()
            self.canvas.draw()
            return
        self.topLabel.configure(text= f"{selected[0].payload.src} -> {selected[0].payload.dst} packets involved: {len(selected)}")
        x = []
        y = []
        if self.graphType.get() == "Time sequence":
            initialTime = selected[0].time
            initialSeq = selected[0]["TCP"].seq
            for packet in selected:
                x.append(packet.time - initialTime)
                y.append(packet["TCP"].seq - initialSeq)
            self.plot1.set_xlabel("time in seconds since first packet")
            self.plot1.set_ylabel("sequence number")
        elif self.graphType.get() == "Round trip time":
            self.plot1.set_xlabel("time in seconds since first packet")
            self.plot1.set_ylabel("trip time in seconds")
            initialTime = selected[0].time
            for packet in selected:
                targetAck = packet.payload.len - 40 + packet["TCP"].seq
                roundTripTime = 0
                for otherPacket in other:
                    if otherPacket["TCP"].ack >= targetAck:
                        roundTripTime = otherPacket.time - packet.time
                        break
                x.append(packet.time - initialTime)
                y.append(max(roundTripTime, 0))
        elif self.graphType.get() == "Window scaling":
            initialSeq = selected[0]["TCP"].seq
            initialTime = selected[0].time
            x2 = []
            y2 = []
            for packet in selected:
                x.append(packet.time - initialTime)
                y.append(packet["TCP"].window)
                lastAck = initialSeq
                for otherPacket in other:
                    if otherPacket.time < packet.time and otherPacket["TCP"].ack >= lastAck:
                        lastAck = otherPacket["TCP"].ack
                    else:
                        break
                x2.append(packet.time - initialTime)
                inFlight = packet.payload.len - 40 + packet["TCP"].seq - initialSeq - (lastAck - initialSeq)
                y2.append(inFlight)
            self.line2, = self.plot1.plot(x2, y2, 'ro', linestyle="-")
            self.plot1.set_xlabel("time in seconds since first packet")
            self.plot1.set_ylabel("window size")
        elif self.graphType.get() == "Throughput":
            initialTime = selected[0].time
            for packet in selected:
                x.append(packet.time - initialTime)
                y.append(packet.payload.len - 40)
            self.plot1.set_xlabel("time in seconds since first packet")
            self.plot1.set_ylabel("segment length")

        self.line1, = self.plot1.plot(x, y, 'bo', linestyle="-")
        self.plot1.get_yaxis().get_major_formatter().set_useOffset(False)
        self.plot1.get_yaxis().get_major_formatter().set_scientific(False)
        self.canvas.draw()
