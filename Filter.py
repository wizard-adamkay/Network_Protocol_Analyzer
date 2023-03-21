import tkinter as tk

class FilterBar(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(**kw)
        self.parent = parent
        self.currentFilter = ""
        self.filterEntry = tk.Entry(self)
        self.filterEntry.bind("<Return>", self.func)
        self.grid_columnconfigure(0, weight=1)
        self.filterEntry.grid(row=0, sticky=tk.EW)

    def func(self, event):
        fast = False
        userInput = self.filterEntry.get()
        splitUserInput = userInput.split()
        splitCurrentFilter = self.currentFilter.split()
        if len(splitUserInput) > len(splitCurrentFilter):
            if splitCurrentFilter[:len(splitUserInput)] == splitUserInput:
                if splitCurrentFilter[len(splitUserInput)] == "and":
                    fast = True
        try:
            self.currentFilter = userInput
            self.parent.packetListView.clear()
            if fast:
                for index, packet in enumerate(self.parent.packetListView.displayedPackets):
                    if self.filterPacket(packet, self.parent.packetListView.displayedPacketsNum[index]):
                        self.parent.packetListView.addToList(self.parent.packetListView.displayedPacketsNum[index],
                                                             packet)
            else:
                for index, packet in enumerate(self.parent.packetHandler.fullPacketList):
                    if self.filterPacket(packet, index):
                        self.parent.packetListView.addToList(index + 1, packet)
        except Exception as e:
            print(e)

    def filterPacket(self, packet, displayNum):
        allowedTerms = ("srcip", "dstip", "srcport", "dstport", "time", "flags", "protocol", "marked")
        allowedComparators = ("==", "!=", "<", "<=", ">", ">=")
        allowedOperators = ("or", "and")
        if self.currentFilter == "":
            return True
        filter = self.currentFilter.split()
        evalFilter = []
        index = 0
        while index < len(filter):
            term = filter[index]
            if term == '(' or term == ')' or term in allowedOperators:
                evalFilter.append(term)
                index+=1
                continue
            op = filter[index+1]
            right = filter[index+2]
            if term not in allowedTerms or op not in allowedComparators:
               return ValueError(f"term {term} or operator {op} not allowed")
            if term == 'srcip':
                if "ARP" in packet:
                    evalFilter.append(self.evaluate(packet["ARP"].psrc, op, right))
                elif "TCP" in packet or "UDP" in packet:
                    evalFilter.append(self.evaluate(packet.payload.src, op, right))
                else:
                    if hasattr(packet, "src"):
                        evalFilter.append(self.evaluate(packet.src, op, right))
                    else:
                        evalFilter.append(False)
            elif term == 'dstip':
                if "ARP" in packet:
                    evalFilter.append(self.evaluate(packet["ARP"].pdst, op, right))
                elif "TCP" in packet or "UDP" in packet:
                    evalFilter.append(self.evaluate(packet.payload.dst, op, right))
                else:
                    if hasattr(packet, "src"):
                        evalFilter.append(self.evaluate(packet.dst, op, right))
                    else:
                        evalFilter.append(False)
            elif term == 'srcport':
                if packet.haslayer("TCP") or packet.haslayer("UDP"):
                    evalFilter.append(self.evaluate(int(packet.payload.payload.sport), op, int(right)))
                else:
                    evalFilter.append(False)
            elif term == 'dstport':
                if packet.haslayer("TCP") or packet.haslayer("UDP"):
                    evalFilter.append(self.evaluate(int(packet.payload.payload.dport), op, int(right)))
                else:
                    evalFilter.append(False)
            elif term == 'time':
                evalFilter.append(self.evaluate(float(packet.time), op, float(right)))
            elif term == 'flags':
                if packet.haslayer("TCP"):
                    evalFilter.append(self.evaluate(packet["TCP"].flags, op, right))
                else:
                    evalFilter.append(False)
            elif term == 'protocol':
                evalFilter.append(self.evaluateProto(packet, op, right))
            elif term == 'marked':
                evalFilter.append(self.evaluateMark(displayNum, op, right))
            else:
                raise ValueError(f"failed on term {term}")
            index+=3
        return self.parseResult(evalFilter)

    def evaluate(self, term, op, right):
        try:
            if op == "==":
                return term == right
            elif op == "!=":
                return term != right
            elif op == "<":
                return term < right
            elif op == "<=":
                return term <= right
            elif op == ">":
                return term > right
            elif op == ">=":
                return term >= right
        except Exception as e:
            print(f"Cannot compare {term} and {right}")

    def evaluateProto(self, packet, op, proto):
        if op == "==":
            return True if packet.haslayer(proto) else False
        elif op == "!=":
            return False if packet.haslayer(proto) else True
        else:
            raise ValueError(f"protocols can only be compared with == or != not {op}")

    def evaluateMark(self, packetNum, op, mark):
        if mark != "True" and mark != "False":
            raise ValueError(f"Marked Packets can only be compared with 'True' or 'False' values not {mark}")
        packetMarked = True if packetNum in self.parent.packetListView.markedPackets else False
        packetMarked = not packetMarked if mark == "False" else packetMarked
        if op == "==":
            return True if packetMarked else False
        elif op == "!=":
            return False if packetMarked else True
        else:
            raise ValueError(f"protocols can only be compared with == or != not {op}")

    def parseResult(self, res):
        if len(res) == 1:
            return res[0]
        return eval(" ".join(str(elem) for elem in res))
