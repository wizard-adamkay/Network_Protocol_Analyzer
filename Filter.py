import tkinter as tk

class FilterBar(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(**kw)
        self.parent = parent
        self.currentFilter = ""

        def func(event):
            userInput = self.filterEntry.get()
            try:
                self.currentFilter = userInput
                self.parent.packetListView.clear()
                for index, packet in enumerate(self.parent.packetHandler.fullPacketList):
                    if self.filterPacket(packet):
                        self.parent.packetListView.addToList(index + 1, packet)
            except Exception as e:
                print(e)


        self.filterEntry = tk.Entry(self)
        self.filterEntry.bind("<Return>", func)
        self.grid_columnconfigure(0, weight=1)
        self.filterEntry.grid(row=0, sticky=tk.EW)


    def filterPacket(self, packet):
        allowedTerms = ("srcip", "dstip", "srcport", "dstport", "time", "flags", "protocol")
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
                else:
                    evalFilter.append(self.evaluate(packet.payload.src, op, right))
            elif term == 'dstip':
                if "ARP" in packet:
                    evalFilter.append(self.evaluate(packet["ARP"].pdst, op, right))
                else:
                    evalFilter.append(self.evaluate(packet.payload.dst, op, right))
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

    def parseResult(self, res):
        if len(res) == 1:
            return res[0]
        return eval(" ".join(str(elem) for elem in res))
