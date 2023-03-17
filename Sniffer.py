from multiprocessing import Process, Queue
from scapy.all import sniff


class Sniffer:
    def start(self):
        queue = Queue()
        self.process = Process(target=sniffer, args=(queue,), daemon=True)
        self.process.start()
        return queue

    def stop(self):
        self.process.terminate()


def sniffer(q):
    sniff(prn=lambda x: q.put(x))
