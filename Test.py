import unittest
from Main import MainApp
import tkinter as tk
from scapy.layers.inet import IP, TCP, UDP, Ether
from Summary import Summary
from Graph import GraphWindow
from Report import Report
import datetime

tcpPacket = Ether() / IP(dst="192.168.0.11", src="192.168.0.12") / TCP(sport=25352, dport=22, flags="S")
tcpPacket2 = tcpPacket
tcpPacket2.time += 1
udpPacket = Ether() / IP(dst="192.168.0.11", src="192.168.0.12") / UDP(sport=25352, dport=22)
udpPacket2 = udpPacket
udpPacket2.time += 2

class TestCases(unittest.TestCase):
    async def _start_app(self):
        self.app.mainloop()

    def setUp(self):
        root = tk.Tk()
        self.app = MainApp(root)
        self._start_app()

    def tearDown(self):
        self.app.destroy()

    def test_startup(self):
        title = self.app.winfo_toplevel().title()
        expected = 'Wirewhale'
        self.assertEqual(title, expected)

    def test_adding_packets(self):
        packetHandler = self.app.packetHandler
        self.assertEqual(packetHandler.fullPacketList, [])
        packetHandler.handleNewPacket(tcpPacket)
        self.assertTrue(len(packetHandler.fullPacketList) != 0)

    def test_filtering(self):
        packetHandler = self.app.packetHandler
        packetDisplay = self.app.packetListView.packetList
        filter = self.app.filterBar
        packetHandler.handleNewPacket(tcpPacket)
        packetHandler.handleNewPacket(udpPacket)
        self.assertTrue(len(packetDisplay.get_children()) == 2)
        filter.filterEntry.insert(0,"protocol == TCP")
        filter.func(1)
        self.assertTrue(len(packetDisplay.get_children()) == 1)
        filter.filterEntry.delete(0)
        filter.func(1)
        self.assertTrue(len(packetDisplay.get_children()) == 2)

    def test_start_stop(self):
        actionBar = self.app.actionBar
        self.assertFalse(actionBar.started)
        actionBar.startCapture.invoke()
        self.assertTrue(actionBar.started)
        actionBar.stopCapture.invoke()
        self.assertFalse(actionBar.started)

    def test_summary(self):
        packetHandler = self.app.packetHandler
        filter = self.app.filterBar
        menu = self.app.menu
        udpPacket.time = tcpPacket.time + 1
        packetHandler.handleNewPacket(tcpPacket)
        packetHandler.handleNewPacket(udpPacket)
        packetHandler.handleNewPacket(tcpPacket2)
        packetHandler.handleNewPacket(udpPacket2)
        filter.filterEntry.insert(0,"protocol == TCP")
        filter.func(1)
        summary = Summary(menu)
        firstPacketTime = datetime.datetime.fromtimestamp(tcpPacket.time).strftime('%Y-%m-%d %H:%M:%S')
        lastPacketTime = datetime.datetime.fromtimestamp(udpPacket2.time).strftime('%Y-%m-%d %H:%M:%S')
        statsTable = summary.statsTable
        ids = statsTable.get_children()
        packets = statsTable.item(ids[0])["values"]
        self.assertTrue(packets[1] == 4)
        self.assertTrue(packets[2] == 2)
        self.assertTrue(firstPacketTime in summary.firstPacketLabel["text"])
        self.assertTrue(lastPacketTime in summary.LastPacketLabel["text"])

    def test_load_pcap(self):
        packetHandler = self.app.packetHandler
        packetDisplay = self.app.packetListView.packetList
        self.assertEqual(packetHandler.fullPacketList, [])
        self.assertTrue(len(packetDisplay.get_children()) == 0)
        menu = self.app.menu
        menu.loadPcap("test.pcap")
        self.assertTrue(len(packetHandler.fullPacketList) == 614)
        self.assertTrue(len(packetDisplay.get_children()) == 614)

    def test_ids(self):
        menu = self.app.menu
        menu.loadPcap("sshtest.pcap")
        IDSHandler = self.app.IDSHandler
        self.assertTrue(len(IDSHandler.threatsByIP) == 0)
        menu.IPSMenu.invoke(2)
        self.assertTrue(len(IDSHandler.threatsByIP) == 1)

    def test_report(self):
        menu = self.app.menu
        menu.loadPcap("sshtest.pcap")
        menu.IPSMenu.invoke(2)
        report = Report(menu)
        self.assertTrue("9" in report.threatsFoundLabel["text"])
        self.assertTrue("1" in report.uniqueThreatsLabel["text"])
        self.assertTrue("1" in report.uniqueIPThreatsLabel["text"])
        self.assertTrue("SSH Bruteforce" in report.typesOfAttacksLabel["text"])
        self.assertTrue("192.168.0.23" in report.ipsUsedLabel["text"])


    def test_graph(self):
        menu = self.app.menu
        menu.loadPcap("test.pcap")
        graph = GraphWindow("Time sequence", self.app)
        self.assertTrue(len(graph.line1.get_xdata()) == 6)

    def test_packet_detail(self):
        menu = self.app.menu
        packetListView = self.app.packetListView
        packetDisplay = self.app.packetListView.packetList
        packetDetails = self.app.packetDetailListView
        packetDetailList = packetDetails.packetDetailList
        packetBytesDisplay = packetDetails.packetBytesDisplay
        menu.loadPcap("test.pcap")
        ids = packetDisplay.get_children()
        packetDisplay.selection_set(ids[0])
        packetListView.selectPacket(1)
        self.assertTrue(len(packetDetailList.get_children()) != 0)
        self.assertTrue(len(packetBytesDisplay.get("1.0", tk.END)) != 0)


if __name__ == '__main__':
    unittest.main()
