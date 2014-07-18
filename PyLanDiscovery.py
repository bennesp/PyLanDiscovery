#!/usr/bin/python2

import logging, os
from ARP import DiscoverARP
from ICMP import DiscoverICMP
from sniff import DiscoverSniff
from scapy.all import srp1, Ether, ARP, IP, conf, get_if_hwaddr
from gi.repository import Gtk, GObject

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb=0
VERSION = "0.4b"

class ListStore(Gtk.ListStore):
  def contains(self, el, column):
    index = -1
    for row in self:
      index += 1
      if(el in row[column]):
        return index
    return -1
    
def vendorOf(mac):
  for line in open("list"):
    ar = line.split("%")
    if(mac[:8].lower()==ar[0].lower()):
      return ar[1].strip()
  return "Unknown"

def discoverMACOf(addr):
  r=srp1(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=addr), timeout=2)
  if r!=None: return str(r[Ether].src)
  else: return ""

class FinestraMain(Gtk.Window):
  def __init__(self):
    Gtk.Window.__init__(self, title="PyLanDiscovery v."+VERSION)
    self.connect("delete-event", Gtk.main_quit)

    grid1 = Gtk.Grid()
    grid2 = Gtk.Grid()

    self.liststore = ListStore(str, str, str, str, int)
    sorted_model = Gtk.TreeModelSort(model=self.liststore)
    sorted_model.set_sort_column_id(1, Gtk.SortType.DESCENDING)
    
    treeview = Gtk.TreeView(model=sorted_model)
    renderer_text = Gtk.CellRendererText()
    column_method = Gtk.TreeViewColumn("Method", renderer_text, markup=0)
    column_ip = Gtk.TreeViewColumn("IP", renderer_text, markup=1)
    column_mac = Gtk.TreeViewColumn("Mac", renderer_text, markup=2)
    column_ven = Gtk.TreeViewColumn("Vendor", renderer_text, markup=3)
    column_pn = Gtk.TreeViewColumn("Packets", renderer_text, markup=4)
    treeview.append_column(column_method)
    treeview.append_column(column_ip)
    treeview.append_column(column_mac)
    treeview.append_column(column_ven)
    treeview.append_column(column_pn)

    button1 = Gtk.Button("Start ICMP")
    button2 = Gtk.Button("Start ARP")
    button3 = Gtk.Button("Stop sniff")
    button1.connect("clicked", self.button1_clicked)
    button2.connect("clicked", self.button2_clicked)
    button3.connect("clicked", self.button3_clicked)

    self.progressbar1 = Gtk.ProgressBar()
    self.progressbar1.set_text("ICMP disabled")
    self.progressbar1.set_show_text(True)
    self.progressbar2 = Gtk.ProgressBar()
    self.progressbar2.set_text("Scanning...")
    self.progressbar2.set_show_text(True)

    grid1.attach(treeview, 0, 0, 3, 7)
    grid1.attach(button1, 0, 8, 1, 1)
    grid1.attach(button2, 1, 8, 1, 1)
    grid1.attach(button3, 2, 8, 1, 1)
    grid1.attach(self.progressbar1, 0, 9, 3, 1)
    grid1.attach(self.progressbar2, 0, 10, 3, 1)

    nb = Gtk.Notebook()
    nb.append_page(grid1, Gtk.Label(label="Scan Lan"))

    self.add(nb)
    self.show_all()

  def compare(self, model, row1, row2, user_data):
    sort_column, _ = model.get_sort_column_id()
    value1 = model.get_value(row1, sort_column)
    value2 = model.get_value(row2, sort_column)
    if(self.PC["IP"] in value1):
      return -1
    if(self.PC["IP"] in value2):
      return 1
    if int(value1.split(".")[3]) < int(value2.split(".")[3]):
      print value1.split(".")[3]+"<"+value2.split(".")[3]
      return -1
    else:
      return 1

  def get_pc_info(self):
    self.PC = {}
    for r in conf.route.routes:
      if("0.0.0.0" not in r[2]):
        ba = r[2].split(".")
        self.PC["BASE"] = ba[0]+"."+ba[1]+"."+ba[2]+"."
        self.PC["IP"] = r[4]
        self.PC["MAC"] = get_if_hwaddr(r[3])
        self.PC["IFACE"] = r[3];
    if(self.PC["BASE"]=="") or (self.PC["IP"]=="") or (self.PC["MAC"]=="") or (self.PC["IFACE"]==""):
      dialog = Gtk.MessageDialog(None, 0, Gtk.MessageType.ERROR,
        Gtk.ButtonsType.OK, "Error")
      dialog.format_secondary_text("Cannot find iface, gateway, IP or MAC.")
      dialog.run()
      dialog.destroy()
      exit(1)

  def button1_clicked(self, b):
    if("Stop" in b.get_label()):
      self.progressbar1.set_text("ICMP disabled")
      self.progressbar1.set_fraction(0)
      self.icmp.stop()
      del self.icmp
      self.icmp = DiscoverICMP(self)
      b.set_label("Start ICMP")
    else:
      self.progressbar1.set_text("Starting ICMP...")
      self.icmp.loop()
      b.set_label("Stop ICMP")

  def button2_clicked(self, b):
    if("Stop" in b.get_label()):
      self.arp.stop()
      del self.arp
      self.arp = DiscoverARP(self)
      b.set_label("Start ARP")
      if(self.sniff.isRunning==False):
        self.progressbar2.set_text("ARP and sniff disabled.")
        self.progressbar2.set_fraction(0)
    else:
      self.progressbar2.set_text("Starting ARP...")
      self.arp.loop()
      b.set_label("Stop ARP")

  def button3_clicked(self, b):
    if("Stop" in b.get_label()):
      self.sniff.stop()
      del self.sniff
      self.sniff = DiscoverSniff(self)
      b.set_label("Start sniff")
      if(self.arp.isRunning==False):
        self.progressbar2.set_text("ARP and sniff disabled.")
        self.progressbar2.set_fraction(0)
    else:
      self.progressbar2.set_text("Starting sniff...")
      self.sniff.start()
      b.set_label("Stop sniff")

  def start(self):
    self.get_pc_info()
    self.liststore.append(["This PC","<span color=\"green\">"+self.PC["IP"]+
      "</span>", "<span color=\"green\">"+self.PC["MAC"]+"</span>",
      "<span color=\"green\">"+vendorOf(self.PC["MAC"])+"</span>",0])

    self.icmp = DiscoverICMP(self)
    self.arp = DiscoverARP(self)
    self.sniff = DiscoverSniff(self)

    self.sniff.loop()

  def stop(self):
    self.icmp.stop()
    self.arp.stop()
    self.sniff.stop()

  """ Private method: Insert one packet in liststore """
  def _insert_packet(self, method, p):
    # if there isn't layer IP in p, quit
    if IP not in p: return False
    # if is not a local IP, quit
    if self.PC["BASE"] not in p[IP].src: return False
    # if IP isn't already in list
    t=self.liststore.contains(p[IP].src, 1)
    if t==-1:
      if(Ether not in p):
        p = p/Ether()
        p[Ether].src = discoverMACOf(p[IP].src)
      self.liststore.append([method, p[IP].src, p[Ether].src,
        vendorOf(p[Ether].src), 1])
      return True

    if self.liststore[t][2] is None:
      self.liststore[t][2] = discoverMACOf(self.liststore[t][1])
      self.liststore[t][3] = vendorOf(self.liststore[t][2])

    if(Ether in p) and (p[Ether].src is not None) and (p[Ether].src!="00:00:00:00:00:00") and (self.liststore[t][2]!="") and (p[Ether].src not in self.liststore[t][2]):
      print "From "+self.liststore[t][2]+" to "+p[Ether].src
      self.liststore[t][2] = "<span color=\"red\">"+p[Ether].src+"</span>"
      self.liststore[t][3] = vendorOf(self.liststore[t][2])

    row = self.liststore[t][:]
    self.liststore[t][4] = row[4]+1
    for el in self.liststore[t][0].split(","):
      if (method==el) or ("This PC"==el):
        return True
    self.liststore[t][0] = ','.join(map(str, sorted((row[0]+","+method).split(","))))
    return True

  """ Insert many packets in liststore """
  def insert(self, method, packets):
    if method == "ICMP":
      if(self.icmp.isRunning==False): return False
      cur = self.progressbar1.get_fraction()
      self.progressbar1.set_text("ICMP: " + packets[0][IP].dst + " ("+str(int(256*cur))+"/255) ")
      if(cur + 1.0/256)<1.0:
        self.progressbar1.set_fraction(cur+1.0/256)
      else:
        self.progressbar1.set_fraction(0)
      p = packets[1]
      if p is None: return False
      self._insert_packet(method, p)
    elif method == "ARP":
      if(self.arp.isRunning==False): return False
      self.progressbar2.set_text(method)
      self.progressbar2.pulse()
      for snd,rcv in packets:
        if ARP not in rcv: return False
        rcv=rcv/IP(src=rcv[ARP].psrc)
        self._insert_packet(method, rcv)
    elif method == "sniff":
      if(self.sniff.isRunning==False): return False
      self.progressbar2.set_text(method)
      self.progressbar2.pulse()
      self._insert_packet(method, packets)
    else:
      return False
    return True

def main():
  # GUI
  if(os.getuid()!=0):
    dialog = Gtk.MessageDialog(None, 0, Gtk.MessageType.ERROR,
      Gtk.ButtonsType.OK, "Error")
    dialog.format_secondary_text("You have to run this script with sudo, scapy needs it.")
    dialog.run()
    dialog.destroy()
    exit(1)

  w = FinestraMain()
  w.start()
  GObject.threads_init()
  Gtk.main()
  w.stop()

if __name__ == '__main__':
  main()