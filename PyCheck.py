import threading
import thread
import logging
from scapy.all import srp, srp1, sr1, Ether, ARP, conf, ICMP, IP
from gi.repository import Gtk
import time

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb=0

def discoverMACOf(addr):
  r=srp1(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=addr), timeout=2)
  if r!=None: return str(r[Ether].src)
  else: return ""

class Worker(threading.Thread):
  def __init__(self, ips, tid, liststore):
    threading.Thread.__init__(self)
    self.ips = ips
    self.id = tid
    self.liststore = liststore
    self.STOP = False
    #print("Worker n."+str(self.id)+" pronto!")

  def run(self):
    #print "Worker n."+str(self.id)+" avviato!"
    for ip in self.ips:
      if(self.STOP==False):
        res = sr1(IP(dst=ip)/ICMP(), timeout=2, iface="wlan0")
        if res!=None:
          #print res.sprintf("ICMP,%Ethernet.src%,%IP.src%")
          self.liststore.append(["ICMP",res[IP].src, discoverMACOf(res[IP].src)])
      else:
        #print "Worker n."+str(self.id)+" fermato"
        break

  def setStop(self, b):
    self.STOP = b

threads = []
def discoverICMP(liststore):
  for k in range(1, 255, 16):
    ips=[]
    for i in range(k,k+16):
      if(i!=256): ips.append("192.168.1."+str(i))
    w = Worker(ips, len(threads), liststore)
    w.setDaemon(False)
    threads.append(w)
    w.start()

def discoverARP(liststore):
  packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24")
  ans,unans = srp(packet, timeout=3, iface="wlan0");

  for snd,rcv in ans:
    print rcv.sprintf("ARP,%Ethernet.src%,%IP.src%")
    liststore.append(["ARP",rcv[ARP].psrc, rcv[Ether].src])

class FinestraMain(Gtk.Window):
  def __init__(self):
    Gtk.Window.__init__(self, title="Checker")
    self.connect("delete-event", Gtk.main_quit)
    self.liststore = Gtk.ListStore(str, str, str)
    
    treeview = Gtk.TreeView(model=self.liststore)
    renderer_text = Gtk.CellRendererText()
    column_method = Gtk.TreeViewColumn("Method", renderer_text, text=0)
    column_ip = Gtk.TreeViewColumn("IP", renderer_text, text=1)
    column_mac = Gtk.TreeViewColumn("Mac", renderer_text, text=2)
    treeview.append_column(column_method)
    treeview.append_column(column_ip)
    treeview.append_column(column_mac)

    self.add(treeview)

if __name__ == '__main__':
  w = FinestraMain()
  w.show_all()
  thread.start_new_thread(discoverICMP, (w.liststore,))
  thread.start_new_thread(discoverARP, (w.liststore,))
  Gtk.main()
  
  for t in threads:
    t.setStop(True)
