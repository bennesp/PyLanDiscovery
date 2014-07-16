import thread, threading
from gi.repository import GObject
from scapy.all import Ether, ARP, srp

class ThreadARP(threading.Thread):
  def __init__(self, ips, tid, w):
    threading.Thread.__init__(self)
    self.ips = ips
    self.id = tid
    self.w = w

  def run(self):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.ips)
    ans,unans = srp(packet, timeout=3);
    GObject.idle_add(self.update, ans)

  def update(self, packets):
    self.w.insert("ARP", packets)

  def __repr__(self):
    return "Thread ARP n."+self.id

class DiscoverARP():
  def __init__(self, window):
    self.w = window
    self.threads = []
    self.isRunning = False

  def start(self):
    self.isRunning = True
    self.threads.append(ThreadARP(self.w.PC["BASE"]+"0/24", 1, self.w))
    for t in self.threads:
      t.start()

  def stop_(self):
    for t in self.threads:
      pass#t.join()
    self.threads = []

  def stop(self):
    self.isRunning = False
    self.stop_()

  def loop_(self):
    self.isRunning = True
    while self.isRunning:
      self.start()
      for t in self.threads:
        t.join()
      self.stop_()

  def loop(self):
    thread.start_new_thread(self.loop_, ())