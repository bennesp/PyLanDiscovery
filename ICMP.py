import thread, threading
from gi.repository import GObject
from scapy.all import ICMP, IP, sr1

class ThreadICMP(threading.Thread):
  def __init__(self, ips, tid, w):
    threading.Thread.__init__(self)
    self.ips = ips
    self.id = tid
    self.w = w
    self.STOP = False

  def run(self):
    for ip in self.ips:
      if(self.STOP==False):
        p = IP(dst=ip)/ICMP()
        res = sr1(p, timeout=2)
        GObject.idle_add(self.update, (p, res))
      else:
        break

  def stop(self):
    self.STOP = True

  def update(self, packets):
    self.w.insert("ICMP", packets)

  def __repr__(self):
    return "Thread ICMP n."+self.id

class DiscoverICMP():
  def __init__(self, window):
    self.w = window
    self.threads = []
    self.isRunning = False

  def start(self):
    self.isRunning = True
    for k in range(1, 255, 16):
      ips=[]
      for i in range(k,k+16):
        if(i!=256): ips.append(self.w.PC["BASE"]+str(i))
      t = ThreadICMP(ips, len(self.threads), self.w)
      self.threads.append(t)
    for t in self.threads:
      t.start()

  def stop_(self):
    for t in self.threads:
      t.stop()
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