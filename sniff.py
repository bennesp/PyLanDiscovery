import thread, threading
from gi.repository import GObject
from scapy.all import IP, sniff

class ThreadSniff(threading.Thread):
  def __init__(self, window):
    threading.Thread.__init__(self)
    self.w = window
    self.STOP = False

  def stop(self):
    self.STOP = True

  def update_(self, packet):
    self.w.insert("sniff", packet)

  def update(self, packet):
    GObject.idle_add(self.update_, packet)

  def run(self):
    while self.STOP==False:
      sniff(prn=self.update, timeout=5)

  def __repr__(self):
    return "Thread sniff n."+self.id

class DiscoverSniff():
  def __init__(self, w):
    self.w = w
    self.threads = []
    self.isRunning = False

  def start(self):
    self.isRunning = True
    self.threads.append(ThreadSniff(self.w))
    for t in self.threads:
      t.start()

  def stop_(self):
    for t in self.threads:
      t.stop()
      #t.join()
    self.threads = []

  def stop(self):
    self.isRunning = False
    self.stop_()

  def loop_(self):
    self.isRunning = True
    self.start()

  def loop(self):
    thread.start_new_thread(self.loop_, ())