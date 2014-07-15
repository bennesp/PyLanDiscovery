import threading, thread, logging, time
from scapy.all import srp, srp1, sr1, Ether, ARP, conf, ICMP, IP, sniff, get_if_hwaddr
from gi.repository import Gtk, GObject

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb=0
VERSION = "0.3a"

threadsICMP = []
threadsSniff = []
STOP_ARP = True
STOP_ICMP = True
STOP_SNIFF = False

def contains(liststore, el):
  index = -1
  for row in liststore:
    index+=1
    if(el in row[1]):
      return index
  return -1

def add(liststore, w):
  global current_ip
  if ("192.168." in w[1]) == False:
    return False
  t=contains(liststore, w[1])
  if t==-1:
    # Nuovo IP
    liststore.append([w[0],w[1],w[2],1])
    return True
  else: # IP gia' esistente
    if(liststore[t][2]==""):
      liststore[t][2] = discoverMACOf(liststore[t][1])
    ar=liststore[t][0].split(",")
    for el in ar:
      if (el in w[0]) or ("This PC" in el):
        # Tutto uguale, aggiungi solo 1 pacchetto
        row = liststore[t][:]
        liststore[t][3]=row[3]+1
        return
    # Tutto uguale tranne il metodo, aggiornalo
    row = liststore[t][:]
    liststore[t][0] = row[0]+","+w[0]
    liststore[t][3] = row[3]+1
    
def discoverMACOf(addr):
  r=srp1(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=addr), timeout=2)
  if r!=None: return str(r[Ether].src)
  else: return ""

class WorkerICMP(threading.Thread):
  def __init__(self, ips, tid, liststore, updatePB):
    threading.Thread.__init__(self)
    self.ips = ips
    self.id = tid
    self.liststore = liststore
    self.updatePB = updatePB
    self.STOP = False

  def run(self):
    for ip in self.ips:
      if(self.STOP==False):
        GObject.idle_add(self.updatePB, 1.0/256, "ICMP: " + ip)
        res = sr1(IP(dst=ip)/ICMP(), timeout=2)
        if res!=None:
          add(self.liststore, ["ICMP",res[IP].src, discoverMACOf(res[IP].src)])
      else:
        break

  def setStop(self, b):
    self.STOP = b

def discoverICMP(liststore, updatePB):
  global threadsICMP
  for k in range(1, 255, 16):
    ips=[]
    for i in range(k,k+16):
      if(i!=256): ips.append(base+str(i))
    w = WorkerICMP(ips, len(threadsICMP), liststore, updatePB)
    threadsICMP.append(w)
    w.start()

  # Detect every 2 secs if all threads are stopped
  while True:
    a = True
    for t in threadsICMP:
      if(t.isAlive()==True):
        a = False
        break
    time.sleep(2)
    # If all threads are stopped
    if(a):
      GObject.idle_add(updatePB, -1, "ICMP Finished")
      for t in threadsICMP:
        # Free resources
        t.join()
        del t
      # Restart
      threadsICMP = []
      break
  time.sleep(3)
  if(STOP_ICMP):
    return
  discoverICMP(liststore, updatePB)

def discoverARP(liststore, updatePB):
  global STOP_ARP
  while True:
    packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=base+"0/24")
    ans,unans = srp(packet, timeout=3);
    for snd,rcv in ans:
      GObject.idle_add(updatePB)
      add(liststore, ["ARP",rcv[ARP].psrc, rcv[Ether].src])
    time.sleep(2)
    if(STOP_ARP):
      break

class WorkerSniff(threading.Thread):
  def __init__(self, liststore, updatePB):
    threading.Thread.__init__(self)
    self.liststore = liststore
    self.updatePB = updatePB
    self.STOP = False

  def setStop(self, b):
    self.STOP = b

  def sniff_callback(self, p):
    GObject.idle_add(self.updatePB)
    if(IP in p) and (Ether in p):
      add(self.liststore, ["sniff", p[IP].src, p[Ether].src])

  def run(self):
    while self.STOP==False:
      sniff(prn=self.sniff_callback, timeout=5)
      if(self.STOP==True):
        break

def discoverSniff(liststore, progressbar):
  w = WorkerSniff(liststore, progressbar)
  threadsSniff.append(w)
  w.start()

class FinestraMain(Gtk.Window):
  def __init__(self):
    Gtk.Window.__init__(self, title="PyLanDiscovery v."+VERSION)
    self.connect("delete-event", Gtk.main_quit)

    self.grid = Gtk.Grid()

    self.liststore = Gtk.ListStore(str, str, str, int)
    treeview = Gtk.TreeView(model=self.liststore)
    renderer_text = Gtk.CellRendererText()
    column_method = Gtk.TreeViewColumn("Method", renderer_text, markup=0)
    column_ip = Gtk.TreeViewColumn("IP", renderer_text, markup=1)
    column_mac = Gtk.TreeViewColumn("Mac", renderer_text, markup=2)
    column_pn = Gtk.TreeViewColumn("Packets", renderer_text, markup=3)
    treeview.append_column(column_method)
    treeview.append_column(column_ip)
    treeview.append_column(column_mac)
    treeview.append_column(column_pn)

    self.liststore.append(["This PC","<span color=\"green\">"+current_ip+
      "</span>", "<span color=\"green\">"+current_mac+"</span>",0])

    self.button1 = Gtk.Button("Start ICMP")
    self.button2 = Gtk.Button("Start ARP")
    self.button3 = Gtk.Button("Stop sniff")
    self.button1.connect("clicked", self.button1_clicked)
    self.button2.connect("clicked", self.button2_clicked)
    self.button3.connect("clicked", self.button3_clicked)

    self.progressbar1 = Gtk.ProgressBar()
    self.progressbar1.set_text("ICMP disabled")
    self.progressbar1.set_show_text(True)
    self.progressbar2 = Gtk.ProgressBar()
    self.progressbar2.set_text("Scanning...")
    self.progressbar2.set_show_text(True)

    self.grid.attach(treeview, 0, 0, 3, 8)
    self.grid.attach(self.button1, 0, 8, 1, 1)
    self.grid.attach(self.button2, 1, 8, 1, 1)
    self.grid.attach(self.button3, 2, 8, 1, 1)
    self.grid.attach(self.progressbar1, 0, 9, 3, 1)
    self.grid.attach(self.progressbar2, 0, 10, 3, 1)
    self.add(self.grid)

  def updatePB1(self, fr, text):
    global STOP_ICMP
    a=0
    if self.progressbar1.get_fraction()!=0:
      a=self.progressbar1.get_fraction()*256
      a=int(a)
    if STOP_ICMP is False:
      self.progressbar1.set_text(text+" ("+str(a)+"/255)")
    else:
      self.progressbar1.set_text("ICMP disabled")
    self.progressbar1.set_fraction(self.progressbar1.get_fraction()+fr)

  def updatePB2(self):
    t = {}
    t[0] = ""
    t[1] = ""
    if STOP_ARP is False:
      t[0]=" ARP"
    if STOP_SNIFF is False:
      t[1]=" sniff"
    if STOP_ARP and STOP_SNIFF:
      self.progressbar2.set_text("ARP and sniff disabled")
      self.progressbar2.set_fraction(0)
    else:
      self.progressbar2.set_text("Running"+t[0]+t[1]+"...")
      self.progressbar2.pulse()

  def button1_clicked(self, b):
    global threadsICMP, STOP_ICMP, w
    if("Stop" in b.get_label()):
      for t in threadsICMP:
        t.setStop(True)
      STOP_ICMP = True
      b.set_label("Start ICMP")
    else:
      STOP_ICMP = False
      thread.start_new_thread(discoverICMP, (w.liststore, w.updatePB1))
      b.set_label("Stop ICMP")

  def button2_clicked(self, b):
    global STOP_ARP
    if("Stop" in b.get_label()):
      STOP_ARP = True
      b.set_label("Start ARP")
    else:
      STOP_ARP = False
      thread.start_new_thread(discoverARP, (w.liststore, w.updatePB2))
      b.set_label("Stop ARP")

  def button3_clicked(self, b):
    global STOP_SNIFF
    global threadsSniff
    if("Stop" in b.get_label()):
      STOP_SNIFF = True
      for t in threadsSniff:
        t.setStop(True)
      b.set_label("Start sniff")
    else:
      STOP_SNIFF = False
      thread.start_new_thread(discoverSniff, (w.liststore, w.updatePB2))
      b.set_label("Stop sniff")

base = ""
current_ip = ""
current_mac = ""
w = None
def main():
  global base, current_ip, current_mac, w
  # Discover base, ip, mac
  for r in conf.route.routes:
    if("0.0.0.0" not in r[2]):
      ba = r[2].split(".")
      base = ba[0]+"."+ba[1]+"."+ba[2]+"."
      current_ip = r[4]
      current_mac = get_if_hwaddr(r[3])
  if base=="" or current_ip=="" or current_mac=="":
    dialog = Gtk.MessageDialog(None, 0, Gtk.MessageType.ERROR,
      Gtk.ButtonsType.OK, "Error")
    dialog.format_secondary_text("Cannot find gateway, IP or MAC ('"+base+
      "', '"+current_ip+"', '"+current_mac+"')")
    dialog.run()
    dialog.destroy()
    exit(1)

  # GUI
  w = FinestraMain()
  w.show_all()
  thread.start_new_thread(discoverSniff, (w.liststore, w.updatePB2))
  GObject.threads_init()
  Gtk.main()
  
  # Stop all threads
  for t in threadsICMP:
    t.setStop(True)
  for t in threadsSniff:
    t.setStop(True)

if __name__ == '__main__':
  main()