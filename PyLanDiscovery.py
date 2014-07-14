import threading, thread, logging
from scapy.all import srp, srp1, sr1, Ether, ARP, conf, ICMP, IP, sniff
from gi.repository import Gtk

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb=0

def contains(liststore, el):
  index = -1
  for row in liststore:
    index+=1
    for b in row:
      if(el==b):
        return index
  return -1

def add(liststore, w):
  if ("192.168." in w[1][:8]) == False:
    return False
  t=contains(liststore, w[1])
  if t==-1:
    # Nuovo IP
    liststore.append([w[0],w[1],w[2],1])
    return True
  else:
    # IP gia' esistente
    ar=liststore[t][0].split(",")
    for el in ar:
      if el==w[0]:
        # Tutto uguale, aggiungi solo 1 pacchetto
        row = liststore[t][:]
        liststore[t][3]=row[3]+1
        #print "Updated packets: " + str(row)
        return
    # Tutto uguale tranne il metodo, aggiornalo
    row = liststore[t][:]
    liststore[t][0] = row[0]+","+w[0]
    liststore[t][3] = row[3]+1
    #print "Updated method: " + str(row)
    
def discoverMACOf(addr):
  r=srp1(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=addr), timeout=2)
  if r!=None: return str(r[Ether].src)
  else: return ""

class WorkerICMP(threading.Thread):
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
          addLock.acquire()
          add(self.liststore, ["ICMP",res[IP].src, discoverMACOf(res[IP].src)])
          addLock.release()
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
      if(i!=256): ips.append(base+str(i))
    w = WorkerICMP(ips, len(threads), liststore)
    threads.append(w)
    w.start()

def discoverARP(liststore):
  packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=base+"0/24")
  ans,unans = srp(packet, timeout=3, iface="wlan0");

  for snd,rcv in ans:
    addLock.acquire()
    add(liststore, ["ARP",rcv[ARP].psrc, rcv[Ether].src])
    addLock.release()

class WorkerSniff(threading.Thread):
  def __init__(self, liststore):
    threading.Thread.__init__(self)
    self.liststore = liststore
    self.STOP = False

  def setStop(self, b):
    self.STOP = b

  def sniff_callback(self, p):
    if(IP in p) and (Ether in p):
      addLock.acquire()
      add(self.liststore, ["Sniff", p[IP].src, p[Ether].src])
      addLock.release()

  def run(self):
    while self.STOP==False:
      sniff(prn=self.sniff_callback, timeout=5)
      if(self.STOP==True):
        break

def discoverSniff(liststore):
  w = WorkerSniff(liststore)
  threads.append(w)
  w.start()

class FinestraMain(Gtk.Window):
  def __init__(self):
    Gtk.Window.__init__(self, title="PyLanDiscover v.0.2a")
    self.connect("delete-event", Gtk.main_quit)
    self.set_default_size(300, 200)
    self.liststore = Gtk.ListStore(str, str, str, int)
    
    treeview = Gtk.TreeView(model=self.liststore)
    renderer_text = Gtk.CellRendererText()
    column_method = Gtk.TreeViewColumn("Method", renderer_text, text=0)
    column_ip = Gtk.TreeViewColumn("IP", renderer_text, text=1)
    column_mac = Gtk.TreeViewColumn("Mac", renderer_text, text=2)
    column_pn = Gtk.TreeViewColumn("Packets", renderer_text, text=3)
    treeview.append_column(column_method)
    treeview.append_column(column_ip)
    treeview.append_column(column_mac)
    treeview.append_column(column_pn)

    self.add(treeview)

addLock = threading.Lock()

if __name__ == '__main__':
  # Discover base
  for r in conf.route.routes:
  if("192.168." in r[2][:8]):
    ba = r[2].split(".")
    base = ba[0]+"."+ba[1]+"."+ba[2]+"."

  # GUI
  w = FinestraMain()
  w.show_all()
  thread.start_new_thread(discoverICMP, (w.liststore,))
  thread.start_new_thread(discoverSniff, (w.liststore,))
  thread.start_new_thread(discoverARP, (w.liststore,))
  Gtk.main()
  
  # Stop all threads
  for t in threads:
    t.setStop(True)
