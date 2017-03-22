#!/usr/bin/python
import threading
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import*
from optparse import OptionParser

def parsing():
    argsparser = OptionParser()
    argsparser.add_option("", "--interface", dest="IF")
    argsparser.add_option("", "--victim-ip", dest="victip")
    argsparser.add_option("", "--victim-ethernet", dest="victmac")
    argsparser.add_option("", "--reflector-ip", dest="reflip")
    argsparser.add_option("", "--reflector-ethernet", dest="reflmac")
    (values, args) = argsparser.parse_args()
    return values

args = parsing()
def handle_arp(orig):
    if(orig[ARP].op == 1):
        if(orig[ARP].pdst == args.victip):
            retip, retmac = args.victip, args.victmac
        elif(orig[ARP].pdst == args.reflip):
            retip, retmac = args.reflip, args.reflmac
        else: return

        attacker_ip, attacker_mac = orig[ARP].psrc, orig[Ether].src

        send(ARP(op=2, hwsrc=retmac, hwdst=attacker_mac, psrc=retip, pdst=attacker_ip))
    if(orig[ARP].op == 2):
        pass

    return

def construct_ret_set(dstip):
    if dstip == args.victip: 
        return args.reflip, args.reflmac
    
    if dstip == args.reflip: 
        return args.victip, args.victmac

    return None, None

def handle_icmp(orig):
    retip, retmac = construct_ret_set(orig[IP].dst)
    if retip == None: return
    has_payload = False

    try:
        orig[Raw]
        has_payload = True
    except: pass


    icmp = orig[ICMP]
    if has_payload:
        P = (IP(src=retip, dst=orig[IP].src)
                /ICMP(type=icmp.type
                    , code=icmp.code
                    , seq=icmp.seq
                    , id=icmp.id, )
                /orig[Raw].load)
    else:
        P = (IP(src=retip, dst=orig[IP].src)
                /ICMP(type=icmp.type
                    , code=icmp.code
                    , seq=icmp.seq
                    , id=icmp.id, ))

    send(P)

def handle_tcp(orig):
    retip, retmac = construct_ret_set(orig[IP].dst)
    if retip == None: return
#    if retip == args.victip: return
#    if retip == args.reflip: return
    has_payload = True

    try:
        orig[Raw]
    except:
        has_payload = False
    
    tcp = orig[TCP]
#    print "-----", tcp.ack, "-----"
#    print "---before----", orig.show()
    if has_payload:    
        P = (IP(src=retip, dst=orig[IP].src)
                /TCP(sport=tcp.sport
                    , dport=tcp.dport
                    , seq=tcp.seq
                    , flags=tcp.flags
                    , options=tcp.options
                    , ack = orig[TCP].ack)
                /orig[Raw].load)
    else: 
        P = (IP(src=retip, dst=orig[IP].src)
                /TCP(sport=tcp.sport
                    , dport=tcp.dport
                    , seq=tcp.seq
                    , flags=tcp.flags
                    , options=tcp.options
                    , ack = orig[TCP].ack))

    send(P);

def handle_udp(orig):
    retip, retmac = construct_ret_set(orig[IP].dst)
    if retip == None: return
    has_payload = True

    try:
        orig[Raw]
    except:
        has_payload = False

    udp = orig[UDP]
    if has_payload:
        P = (IP(src=retip, dst=orig[IP].src)
                /UDP(sport=udp.sport
                    ,dport=udp.dport
                    ,len=udp.len)
                /orig[Raw].load)

    else:
        P = (IP(src=retip, dst=orig[IP].src)
                /UDP(sport=udp.sport
                    ,dport=udp.dport
                    ,len=udp.len))

    send(P)

def dispatch_orig(orig):

    farp = False
    try:
        orig[ARP]
        farp = True
    except: pass

    if farp: return threading.Thread(target=handle_arp, args=(orig,)).start()


    try:
        orig[IP]
    except:
        return

    ficmp = False
    fudp = False
    ftcp = False
    try:
        orig[ICMP]
        ficmp = True
    except: pass

    try:
        orig[UDP]
        fudp = True
    except: pass

    try:
        orig[TCP]
        ftcp = True
    except: pass

    if ficmp: return threading.Thread(target=handle_icmp, args=(orig,)).start()

    if fudp: return threading.Thread(target=handle_udp, args=(orig,)).start()

    if ftcp: return threading.Thread(target=handle_tcp, args=(orig,)).start()


sniff(iface=args.IF,  prn = dispatch_orig)

def dispatch_orig(orig):

    farp = False
    try:
        orig[ARP]
        farp = True
    except: pass

    if farp: returnhandle_arp(orig)


    try:
        orig[IP]
    except:
        return

    ficmp = False
    fudp = False
    ftcp = False
    try:
        orig[ICMP]
        ficmp = True
    except: pass

    try:
        orig[UDP]
        fudp = True
    except: pass

    try:
        orig[TCP]
        ftcp = True
    except: pass

    if ficmp: return threading.Thread(target=handle_icmp, args=(orig,)).start()

    if fudp: return threading.Thread(target=handle_udp, args=(orig,)).start()

    if ftcp: return threading.Thread(target=handle_tcp, args=(orig,)).start()


sniff(iface=args.IF,  prn = dispatch_orig)
