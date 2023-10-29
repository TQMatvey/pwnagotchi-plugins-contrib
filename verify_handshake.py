from scapy.all import *

import pwnagotchi.plugins as plugins

import logging
import os

'''
Scapy is needed, but should be preinstalled in modern Pwnagotchi images:
> sudo pip3 install scapy
'''

class VerifyHandshake(plugins.Plugin):
    __author__ = '@tqmatvey'
    __version__ = '1.0.0'
    __license__ = 'GPL3'
    __description__ = 'verify that pcaps contains handshake/PMKID or delete them'
    
    def __init__(self):
        self.text_to_set = ""
    
    def is_valid_handshake(eapol_packets):
        # Check for a valid handshake structure
        if len(eapol_packets) == 4:
            if all([pkt.haslayer(EAPOL) for pkt in eapol_packets]):
                return True
        return False

    def check_for_valid_handshake_or_pmkid(pcap_file):
        capture = rdpcap(pcap_file)

        eapol_packets = []
        found = False

        for packet in capture:
            if packet.haslayer(EAPOL):
                eapol_packets.append(packet)

                if VerifyHandshake.is_valid_handshake(eapol_packets):
                    found = True

            # Check for PMKID
            if packet.haslayer(Dot11Elt) and packet[Dot11Elt].ID == 48:
                found = True

            if found:
                break

            if len(eapol_packets) > 4:
                eapol_packets.pop(0)

        return found
    
    def on_loaded(self):
        logging.info("[VerifyHandshake] plugin loaded")
        # TODO: Check that scapy is installed
        
    def on_handshake(self, agent, filename, access_point, client_station):
        eapol_or_pmkid = VerifyHandshake.check_for_valid_handshake_or_pmkid(filename)
        
        if eapol_or_pmkid:
            logging.info("[VerifyHandshake] Handshake or PMKID detected")
        else:
            logging.info("[VerifyHandshake] Neither EAPOL nor PMKID found")
            os.remove(filename)
            if not os.path.exists(filename):
                logging.info("[VerifyHandshake] Successfully Deleted " + filename)
