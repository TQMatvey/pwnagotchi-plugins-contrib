import os
import pwnagotchi.plugins as plugins
import logging
import glob

class HandshakeCleaner(plugins.Plugin):
    __author__ = 'TQMatvey'
    __version__ = '1.0.0'
    __license__ = 'GPL3'
    __description__ = 'Check and delete PCAP files without handshakes or PMKID'

    def __init__(self):
        self.interval = 30  # 5 minutes in seconds

    def on_loaded(self):
        logging.info("[HandshakeCleaner] plugin loaded")

    def on_periodic(self):
        # Function called periodically
        pcap_dir = "/root/handshakes/"
        pcap_files = glob.glob(os.path.join(pcap_dir, "*.pcap"))

        for pcap_file in pcap_files:
            # You can use a tool like tshark to check for handshakes or PMKID.
            # Make sure to adjust the tshark command as needed.
            command = f"tshark -r {pcap_file} -Y 'eapol' -E separator=, -T fields -e wlan_mgt.rsn.akmsuitetype -e wlan_mgt.rsn.pmkid"
            result = os.popen(command).read()
        
            # If 'pmkid' is not in the result, delete the file
            if 'pmkid' not in result:
                os.remove(pcap_file)
                logging.warning(f"Deleted: {pcap_file}")

    def get_status(self):
        return "Checking /root/handshakes/ for PCAP files without handshakes or PMKID."

