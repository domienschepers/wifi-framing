# Import dependencies and libraries.
from dependencies.libwifi.wifi import *
from library.testcase import Trigger, Action, Test

class QueueSAQuery(Test):
	""" Queueing of SA Queries against an AP.
	"""
	name = "queue-saquery"
	kind = Test.Supplicant

	# Instructions:
	# cd setup; ./load-config.sh wpa3-personal-pmf
	# clear; ./hostap.py wlan0 --ap
	# clear; ./run.py wlan1 queue-saquery
	
	def __init__(self):
		super().__init__([
			# Inject Association-request frames.
			Action( trigger=Trigger.Connected, action=Action.Inject ),
			Action( trigger=Trigger.Connected, action=Action.Inject ),
			# Listen for an unprotected deauthentication frame and exit.
			Action( trigger=Trigger.Connected, action=Action.Receive ),
			Action( trigger=Trigger.Received, action=Action.Terminate )
		])
		
	def receive(self, station, frame):
		if frame[Dot11].addr2 != station.bss:
			return False
		if frame[Dot11].addr1 != station.mac:
			return False
		if frame.haslayer(Dot11Deauth):
			log(STATUS, frame.summary(), color="orange")
			log(STATUS,'Detected an unprotected deauthentication frame from AP.', color="green")
			return True
		return False
			
	def generate(self, station):
		
		# Construct payload for the Association-request.
		payload = Dot11AssoReq()
		payload /= Dot11Elt( ID='SSID', info='testnetwork' )
		payload /= Dot11Elt( ID='Rates', info='\x02\x04\x0b\x16\x0c\x12\x18\x24' )
		payload /= Dot11Elt( ID='ESRates', info='\x30\x48\x60\x6c' )
		payload /= Raw(bytes.fromhex("301a0100000fac040100000fac040100000fac08c0000000000fac06")) # RSN.
		
		# Inject Association-request frame.
		frame = Dot11( type="Management" , subtype=0 , addr1=station.bss , addr2=station.mac , addr3=station.bss )
		frame.FCfield |= Dot11(FCfield="pw-mgt").FCfield # Set to sleep.
		self.actions[0].set_frame( frame/payload , mon=True , encrypt=False )
		self.actions[0].set_delay( delay=1 )

		# Inject Association-request frame.
		frame = Dot11( type="Management" , subtype=0 , addr1=station.bss , addr2=station.mac , addr3=station.bss )
		self.actions[1].set_frame( frame/payload , mon=True , encrypt=False )
		self.actions[1].set_delay( delay=2 ) # Wait for SA Query timeout.
		
		# Listen for an unprotected deauthentication frame.
		self.actions[2].set_receive( self.receive , mon=True )
		
		# Exit after a delay to avoid interference in logs.
		self.actions[3].set_delay( delay=2 )
