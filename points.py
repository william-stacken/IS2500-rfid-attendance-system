import sys
import time
import signal
from pirc522 import RFID

rdr = RFID()
util = rdr.util()

running = True

def end_read(signal,frame):
	global running
	print("\nStopping points system...")
	running = False
	rdr.cleanup()
	sys.exit()

def UIDLookup(self):
	# TODO Lookup UID in database
	return (True, 0, 0, 0)

def DeriveKey(self, uid)
	# TODO Convert UID of tag into its KeyA field
	return [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]

signal.signal(signal.SIGINT, end_read)

while True:
	rdr.wait_for_tag()
	(err, tag_type) = rdr.request()
	if err:
		continue

	(err, uid) = rdr.anticoll()
	if err:
		continue

	(valid, last_access, salt, nonce) = UIDLookup(uid)
	if not valid:
		continue
	
	util.set_tag(uid)

	util.auth(rdr.auth_b, DeriveKey(uid))

	# TODO

	util.deauth()

	time.sleep(0.5)
