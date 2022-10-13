import sys
import time
import signal
import struct
import hmac
import hashlib
import binascii

from datetime import datetime
from pirc522 import RFID

HMAC_KEY_PATH = "hmac.key"
hmac_key = None

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

def UIDUpdate(self, uid, last_access, nonce):
	# TODO Update UID information in database
	return 

def DerivePassword(self, uid, salt):
	# TODO Convert UID of tag into its KeyA field
	return [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]

def HmacVerify(points, nonce, hmac):
	return HmacGenerate(points, nonce) == hmac

def HmacGenerate(points, nonce):
	return hmac.new(hmac_key, struct.pack("<IQ", points, nonce), hashlib.sha256)

def ReadBlock(self, key, sect, block):
	util.auth(rdr.auth_a, key)
	util.do_auth(util.block_addr(sect, block))

	(err, data) = rdr.read(sect * 4 + block)
	return (err, data)

def WriteBlock(self, key, sect, block, data):
	util.auth(rdr.auth_a, key)
	util.do_auth(util.block_addr(sect, block))

	return rdr.write(sect * 4 + block, data)

def ReadPointsStructure(self, section, key):
	points = None
	nonce = None
	hmac = None

	(err, data) = ReadBlock(key, section, 0)
	if err:
		return (err, points, nonce)

	(points, nonce, rsrv) = struct.unpack("<IQI", bytes(data))

	(err, data) = ReadBlock(key, section, 1)
	if err:
		return (err, points, nonce)
	hmac = bytes(data)

	(err, data) = ReadBlock(key, section, 2)
	if err:
		return (err, points, nonce)
	hmac += bytes(data)

	return (HmacVerify(points, nonce, hmac), points, nonce)

def WritePointsStrucutre(self, section, key, points, nonce):
	# TODO Figure out what should be written as reserved bytes
	rsrv = 0

	data = list(struct.pack("<IQI", points, nonce, rsrv))
	hmac = HmacGenerate(points, nonce)

	err = WriteBlock(key, section, 0, data)
	if err:
		return err

	data = list(hmac[:16])
	err = WriteBlock(key, section, 1, data)
	if err:
		return err

	data = list(hmac[16:])
	err = WriteBlock(key, section, 2, data)
	if err:
		return err

	return False

def DisplayPoints(self, points)
	# TODO Show points on display
	return

signal.signal(signal.SIGINT, end_read)

f = open(HMAC_KEY_PATH, "r")
hmac_key = binascii.unhexlify(f.read())
f.close()

while True:
	rdr.wait_for_tag()
	(err, tag_type) = rdr.request()
	if err:
		continue

	(err, uid) = rdr.anticoll()
	if err:
		continue

	(valid, last_access, salt, nonce_expected) = UIDLookup(uid)
	if not valid:
		continue

	util.set_tag(uid)

	passwd = DerivePassword(uid, salt)

	(err, points, nonce) = ReadPointsStructure(1, passwd)

	if err or nonce != nonce_expected:
		# TODO Handle error
		continue

	DisplayPoints(points)

	if datetime.now()

	util.deauth()

	time.sleep(0.5)
