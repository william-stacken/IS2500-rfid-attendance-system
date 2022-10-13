#!/usr/bin/python3

import sys
import time
import signal
import struct
import hmac
import hashlib
import binascii
import argparse

from datetime import datetime
from pirc522 import RFID

HMAC_KEY_PATH = "hmac.key"
hmac_key = None

rdr = RFID()
util = rdr.util()

running = True
verbosity = 0

def PrintDEBUG(self, msg):
	if verbosity > 2:
		print("[DEBUG]: %s" % msg)

def PrintINFO(self, msg):
	if verbosity > 1:
		print("[INFO]: %s" % msg)

def PrintERROR(self, msg):
	if verbosity > 0:
		print("[ERROR]: %s" % msg)

from xml.dom.minidom import parse
import xml.dom.minidom

def DeltaPointLookup(self):
	# TODO Lookup the points to add in database
	return 1

def UIDLookup(self, uid):
	# TODO Lookup UID in database
	db = xml.dom.minidom.parse("db.xml")
	root = db.documentElement
	uid = binascii.hexlify(bytes(uid)).decode().lower()

	for tag in db.documentElement.getElementsByTagName("Tags")[0].getElementsByTagName("Tag"):
		if tag.getAttribute("UID").lower() == uid:
			return (True, int(tag.getAttribute("LastAccess")), int(tag.getAttribute("Salt")), int(tag.getAttribute("Nonce")))

	return (False, 0, 0, 0)

def UIDUpdate(self, uid, last_access, nonce):
	# TODO Update UID information in database
	db = xml.dom.minidom.parse("db.xml")
	root = db.documentElement
	uid = binascii.hexlify(bytes(uid)).decode().lower()

	for tag in db.documentElement.getElementsByTagName("Tags")[0].getElementsByTagName("Tag"):
		if tag.getAttribute("UID").lower() == uid:
			tag.setAttribute("LastAccess", str(last_access))
			tag.setAttribute("Nonce", str(nonce))

	with open("db.xml", "w") as f:
		f.write(db.documentElement.toxml())

def HmacVerify(points, nonce, hmac):
	expected = HmacGenerate(points, nonce)
	PrintDEBUG("Expected HMAC %s, got %s" % (expected, hmac))
	return expected == hmac

def HmacGenerate(points, nonce):
	hmac = hmac.new(hmac_key, struct.pack("<IQ", points, nonce), hashlib.sha256)
	PrintDEBUG("Generated HMAC %s for points %d and nonce %d" % (hmac, points, nonce))
	return hmac

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
		PrintERROR("Failed to read section %d block 0" % section)
		return (err, False, points, nonce)

	(points, nonce, rsrv) = struct.unpack("<IQI", bytes(data))

	(err, data) = ReadBlock(key, section, 1)
	if err:
		PrintERROR("Failed to read section %d block 1" % section)
		return (err, False, points, nonce)
	hmac = bytes(data)

	(err, data) = ReadBlock(key, section, 2)
	if err:
		PrintERROR("Failed to read section %d block 2" % section)
		return (err, False, points, nonce)
	hmac += bytes(data)

	return (False, HmacVerify(points, nonce, hmac), points, nonce)

def WritePointsStrucutre(self, section, key, points, nonce):
	# TODO Figure out what should be written as reserved bytes
	rsrv = 0

	data = list(struct.pack("<IQI", points, nonce, rsrv))
	hmac = HmacGenerate(points, nonce)

	err = WriteBlock(key, section, 0, data)
	if err:
		PrintERROR("Failed to write to section %d block 0" % section)
		return err

	data = list(hmac[:16])
	err = WriteBlock(key, section, 1, data)
	if err:
		PrintERROR("Failed to write to section %d block 1" % section)
		return err

	data = list(hmac[16:])
	err = WriteBlock(key, section, 2, data)
	if err:
		PrintERROR("Failed to write to section %d block 2" % section)
		return err

	return False

def ResetPointsStructure(self, section, key):
	return WritePointsStructure(section, key, 0, 0)

def DerivePassword(self, uid, salt):
	# TODO Convert UID of tag into its KeyA field
	return [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]

def DisplayPoints(self, points, new_points):
	# TODO Show points on display
	if points == new_points:
		print("You have %d points" % points)
	else:
		print("You received %d points!" % (new_points - points))
		print("You now have %d points" % new_points)

def end_read(signal,frame):
	global running
	print("\nStopping points system...")
	running = False
	rdr.cleanup()
	sys.exit()

signal.signal(signal.SIGINT, end_read)

parser = argparse.ArgumentParser(prog=sys.argv[0], description='Reads and writes points to a MIFARE Classic RFID tag using the RC522 RFID reader')
parser.add_argument('-r', '--reset', type=bool, default=False,
                    help='Reset the points on the tag to 0 permanently if they are invalid.')
parser.add_argument('-v', '--verbose', action='count', default=0,
                    help='The verbosity of prints to be shown.')

args = parser.parse_args(args=sys.argv[1:])

verbosity = args.verbose
util.debug = verbosity > 2

f = open(HMAC_KEY_PATH, "r")
hmac_key = binascii.unhexlify(f.read())
f.close()

print("Points system started")
print("Press CTRL+C to stop")
print("Waiting for tags...\n")

while True:
	rdr.wait_for_tag()
	(err, tag_type) = rdr.request()
	if err:
		# No tag present
		continue

	(err, uid) = rdr.anticoll()
	if err:
		PrintERROR("Anticollision algorithm failed")
		continue

	(valid, last_access, salt, nonce_expected) = UIDLookup(uid)
	if not valid:
		PrintERROR("Tag with UID %s was not found in the database" % binascii.hexlify(bytes(uid)).decode())
		continue

	util.set_tag(uid)

	passwd = DerivePassword(uid, salt)

	(err, hmac_valid, points, nonce) = ReadPointsStructure(1, passwd)
	if err:
		PrintERROR("Reading points data structure failed")
		continue

	if nonce != nonce_expected:
		PrintERROR("Received invalid nonce %d from tag, database contained %d" % (nonce, nonce_expected))
		if args.reset:
			ResetPointsStructure(1, passwd)
		continue
	if not hmac_valid:
		PrintERROR("Received invalid HMAC from tag")
		if args.reset:
			ResetPointsStructure(1, passwd)
		continue

	# Received valid points counter from tag

	new_points = points
	current_date = datetime.now().date()
	if current_date > datetime.fromtimestamp(last_access).date():
		# The tag is eligible for new points
		delta_points = DeltaPointLookup()
		new_points += delta_points
		nonce += 1

		WritePointsStructure(1, passwd, new_points, nonce)
		UIDUpdate(uid, current_date, nonce)


	DisplayPoints(points, new_points)

	util.deauth()

	time.sleep(0.5)
