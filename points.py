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

def PrintDEBUG(msg):
	if verbosity > 2:
		print("[DEBUG]: %s" % msg)

def PrintINFO(msg):
	if verbosity > 1:
		print("[INFO]: %s" % msg)

def PrintERROR(msg):
	if verbosity > 0:
		print("[ERROR]: %s" % msg)

from xml.dom.minidom import parse
import xml.dom.minidom

def DeltaPointLookup():
	# TODO Lookup the points to add in database
	return 1

def UIDLookup(uid):
	# TODO Lookup UID in database
	db = xml.dom.minidom.parse("db.xml")
	root = db.documentElement
	uid = binascii.hexlify(bytes(uid)).decode().lower()

	for tag in db.documentElement.getElementsByTagName("Tags")[0].getElementsByTagName("Tag"):
		if tag.getAttribute("UID").lower() == uid:
			return (True, int(tag.getAttribute("LastAccess")), int(tag.getAttribute("Salt")), int(tag.getAttribute("Nonce")))

	return (False, 0, 0, 0)

def UIDUpdate(uid, last_access, nonce):
	# TODO Update UID information in database
	db = xml.dom.minidom.parse("db.xml")
	root = db.documentElement
	uid = binascii.hexlify(bytes(uid)).decode().lower()

	for tag in db.documentElement.getElementsByTagName("Tags")[0].getElementsByTagName("Tag"):
		if tag.getAttribute("UID").lower() == uid:
			tag.setAttribute("LastAccess", str(int(time.mktime(last_access.timetuple()))))
			tag.setAttribute("Nonce", str(nonce))

	with open("db.xml", "w") as f:
		f.write(db.documentElement.toxml())

def HmacVerify(points, nonce, hmac):
	expected = HmacGenerate(points, nonce)
	PrintDEBUG("Got HMAC %s" % binascii.hexlify(hmac).decode())
	return expected == hmac

def HmacGenerate(points, nonce):
	gen_hmac = hmac.new(hmac_key, struct.pack("<IQ", points, nonce), hashlib.sha256).digest()
	PrintDEBUG("Generated HMAC %s for points %d and nonce %d" % (binascii.hexlify(gen_hmac).decode(), points, nonce))
	return gen_hmac

def ReadBlock(key, sect, block):
	util.auth(rdr.auth_a, key)
	util.do_auth(util.block_addr(sect, block))

	(err, data) = rdr.read(sect * 4 + block)
	return (err, data)

def WriteBlock(key, sect, block, data):
	util.auth(rdr.auth_a, key)
	util.do_auth(util.block_addr(sect, block))

	return rdr.write(sect * 4 + block, data)

def WriteKeyA(old_key, sect, new_key):
	if len(new_key) != 6:
		return True
	util.auth(rdr.auth_a, old_key)
	return util.rewrite(sect * 4 + 3, new_key + [None, None, None, None, None, None, None, None, None, None])

def ReadPointsStructure(section, key):
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

def WritePointsStructure(section, key, points, nonce):
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

def ResetPointsStructure(section, key):
	return WritePointsStructure(section, key, 0, 0)

def DerivePassword(uid, salt):
	# TODO Convert UID of tag into its KeyA field
	# TODO Test that password overwrite works beforehand
	return [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]

def DisplayPoints(points, new_points):
	# TODO Show points on display
	if points == new_points:
		print("[DISPLAY] You have %d point(s)" % points)
	else:
		print("[DISPLAY] You received %d point(s)!" % (new_points - points))
		print("[DISPLAY] You now have %d point(s)" % new_points)

def StopPoints(signal, frame):
	global running
	print("\nStopping points system...")
	running = False
	rdr.cleanup()
	sys.exit()

signal.signal(signal.SIGINT, StopPoints)

parser = argparse.ArgumentParser(prog=sys.argv[0], description='Reads and writes points to a MIFARE Classic RFID tag using the RC522 RFID reader')
parser.add_argument('-r', '--reset', type=bool, default=False,
                    help='Reset the points on the tag to 0 permanently if they are invalid.')
parser.add_argument('-p', '--setpass', type=str,
                    help='Start in password overwrite mode. The current password should be supplied as an argument, and it will be overwritten by the password derived from the UID')
parser.add_argument('-v', '--verbose', action='count', default=0,
                    help='The verbosity of prints to be shown.')

args = parser.parse_args(args=sys.argv[1:])

verbosity = args.verbose
util.debug = verbosity > 2

f = open(HMAC_KEY_PATH, "r")
hmac_key = binascii.unhexlify(f.read().strip())
f.close()

print("Points system started")
if args.setpass is not None:
	old_passwd = list(binascii.unhexlify(args.setpass))
	print("WARNING: Running in set password mode!")
	print("Tags with password %s (hex) will have their password OVERWRITTEN by the password derived by its UID!" % args.setpass)
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

	if args.setpass is not None:
		err = WriteKeyA(old_passwd, 1, passwd)
		if err:
			PrintERROR("Failed to write key A to section 1")
		else:
			PrintINFO("Key A of section 1 was updated")

		time.sleep(2)
		continue

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
	PrintDEBUG("Received valid points %d and nonce %d from tag" % (points, nonce))

	new_points = points
	current_date = datetime.now().date()
	last_access_date = datetime.fromtimestamp(last_access).date()
	PrintDEBUG("Last access time was %s, today's date is %s" % (last_access_date, current_date))
	if current_date > last_access_date:
		# The tag is eligible for new points
		delta_points = DeltaPointLookup()
		new_points += delta_points
		nonce += 1

		PrintINFO("Writing new points %d and nonce %d to tag" % (new_points, nonce))
		WritePointsStructure(1, passwd, new_points, nonce)
		UIDUpdate(uid, current_date, nonce)


	DisplayPoints(points, new_points)

	util.deauth()

	time.sleep(0.5)
