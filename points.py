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

# Sections where the points data structure should be redundantly stored
REDUNDANT_SECTIONS = [1, 2, 3]

# Where to retrieve the secret HMAC key for authenticating the tag's points
HMAC_KEY_PATH = "hmac.key"
hmac_key = None

# How many times to attempt writing to tag before giving up
MAX_WRITE_ATTEMPTS = 5

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
	db = xml.dom.minidom.parse("db.xml")
	root = db.documentElement

	return int(db.documentElement.getElementsByTagName("DeltaPoint")[0].getAttribute("Value"))

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
		PrintERROR("Bad key length %d" % len(new_key))
		return True
	util.auth(rdr.auth_a, old_key)
	util.do_auth(util.block_addr(sect, 3))
	return util.rewrite(sect * 4 + 3, new_key + [None, None, None, None, None, None, None, None, None, None])

# Reads all redundant points strucutres and returns any strucutre that was valid
# or returns an error if none was valid. If mutliple strucutres were valid, the
# first valid one will be returned. This is because it is liklier to be up-to-date
# as structures are written from first to last in WritePointsStructure()
def ReadPointsStructure(sections, key):
	for section in sections:
		(err, data) = ReadBlock(key, section, 0)
		if err:
			PrintERROR("Failed to read section %d block 0" % section)
			return (err, False, None, None)

		(points, nonce, rsrv) = struct.unpack("<IQI", bytes(data))

		(err, data) = ReadBlock(key, section, 1)
		if err:
			PrintERROR("Failed to read section %d block 1" % section)
			return (err, False, None, None)
		hmac = bytes(data)

		(err, data) = ReadBlock(key, section, 2)
		if err:
			PrintERROR("Failed to read section %d block 2" % section)
			return (err, False, None, None)
		hmac += bytes(data)

		if not HmacVerify(points, nonce, hmac):
			PrintINFO("Section %d did not contain a valid HMAC" % section)
			continue

		PrintDEBUG("Section %d contained valid points strucutre" % section)
		return (False, True, points, nonce)

	return (False, False, None, None)

# Writes updated points structures to all redundant sections
def WritePointsStructure(sections, key, points, nonce):
	# TODO Figure out what should be written as reserved bytes
	rsrv = 0
	hmac = HmacGenerate(points, nonce)
	data = [list(struct.pack("<IQI", points, nonce, rsrv)), list(hmac[:16]), list(hmac[16:])]

	for section in sections:
		for block in range(3):
			err = WriteBlock(key, section, block, data[block])
			if err:
				PrintERROR("Failed to write to section %d block %d" % (section, block))
				return err

	return False

def ResetPointsStructure(sections, key):
	err = WritePointsStructure(sections, key, 0, 0)
	if not err:
		UIDUpdate(uid, datetime.now().date(), 0)

def DerivePassword(uid, salt):
	salted_uid = (binascii.hexlify(bytes(uid)).decode().lower() + str(salt)).encode()
	PrintDEBUG("Creating new Key A as digest of %s" % salted_uid)

	gen_hmac = hmac.new(hmac_key, salted_uid, hashlib.sha256).digest()
	gen_hmac = list(gen_hmac)[-6:]

	PrintDEBUG("Final Key A is %s" % gen_hmac)
	return gen_hmac

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
parser.add_argument('-r', '--reset', action='store_true',
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
	print("\tWARNING: Running in set password mode!")
	print("\tTags with password %s (hex) will have their password OVERWRITTEN by the password derived by its UID!" % args.setpass)
print("Press CTRL+C to stop")
print("Waiting for tags...\n")

start_time = 0
end_time = 0

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

	start_time = time.time()
	(valid, last_access, salt, nonce_expected) = UIDLookup(uid)
	if not valid:
		PrintERROR("Tag with UID %s was not found in the database" % binascii.hexlify(bytes(uid)).decode())
		time.sleep(0.5)
		continue

	util.set_tag(uid)

	passwd = DerivePassword(uid, salt)

	if args.setpass is not None:
		for section in REDUNDANT_SECTIONS:
			err = WriteKeyA(old_passwd, section, passwd)
			if err:
				PrintERROR("Failed to write key A to section %d" % section)
			else:
				PrintINFO("Key A of section %d was updated" % section)

		time.sleep(2)
		continue

	(err, hmac_valid, points, nonce) = ReadPointsStructure(REDUNDANT_SECTIONS, passwd)
	if err:
		PrintERROR("Reading points data structure failed")
		continue

	if not hmac_valid:
		PrintERROR("Received invalid HMAC from tag")
		if args.reset:
			PrintINFO("Reseting the points structure...")
			ResetPointsStructure(REDUNDANT_SECTIONS, passwd)
		continue
	if nonce != nonce_expected:
		PrintERROR("Received invalid nonce %d from tag, database contained %d" % (nonce, nonce_expected))
		if args.reset:
			PrintINFO("Reseting the points structure...")
			ResetPointsStructure(REDUNDANT_SECTIONS, passwd)
		continue

	# Received valid points structure from tag
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
		err = True
		attempt = 0
		while err and attempt < MAX_WRITE_ATTEMPTS:
			err = WritePointsStructure(REDUNDANT_SECTIONS, passwd, new_points, nonce)
			attempt += 1

		if attempt >= MAX_WRITE_ATTEMPTS:
			PrintERROR("Falied to write points! Data on the tag may be corrupted.")
			new_points = points
		else:
			UIDUpdate(uid, current_date, nonce)

	DisplayPoints(points, new_points)
	end_time = time.time()
	#print("%f" % (end_time - start_time))

	util.deauth()

	time.sleep(0.5)
