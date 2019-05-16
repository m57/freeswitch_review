#!/usr/bin/env python

import sys
import os

fs_folder 	= ""
files 		= []
VERSION		= 1.0

def banner():

	print "\n\t\t\033[1;32m__ FreeSWITCH Security Review v%s __\033[0m" % VERSION
	print ""
	print "    A simple FreeSWITCH security review script. Review the output carfully."
	print ""
	print "\t\t -- https://www.twitter.com/@_g0dmode --\n"


def usage():

	print "%s -c [path to freeswitch config folder]\n" % sys.argv[0]
	exit()

def analyse_config(c_dir):

	for dpath, dnames, fnames in os.walk(c_dir):
		for i, fname in enumerate([os.path.join(dpath, fname) for fname in fnames]):
			if fname.endswith(".xml") and "lang" not in fname and "example.xml" not in fname:
				files.append(fname)

	print "\033[1;32m__{ SIP TLS Settings }__\033[0m"
	print ""

	ports 	= []
	en	= []
	ver	= []

	for f in files:

		fh = open(f, "r")
		for line in fh.readlines():
			if "sip_tls" in line:
				ver.append(f +": " + line.strip())
			elif "tls_port" in line:
				ports.append(f + ": " +line.strip())
			elif "ssl_enable" in line:
				if "false" in line:
					en.append(f + ": " + "\033[1;31m%s\033[0m" % line.strip())
				elif "ssl_enable=true\"" in line:
					en.append(f + ": " + "\033[1;32m%s\033[0m" % line.strip())
				else:
					en.append(f + ": " + line.strip())
					
	print "\033[1;34m[ Enabled ]\033[0m"
	for l in en:
		print l

	print "\n\033[1;34m[ Version ]\033[0m"
	for l in ver:
		print l

	print "\n\033[1;34m[ Ports ]\033[0m"
	for l in ports:
		print l


	print ""						
	print "\033[1;32m__{ SIP RTP Encryption Settings }__\033[0m"
	print ""

	AEAD = False
	AES_NULL = False

	for f in files:

		fh = open(f, "r")
		for line in fh.readlines():
			if "AES_CM_128_NULL_AUTH" in line:
				AES_NULL = true

			if "AEAD" in line:
				AEAD = true

			if "rtp_secure_media" in line or "AES" in line or "AEAD" in line:
				print f + ": " + line.strip()

	print ""
	if not AEAD:
		print "\033[1;33m[?] AEAD suites were not seen to be in use."
	
	if AES_NULL:
		print "\033[1;31m[!] Cipher 'AES_CM_128_NULL_AUTH' was seen to be supported. This offers no encryption"

	print ""
				
if __name__ == "__main__":

	banner()

	if "-c" not in sys.argv:
		usage()
	
	fs_folder = sys.argv[sys.argv.index("-c")+1]

	analyse_config(fs_folder)
