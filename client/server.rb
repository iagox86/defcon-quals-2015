# This is more or less the server software used by the real game - I can't get
# it properly authenticate the key, though, even though I'm doing exactly what
# the server software does. Not sure if client bug or if it requires something
# strange, and it wasn't really worth the time to debug it. :)

require 'socket'

def hash_password(password, connection_id, mode)
  char_7 = connection_id[7].ord

  result = ""
  0.upto(4) do |i|
    edx = password[i].ord ^ connection_id[i + char_7 - (((char_7 * 0x55555556) >> 32) * 3) + mode].ord
    if(edx < 0x1f)
      edx += 0x20
    elsif(edx > 0x7F)
      edx = edx - 0x7E + 0x20
    end
    result << edx.chr
  end

  return result
end

s = TCPServer.new(17069)
c = s.accept()

key = ""
0.upto(14) do |i|
  key += (rand(0x7F - 0x20) + 0x20).chr
end

c.write("connection ID: " + key + "\n")
c.write("\n\n*** Welcome to the ACME data retrieval service ***\nwhat version is your client?\n")
version = c.recv(1024).chomp()

#if(c != "version 3.11.54")
#  c.puts("Sorry!")
#  c.close
#  exit
#end

c.write("hello...who is this?")
username = c.recv(1024).chomp()
c.write("\x0a")

puts("Username: #{username}")

c.write("enter user password\x0a")
password = c.recv(1024).chomp()

puts("Password: #{password}")

if(password == hash_password(username, key, 1))
  loop do
    c.puts("hello #{username}, what would you like to do?\n")

    command = c.recv(1024).chomp()
    puts("Command: #{command}")
    if(command == "list users")
      ['grumpy', 'mrvito', 'gynophage', 'selir', 'jymbolia', 'sirgoon', 'duchess', 'deadwood'].each do |user|
        c.puts("#{user}")
      end
    elsif(command == "print key")
      if(username == "grumpy")
        challenge = ""
        0.upto(4) do
          challenge = challenge + (rand(0x7f - 0x20) + 0x20).chr
        end
        c.write("challenge: " + challenge + "\n")
        sleep(0.1)
        c.write("answer?\n")
        sleep(0.1)
        proof = c.recv(1024).chomp

        if(proof == hash_password(challenge, key, 7))
          c.write("the key is: The only easy day was yesterday. 44564")
        else
          c.write("sorry!\n")
        end
      else
        c.puts("the key is not accessible from this account. your administrator has been notified.")
      end
    else
      c.puts("contact your company admin for help\n")
    end
  end
else
  c.puts("sorry")
  c.close()
end
