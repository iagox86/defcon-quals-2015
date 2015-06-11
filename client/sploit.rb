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

def read_until(s, str)
  line = ""

  while(line !~ /#{str}/m)
    line += s.recv(1000)
  end

  puts("Received: #{line.gsub("\n", "\\n")}")

  return line
end

def read_line(s)
  line = ""

  while(line !~ /\n$/m)
    line += s.recv(1)
  end

  return line
end

s = TCPSocket.new("127.0.0.1", 17069)
id = read_line(s)
id = id.split(/ /, 3)[2]
puts("Connection id: " + id)

USER = "duchess"
PASS = hash_password(USER, id, 1)

read_until(s, "client?")
s.write("version 3.11.54\n")

read_until(s, "who is this?")
s.write(USER + "\n")
read_until(s, "user password")
s.write(PASS + "\n")

read_until(s, "like to do")
s.write("print key\n")

challenge = read_until(s, "challenge: ").split(/ /, 2)[1]
puts("Challenge: " + challenge)

answer = hash_password(challenge, id, 7)
puts("Answer: " + answer)
s.write(answer + "\n")

puts(read_until(s, "the key is"))

