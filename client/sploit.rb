require 'socket'


# mode = 1 for passwords, 7 for keys
def hash_password(password, connection_id, mode)
# mov     eax, [ebp+password]
  eax = password

# mov     [ebp+var_2C], eax
  var_2c = eax

# mov     eax, [ebp+buffer]
  eax = ""

# mov     [ebp+var_30], eax
  var_30 = ""

# xor     eax, eax
  eax = 0

# mov     ecx, ds:g_connection_id_plus_7 ; 0x0000007d, but changes
  ecx = connection_id[7]
  #puts('%x' % ecx.ord)

# mov     edx, 55555556h
  edx = 0x55555556
# mov     eax, ecx
  eax = ecx
# imul    edx
  #puts("imul")
  #puts("%x" % eax.ord)
  #puts("%x" % edx)
  edx = ((eax.ord * edx) >> 32)
  #puts("%x" % edx)
# mov     eax, ecx
  eax = ecx
# sar     eax, 1Fh
  #puts("sar")
  #puts("%x" % eax.ord)
  eax = eax.ord >> 0x1F
  #puts("%x" % eax)
# mov     ebx, edx
  ebx = edx
# sub     ebx, eax
  ebx -= eax
  #puts("sub")
  #puts("%x" % ebx)
# mov     eax, ebx
  eax = ebx
# mov     [ebp+var_18], eax
  var_18 = eax
# mov     edx, [ebp+var_18]
  edx = var_18
# mov     eax, edx
  eax = edx
# add     eax, eax
  eax = eax * 2
# add     eax, edx
  eax = eax + edx

  #puts("")
  #puts("%x" % eax)
# mov     edx, ecx
  edx = ecx
# sub     edx, eax
  #puts()
  #puts("%x" % ecx.ord)
  #puts("%x" % edx.ord)
  edx = edx.ord - eax
  #puts("%x" % edx)
# mov     eax, edx
  eax = edx
# mov     [ebp+var_18], eax
  var_18 = eax
  #puts()
  #puts("%x" % var_18)
# mov     eax, dword_804B04C
  eax = mode
# add     [ebp+var_18], eax
  var_18 += eax
  #puts("%x" % eax)
# mov     edx, offset g_connection_id ; <--
  edx = connection_id
# mov     eax, [ebp+var_18]
  eax = var_18
# add     eax, edx
# mov     dword ptr [esp+8], 5 ; n
# mov     [esp+4], eax    ; src
# lea     eax, [ebp+dest]
# mov     [esp], eax      ; dest
# call    _strncpy
  dest = connection_id[var_18, 5]
  #puts(dest)
# mov     [ebp+var_1C], 0
  var_1c = 0

# jmp     short loc_8048F4A
# loc_8048F2A:                            ; CODE XREF: do_password+A3j
  0.upto(4) do |var_1c|
#   mov     eax, [ebp+var_1C]
    eax = var_1c
#   add     eax, [ebp+var_30]
    # XXX
#   lea     edx, [ebp+dest]
    edx = dest

#   add     edx, [ebp+var_1C]
#   movzx   ecx, byte ptr [edx]
    ecx = edx[var_1c]
#   mov     edx, [ebp+var_1C]
    edx = var_1c

#   add     edx, [ebp+var_2C]
#   movzx   edx, byte ptr [edx]
    edx = var_2c[var_1c]

#   xor     edx, ecx
    edx = edx.ord ^ ecx.ord
#   mov     [eax], dl
    edx &= 0x0FF
    #puts("before edx = %x" % edx)
    if(edx < 0x1f)
      #puts("a")
      edx += 0x20
    elsif(edx > 0x7F)
      edx = edx - 0x7E + 0x20
    end
    #puts("after edx = %x" % edx)
    var_30[var_1c] = (edx & 0x0FF).chr

#   add     [ebp+var_1C], 1
#
#   loc_8048F4A:                            ; CODE XREF: do_password+7Dj
#   cmp     [ebp+var_1C], 4
#   jle     short loc_8048F2A
  end

  #puts()

  return var_30
end

def hash_password_phase2(password, connection_id, mode)
  eax = password
  var_2c = eax
  eax = ""
  var_30 = ""
  eax = 0
  ecx = connection_id[7]
  edx = 0x55555556
  eax = ecx
  edx = ((eax.ord * edx) >> 32)
  eax = ecx
  eax = eax.ord >> 0x1F
  ebx = edx
  ebx -= eax
  eax = ebx
  var_18 = eax
  edx = var_18
  eax = edx
  eax = eax * 2
  eax = eax + edx

  edx = ecx
  edx = edx.ord - eax
  eax = edx
  var_18 = eax
  eax = mode
  var_18 += eax
  edx = connection_id
  eax = var_18
  dest = connection_id[var_18, 5]
  var_1c = 0

  0.upto(4) do |var_1c|
    eax = var_1c
    edx = dest
    ecx = edx[var_1c]
    edx = var_1c
    edx = var_2c[var_1c]
    edx = edx.ord ^ ecx.ord
    edx &= 0x0FF
    if(edx < 0x1f)
      edx += 0x20
    elsif(edx > 0x7F)
      edx = edx - 0x7E + 0x20
    end
    var_30[var_1c] = (edx & 0x0FF).chr
  end

  return var_30
end

def hash_password_phase3(password, connection_id, mode)
  ecx = connection_id[7]
  eax = ecx
  edx = ((eax.ord * 0x55555556) >> 32)
  eax = ecx
  eax = eax.ord >> 0x1F
  eax = ((edx - (eax.ord >> 0x1F)) * 2) + edx

  edx = ecx
  edx = edx.ord - eax
  eax = edx
  var_18 = eax
  var_18 += mode
  edx = connection_id
  eax = var_18
  dest = connection_id[var_18, 5]

  result = ""
  0.upto(4) do |i|
    eax = i
    edx = dest
    ecx = edx[i]
    edx = password[i]
    edx = edx.ord ^ ecx.ord
    edx &= 0x0FF
    if(edx < 0x1f)
      edx += 0x20
    elsif(edx > 0x7F)
      edx = edx - 0x7E + 0x20
    end
    result << (edx & 0x0FF).chr
  end

  return result
end

def hash_password_phase4(password, connection_id, mode)
  char_7 = connection_id[7].ord
  edx = ((char_7 * 0x55555556) >> 32)
  eax = ((edx - (char_7 >> 0x1F >> 0x1F)) * 2) + edx

  result = ""
  0.upto(4) do |i|
    edx = (password[i].ord ^ connection_id[char_7 - eax + mode + i].ord) & 0xFF

    if(edx < 0x1f)
      edx += 0x20
    elsif(edx > 0x7F)
      edx = edx - 0x7E + 0x20
    end
    result << (edx & 0x0FF).chr
  end

  return result
end

def hash_password_phase5(password, connection_id, mode)
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

def read_line(s)
  line = s.gets()

  puts(line)

  return line
end

s = TCPSocket.new("127.0.0.1", 17069)
id = read_line(s)
id = id.split(/ /, 2)[2]
puts(id)

USER = "duchess"
password = hash_password(USER, id, 1)

read_line(s) # blank line
read_line(s) # blank line
read_line(s) # welcome
read_line(s) # version
s.write("version 3.11.54\n")
read_line(s)
s.write(USER + "\n")
read_line(s)
s.write(password + "\n")
read_line(s)
s.write("print key\n")
challenge = read_line(s)
read_line(s)
puts("A: " + challenge)
challenge = challenge.split(/ /, 2)[1]
puts("B: " + challenge)
puts(challenge)

answer = hash_password(challenge, id, 7)
puts(answer)
s.write(answer + "\n")
read_line(s)
read_line(s)
read_line(s)


