#!/usr/bin/ruby

def banned(i)
  puts(i.chr)
end

0.upto(255) do |i|
  if(i - 0x26 == 1 || i - 0x26 == 0)
    banned(i)
  elsif(i == '|'.ord)
    banned(i)
  elsif(i == '*'.ord)
    banned(i)
  elsif((i & 0xFFFFFFFD) == '!'.ord)
    banned(i)
  elsif((i - 0x3A) == 1 || (i - 0x3A) == 0)
    banned(i)
  end
end
