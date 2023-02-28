ct = 'wxqvn$Zae${deyZv$d"i'

sub = {'01': '01', '11':'10', '10':'11', '00':'00'}

bin_ct = ''
for c in ct:
    bin_ct += bin(ord(c))[2:].zfill(8)

bin_pt = ''
for i in range(0, len(bin_ct), 2):
    bin_pt += sub[bin_ct[i:i+2]]

pt = ''
for i in range(0, len(bin_pt), 8):
    pt += chr(int(bin_pt[i:i+8], 2))
print(pt)
