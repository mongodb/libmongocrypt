help = """
Script to rewrite \n to \r\n
Usage: python3 rewrite.py file-in.txt file-out.txt
file-in.txt will be rewritten to have \n replaced with \r\n.
"""
import sys
if len(sys.argv) != 3:
    print (help)
    sys.exit(1)

src = open (sys.argv[1], "r")
dst = open (sys.argv[2], "w")
for line in src:
    print (line)
    dst.write(line.strip() + "\r\n")
dst.close()