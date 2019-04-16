#!/usr/bin/python3

# Student name and No.: Zhang Yuqian 3035233565
# Student name and No.: Dai Songcheng 3035232652
# Development platform: Ubuntu 16.04
# Python version: python 3.6.7
# Version: 0.1


from tkinter import *
import sys
import socket
import select
import threading
import time
from operator import itemgetter

#
# Global variables
#
# username
# sockfd
#

joined = False
peer_list = []
username = ''
roomname = ''
sockfd = socket.socket()
keep_alive = False
msid = ''
join_msg = ''
my_backward_links = []
msgID = 0
my_socket_list = []
forward_link = ('','','')

#
# This is the hash function for generating a unique
# Hash ID for each peer.
# Source: http://www.cse.yorku.ca/~oz/hash.html
#
# Concatenate the peer's username, str(IP address), 
# and str(Port) to form a string that be the input 
# to this hash function
#
def sdbm_hash(instr):
    hash = 0
    for c in instr:
        hash = int(ord(c)) + (hash << 6) + (hash << 16) - hash
    return hash & 0xffffffffffffffff


#
# Auxiliary functions
#
class keep_alive_thread (threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        while True:     #run for every 20 seconds 
            time.sleep(20.0)

            send_join_msg()


def send_join_msg():
    global sockfd
    global join_msg
    sockfd.send(join_msg.encode("ascii"))
    # CmdWin.insert(1.0, "\nKept alive")

    try:
        respond = sockfd.recv(1024).decode("ascii")
    except socket.error as err:
        print("Recv errror:", err)

    if respond:
        CmdWin.insert(1.0, "\n"+respond)
        if respond[0] == 'M': # a list of group members in that group
            # should check whether msid changed
            global msid
            if respond.split(':')[1] != msid:
                # update msid
                msid = respond.split(':')[1]
            
                # update peer_list
                global peer_list
                try:
                    peer_list = respond.split("::")[0].split(':', 2)[2].split(':')
                except IndexError:
                    peer_list = []


class listen_to_udp_request(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        # Create a datagram socket
        udp_server_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
         
        # Bind to address and ip
        udp_server_index = peer_list.index(username)
        udp_server_address = peer_list[udp_server_index+1]
        udp_server_port = peer_list[udp_server_index+2]

        udp_server_socket.bind((udp_server_address, int(udp_server_port)))

        udp_buffer_size =  1024
        udp_respond =  "A::\r\n"

        # Listen for incoming datagrams
        while(True):
            try:
                udp_client_pair = udp_server_socket.recvfrom(udp_buffer_size)
            except socket.error as err:
                print("UDP recv errror:", err)

            if udp_client_pair:
                CmdWin.insert(1.0, "\n")
                udp_client_msg = udp_client_pair[0].decode("ascii")
                udp_client_ip = udp_client_pair[1]
                udp_client_name = udp_client_msg.split("::")[0].split(':')[2]

                CmdWin.insert(1.0, "\nReceived a poke from " + udp_client_name)
                MsgWin.insert(1.0, "\n~~~~[" + udp_client_name+ "]Poke~~~~")

                # Sending a UDP reply to client
                udp_server_socket.sendto(udp_respond.encode("ascii"), udp_client_ip)


class listen_to_tcp(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        tcp_server_socket = socket.socket()

        # read lock
        pList = peer_list
        # unlock

        tcp_server_index = pList.index(username)
        tcp_server_address = pList[tcp_server_index+1]
        tcp_server_port = pList[tcp_server_index+2]
        print(sys.argv)

        # bind
        tcp_server_socket.bind((tcp_server_address, int(sys.argv[3])))

        # listen
        tcp_server_socket.listen(5)

        # use select
        read_list = [tcp_server_socket]
        write_list = []

        while True:

            Rready, Wready, Eready = select.select(read_list, [], [], 1.0)

            # if has incoming activities
            if Rready:

                # for each socket in the READ ready list
                for fd in Rready:

                    # if the listening socket is ready
                    # that means a new connection request
                    # accept that new connection request
                    # add the new client connection to READ socket list
                    # add the new client connection to WRITE socket list
                    if fd==tcp_server_socket:
                        try:
                            new, who = fd.accept()
                        except socket.error as err:
                            print("Socket accept error: ", err)

                        read_list.append(new)
                        write_list.append(new)


                    # else is a client socket being ready
                    # that means a message is waiting or
                    # a connection is broken
                    # if a new message arrived, send to everybody
                    # except the sender
                    # if broken connection, remove that socket from READ
                    # and WRITE lists
                    else:
                        try:
                            message = fd.recv(1024)
                        except socket.error as err:
                            print("Recv error: ", err)

                        if message:
                            # if a hand-shaking request
                            if message.decode("ascii").split(':')[0] == 'P':
                                peer_name = message.decode("ascii").split(':')[2]

                                if is_room_mate(peer_name) and peer_name != forward_link[0]:
                                    msg = "S:"+str(msgID)+"::\r\n"
                                    try:
                                        fd.send(msg.encode("ascii"))
                                    except socket.error as err:
                                        print("Sending error:", err)
                                    else:
                                        my_backward_links.append(peer_name)
                                        CmdWin.insert(1.0, "\n"+peer_name+" connected to me.")
                                else:
                                    fd.close()
                                    print("Unknown person connect to me, so scared i closed the connection")

                        else:
                            print("A connection is broken")
                            read_list.remove(fd)
                            write_list.remove(fd)   
                            fd.close()                 


class forward_connect(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        global peer_list
        while True:

            # read lock
            pList = peer_list
            # unlock

            # check if the previous forward link is still in the chatroom
            if forward_link[0] not in pList:
                print("my forward_link exited, find another one")
                connect(pList)

            time.sleep(5.0)

def is_room_mate(peer_name):
    global peer_list

    # lock read
    pList = peer_list
    # unlock

    if peer_name in pList:
        return True
    else:
        send_join_msg()

        # lock read
        pList = peer_name
        # unlock

        return peer_name in pList


def connect(pList) :
    connected = False

    while not connected:

        global peer_list

        # lock read
        pList = peer_list
        # unlock

        # get my info
        my_index = pList.index(username)
        my_add = pList[my_index+1]
        my_port = pList[my_index+2]
        my_hash = sdbm_hash(username+my_add+my_port)

        gList = [(a,a+b+c) for a,b,c in zip(pList[0::3], pList[1::3], pList[2::3])]
        gList = [(i,sdbm_hash(j)) for (i,j) in gList]

        # gList = [(name, hash)]
        gList = sorted(gList, key=itemgetter(1))

        start = (gList.index((username,my_hash))+1)%len(gList)


        while gList[start][1] != my_hash:
            if gList[start][0] in my_backward_links:
                start = (start+1) % len(gList)
            else:
                sockfl = socket.socket()

                # get peer information
                peer_name = gList[start][0]
                peer_index = pList.index(peer_name)
                peer_add = pList[peer_index+1]
                peer_port = pList[peer_index+2]

                # establish a TCP connection to this member 
                try:
                    sockfl.connect((peer_add, int(peer_port)))
                except socket.error as err:
                    # TCP connection failed
                    print("tcp connection failed", err)
                    start = (start+1) % len(gList)
                    continue

                print("The connection with ", sockfl.getpeername(), " has been established")

                # run peer-to-peer handshaking procedure
                global msgID
                hs_msg = "P:"+roomname+":"+username+":"+my_add+":"+my_port+":"+str(msgID)+"::\r\n"

                # send hand-shaking msg
                sockfl.send(hs_msg.encode("ascii"))

                print("Sent hand-shaking msg")
                time.sleep(2.0)

                # try to receive hand-shaking reply
                try:
                    message = sockfl.recv(1024)
                except socket.error as err:
                    print("Recv error: ", err) 

                print("processing msg")
                    
                if message:
                    if message.decode("ascii").split(":")[0]=='S':
                        connected = True

                        global forward_link
                        forward_link = (peer_name, peer_add, peer_port)

                        my_socket_list.append(sockfl)

                        CmdWin.insert(1.0, "\n"+"Successfully linked to the group - via "+peer_name)

                        # update gList to indicate this link
                        return None
                else:
                    CmdWin.insert(1.0, "\nBad message from my forward")

                # hand-shaking procedure not successful
                start = (start+1) % len(gList)

        print("reschedule connection later")
        time.sleep(20.0)



#
# Functions to handle user input
#

def do_User():   #only available before join
    global joined
    CmdWin.insert(1.0, "\n")
    if joined:
        CmdWin.insert(1.0, "\nCannot change username after JOINED")
    else:
        if userentry.get():
            global username
            username = userentry.get()
            outstr = "\n[User] username: " + username
            CmdWin.insert(1.0, outstr)
            userentry.delete(0, END)
        else:
            CmdWin.insert(1.0, "\nPlease input user name")


def do_List():
    CmdWin.insert(1.0, "\n")
    msg = "L::\r\n"
    global sockfd
    try:
        sockfd.send(msg.encode("ascii"))
    except:
        sockfd.connect((sys.argv[1], int(sys.argv[2])))
        CmdWin.insert(1.0, "\nConnected to room server at "+ sys.argv[1] + ":"+ sys.argv[2])
        sockfd.send(msg.encode("ascii"))

    try:
        respond = sockfd.recv(50).decode("ascii")
    except socket.error as err:
        print("Recv errror:", err)

    if respond:
        if respond[:3] == "G::":
            CmdWin.insert(1.0, "\nNo active chatrooms")
        elif respond[:2] == "G:":
            room_list = respond.split("::")[0].split(':')[1:]
            for r in room_list:
                CmdWin.insert(1.0, "\n\t"+r)
            CmdWin.insert(1.0, "\nHere are the active chatrooms:")

        else:
            CmdWin.insert(1.0, "\nError: "+respond.split(':')[1])


def do_Join():
    CmdWin.insert(1.0, "\n")
    global joined, roomname
    if joined:
        CmdWin.insert(1.0, "\nAlready in chatroom: "+roomname+". Cannot JOIN again")
    else:
        if not username:
            CmdWin.insert(1.0, "\nPlease input user name")
        else: # username is ready
            roomname = userentry.get()
            if not roomname:
                CmdWin.insert(1.0, "\nPlease input room name")
            else: # room name is entered in the entry box
                userentry.delete(0, END)

                global sockfd
                # get the IP address, & listening port of the requesting peer
                (add, port) = sockfd.getsockname()
                if add == '0.0.0.0': # TCP connection is not established
                    sockfd.connect((sys.argv[1], int(sys.argv[2])))
                    CmdWin.insert(1.0, "\nConnected to room server")
                    (add, port) = sockfd.getsockname()  

                # send the joining request
                global join_msg
                join_msg = "J:"+roomname+":"+username+":"+add+":"+sys.argv[3]+"::\r\n"
                sockfd.send(join_msg.encode("ascii"))

                try:
                    respond = sockfd.recv(1024).decode("ascii")
                except socket.error as err:
                    print("Recv errror:", err)

                if respond:
                    CmdWin.insert(1.0, "\n"+respond)
                    if respond[0] == 'M': # a list of group members in that group
                        # update peer_list
                        global peer_list
                        try:
                            peer_list = respond.split("::")[0].split(':', 2)[2].split(':')
                            print(peer_list)
                        except IndexError:
                            peer_list = []

                        # update msid
                        global msid
                        msid = respond.split("::")[0].split(':')[1]

                        
                        # global keep_alive

                        # if joined == False:
                        #     keep_alive = True
                        # else:
                        #     keep_alive = False

                        joined = True

                        # if keep_alive:
                        my_keep_alive_thread = keep_alive_thread()
                        my_keep_alive_thread.start()

                        # start listening to UDP requests
                        my_listen_thread = listen_to_udp_request()
                        my_listen_thread.start()

                        # connect to a peer
                        my_forward_connect_thread = forward_connect()
                        my_forward_connect_thread.start()

                        # listening to TCP connections
                        my_tcp_listen_thread = listen_to_tcp()
                        my_tcp_listen_thread.start()



                    #elif respond[0] == 'F': # encounters error, e.g. already joined another chatroom



def do_Send():
    CmdWin.insert(1.0, "\nPress Send")


def do_Poke():
    global joined, roomname
    CmdWin.insert(1.0, "\n")
    
    if not joined:
        CmdWin.insert(1.0, "\nError: Please join a chatroom before poke!")
    else:
        nickname_list = peer_list[0::3]
        peer = userentry.get()
        if peer:        # the peer name is provided 
            if peer== username:     # if input self's name 
                CmdWin.insert(1.0, "\nError: Cannot poke self!")
            elif peer not in nickname_list:     # peer not in this room
                CmdWin.insert(1.0, "\nError:"+peer +" is not in this chatroom!")
            else: # find peer
                peer_index = peer_list.index(peer)
                peer_address = peer_list[peer_index+1]
                peer_port = peer_list[peer_index+2]
                poke_msg = "K:"+roomname+":"+username+"::\r\n"

                sockpk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP socket

                sockpk.sendto(poke_msg.encode("ascii"), (peer_address, int(peer_port)))
                CmdWin.insert(1.0, "\nHave sent a poke to "+peer)
                userentry.delete(0, END)

                sockpk.settimeout(2)    # settimeout for 2 seconds for receiving
                try:
                    upd_server_respond = sockpk.recv(1024).decode("ascii")
                    CmdWin.insert(1.0, "\nReceived ACK from "+ peer)
                except socket.timeout as e:
                    CmdWin.insert(1.0, "\nNo ACK received, time out!")

        else:       # the peer name is not provided, print all the members in the chatroom 
            CmdWin.insert(1.0, "\n" + ' '.join(nickname_list))
            CmdWin.insert(1.0, "\nTo whom do you want to send the poke?")


        
def do_Quit():
    CmdWin.insert(1.0, "\nPress Quit")

    try:
        my_keep_alive_thread.join()
    except:
        pass
    try:
        sockfd.close()
    except:
        pass

    sys.exit(0)


#
# Set up of Basic UI
#
win = Tk()
win.title("MyP2PChat")

#Top Frame for Message display
topframe = Frame(win, relief=RAISED, borderwidth=1)
topframe.pack(fill=BOTH, expand=True)
topscroll = Scrollbar(topframe)
MsgWin = Text(topframe, height='15', padx=5, pady=5, fg="red", exportselection=0, insertofftime=0)
MsgWin.pack(side=LEFT, fill=BOTH, expand=True)
topscroll.pack(side=RIGHT, fill=Y, expand=True)
MsgWin.config(yscrollcommand=topscroll.set)
topscroll.config(command=MsgWin.yview)

#Top Middle Frame for buttons
topmidframe = Frame(win, relief=RAISED, borderwidth=1)
topmidframe.pack(fill=X, expand=True)
Butt01 = Button(topmidframe, width='6', relief=RAISED, text="User", command=do_User)
Butt01.pack(side=LEFT, padx=8, pady=8);
Butt02 = Button(topmidframe, width='6', relief=RAISED, text="List", command=do_List)
Butt02.pack(side=LEFT, padx=8, pady=8);
Butt03 = Button(topmidframe, width='6', relief=RAISED, text="Join", command=do_Join)
Butt03.pack(side=LEFT, padx=8, pady=8);
Butt04 = Button(topmidframe, width='6', relief=RAISED, text="Send", command=do_Send)
Butt04.pack(side=LEFT, padx=8, pady=8);
Butt06 = Button(topmidframe, width='6', relief=RAISED, text="Poke", command=do_Poke)
Butt06.pack(side=LEFT, padx=8, pady=8);
Butt05 = Button(topmidframe, width='6', relief=RAISED, text="Quit", command=do_Quit)
Butt05.pack(side=LEFT, padx=8, pady=8);

#Lower Middle Frame for User input
lowmidframe = Frame(win, relief=RAISED, borderwidth=1)
lowmidframe.pack(fill=X, expand=True)
userentry = Entry(lowmidframe, fg="blue")
userentry.pack(fill=X, padx=4, pady=4, expand=True)

#Bottom Frame for displaying action info
bottframe = Frame(win, relief=RAISED, borderwidth=1)
bottframe.pack(fill=BOTH, expand=True)
bottscroll = Scrollbar(bottframe)
CmdWin = Text(bottframe, height='15', padx=5, pady=5, exportselection=0, insertofftime=0)
CmdWin.pack(side=LEFT, fill=BOTH, expand=True)
bottscroll.pack(side=RIGHT, fill=Y, expand=True)
CmdWin.config(yscrollcommand=bottscroll.set)
bottscroll.config(command=CmdWin.yview)

def main():
    if len(sys.argv) != 4:
        print("P2PChat.py <server address> <server port no.> <my port no.>")
        sys.exit(2)

    win.mainloop()

if __name__ == "__main__":
    main()

