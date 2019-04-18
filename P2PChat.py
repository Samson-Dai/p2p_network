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
import copy
from operator import itemgetter

#
# Global variables
#
#

## informatic variables 
peer_list = []
username = ''
roomname = ''
msid = ''
join_msg = ''
my_backward_links = []
msgID = 0   # ID of last received message
last_message = "" # content of last message
forward_link = ('','','')  #name, add, port
joined = False
keep_alive = False
connected = False


## sockets 
my_socket_list = []         # the list of sockets used by forward link and backward links, [(peer,socket)] 
socket_room_server = socket.socket()        #socket used to connect with room server
udp_server_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)    #tcp socket for POKE

## locks
lock_peer_list = threading.Lock() # lock for accessing peer_list
lock_messageID = threading.Lock() # lock for accessing msgID

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
# Auxiliary functions for multi- threading
#
class keep_alive_thread (threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        while True:     #run for every 20 seconds 
            time.sleep(20.0)
            send_join_msg()


class listen_to_udp_request(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        global peer_list, username, udp_server_socket
        
        # Bind to address and ip
        udp_server_index = peer_list.index(username)
        udp_server_address = peer_list[udp_server_index+1]
        udp_server_port = peer_list[udp_server_index+2]

        udp_server_socket.bind((udp_server_address, int(udp_server_port)))

        udp_buffer_size =  1024
        udp_respond =  "A::\r\n"

        # Listen for incoming datagrams
        while True:
            try:
                udp_client_pair = udp_server_socket.recvfrom(udp_buffer_size)
            except socket.error as err:
                print("UDP recv errror:", err)

            if udp_client_pair:
                CmdWin.insert(1.0, "\n")
                udp_client_msg = udp_client_pair[0].decode("ascii")
                udp_client_ip = udp_client_pair[1]
                udp_client_name = udp_client_msg.split("::")[0].split(':')[2]

                #display poke msg
                CmdWin.insert(1.0, "\nReceived a poke from " + udp_client_name)
                MsgWin.insert(1.0, "\n~~~~[" + udp_client_name+ "]Poke~~~~")

                # Sending a UDP ACK to client
                udp_server_socket.sendto(udp_respond.encode("ascii"), udp_client_ip)


class listen_to_tcp(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        global lock_peer_list, username, peer_list, roomname, receiving_message, msgID, lock_messageID, read_list

        with lock_peer_list:
            pList = copy.deepcopy(peer_list)

        tcp_server_socket = socket.socket()
        tcp_server_index = pList.index(username)
        tcp_server_address = pList[tcp_server_index+1]
        tcp_server_port = pList[tcp_server_index+2]

        # bind
        tcp_server_socket.bind((tcp_server_address, int(sys.argv[3])))

        # listen
        tcp_server_socket.listen(5)


        while True:
            read_list = [tcp_server_socket]
            for sock_tuple in my_socket_list:
                read_list.append(sock_tuple[0]) 
            #print("Read List: " + str(read_list))

            # use select to implement listening
            Rready, Wready, Eready = select.select(read_list, [], [], 1.0)

            # if has incoming activities
            if Rready:
                print("income event ready###############################################")

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

                        print("TCP Connection established ")
                        my_socket_list.append((new, who[1]))


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
                            if message.decode("ascii").split(':')[0] == 'P':
                            # if a hand-shaking request 

                                print("Receive handshaking msg " +message.decode("ascii") ) 
                                peer_name = message.decode("ascii").split(':')[2]

                                if is_room_mate(peer_name) and peer_name != forward_link[0]:
                                    # establish backward connection
                                    msg = "S:"+str(msgID)+"::\r\n"
                                    try:
                                        fd.send(msg.encode("ascii"))
                                    except socket.error as err:
                                        print("Sending error:", err)
                                    else:
                                        my_backward_links.append(peer_name)
                                        CmdWin.insert(1.0, "\n"+peer_name+" connected to me.")

                                    # add the backward link to my_link_list
                                    my_socket_list.append((fd, peer_name))


                                else:
                                    # unknow peer, remove connection
                                    read_list.remove(fd)
                                    fd.close()
                                    print("Unknown person connect to me, so scared i closed the connection")

                            elif message.decode("ascii").split(':')[0] == 'T':
                            # if a TEXT msg
                                print("in handle_receiving_message, the received message is", message.decode("ascii"))
                                rmsgs = message.decode('ascii').split(":")
                                text_roomname  =  rmsgs[1]
                                if text_roomname != roomname:   # not in the same chatroom
                                    CmdWin.insert(1.0, "\n Error: Received message not from this chatroom.")
                                else:
                                    sending_user = rmsgs[3]
                                    messageID_rcv = rmsgs[4]
                                    CmdWin.insert(1.0, "\nReceived message from " + sending_user)
                                    print("Received message from " + sending_user)

                                    if int(messageID_rcv) > msgID: # a new message incoming
                                        msg = extract_message(rmsgs)  # extracting the msg content 

                                        print("the message is" + msg)

                                        with lock_messageID:
                                            msgID = int(messageID_rcv)
                                            last_message = rmsgs

                                        #display msg
                                        MsgWin.insert(1.0, "\n[" + sending_user + "] " + msg)

                                        # relay the msg to my  peers
                                        send_msg(message.decode("ascii"))
                                            
                                    else:
                                        CmdWin.insert(1.0, "\nError: This message has been received before.")

                        else:
                            print("A connection is broken")
                            read_list.remove(fd)
                            fd.close()                 


class forward_connect(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        global peer_list, forward_link, lock_peer_list
        while True:
            with lock_peer_list:
                pList = copy.deepcopy(peer_list)

            # check if the previous forward link is still in the chatroom
            if forward_link[0] not in pList:
                print("my forward_link exited, find another one")
                connect()

            time.sleep(5.0)


#
# Auxiliary functions
#
def send_join_msg():
    global socket_room_server, join_msg
    socket_room_server.send(join_msg.encode("ascii"))
    # CmdWin.insert(1.0, "\nKept alive")

    try:
        respond = socket_room_server.recv(1024).decode("ascii")
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
                    update_socket_list()
                except IndexError:
                    peer_list = []

def update_socket_list():
    global my_socket_list, peer_list

    with lock_peer_list:
        pList = copy.deepcopy(peer_list)

    temp_socket_list = my_socket_list
    for socket_member in my_socket_list:
        if socket_member[1] not in pList:
            temp_socket_list.remove(socket_member)

    if forward_link[0] not in pList:    # try to reconnect if forward link quits
        connect()
    my_socket_list = temp_socket_list



def is_room_mate(peer_name):
    global peer_list

    with lock_peer_list:
        pList = copy.deepcopy(peer_list)
    
    if peer_name in pList:
        return True
    else:
        send_join_msg()
        with lock_peer_list:
            pList = copy.deepcopy(peer_list)

        return peer_name in pList


def connect() :
    global peer_list, my_backward_links, msgID, forward_link, connected
    connected = False
    send_join_msg()   # update peer list 

    while not connected:
        with lock_peer_list:
            pList = copy.deepcopy(peer_list)

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

                print("The connection with ", sockfl.getpeername(), " has been sent")
    
                # run peer-to-peer handshaking procedure
                hs_msg = "P:"+roomname+":"+username+":"+my_add+":"+my_port+":"+str(msgID)+"::\r\n"

                # send hand-shaking msg
                sockfl.send(hs_msg.encode("ascii"))

                print("Sent hand-shaking msg")
                time.sleep(2.0)

                message=''
                # try to receive hand-shaking reply
                try:
                    message = sockfl.recv(1024)
                except socket.error as err:
                    print("Recv error: ", err) 
                    
                if message:
                    if message.decode("ascii").split(":")[0]=='S':
                        connected = True

                        # update forward_link to indicate this link
                        forward_link = (peer_name, peer_add, peer_port)

                        # add forward link to my_socket_list
                        my_socket_list.append((sockfl, peer_name))

                        CmdWin.insert(1.0, "\n"+"Successfully linked to the group - via "+peer_name)
                        return None          #jump out of the function

                else:
                    print("cannot receive msg")

                # hand-shaking procedure not successful
                start = (start+1) % len(gList)

        # Cannot establish forward links now, reschedule  
        #print("reschedule connection later")
        time.sleep(10.0)


# send message to all connecting peers
def send_msg(msg):
    global my_socket_list

    send_list = my_socket_list
    CmdWin.insert(1.0, "\nRelay the message to other peers")
    for sock_tuple in send_list:
        sock = sock_tuple[0]
        try:
            sock.send(msg.encode('ascii'))
            print("Send message to " + str(sock.getpeername()))
            print(msg + '\n')
        except socket.error as err:
            print("Error in broadcasting message: ", err)
            CmdWin.insert(1.0, "\nError in broadcasting message out.")


# extracting received TEXT message (handling ':' problem)
def extract_message(msg):
    result = msg[6]
    if len(msg) - 2 > 6:
        for i in range(7, len(msg) - 2):
            result += ":" + msg[i]
    return result



#
# Functions to handle user input
#

def do_User():   #only available before join
    global joined, username
    CmdWin.insert(1.0, "\n")
    if joined:
        CmdWin.insert(1.0, "\nCannot change username after JOINED")
    else:
        if userentry.get():
            username = userentry.get()
            outstr = "\n[User] username: " + username
            CmdWin.insert(1.0, outstr)
            userentry.delete(0, END)
        else:
            CmdWin.insert(1.0, "\nPlease input user name")


def do_List():
    CmdWin.insert(1.0, "\n")
    msg = "L::\r\n"
    global socket_room_server
    try:
        socket_room_server.send(msg.encode("ascii"))
    except:
        socket_room_server.connect((sys.argv[1], int(sys.argv[2])))
        CmdWin.insert(1.0, "\nConnected to room server at "+ sys.argv[1] + ":"+ sys.argv[2])
        socket_room_server.send(msg.encode("ascii"))

    try:
        respond = socket_room_server.recv(50).decode("ascii")
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
    global joined, roomname, socket_room_server, join_msg, peer_list, msid, keep_alive
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
 
                # get the IP address, & listening port of the requesting peer
                (add, port) = socket_room_server.getsockname()
                if add == '0.0.0.0': # TCP connection is not established
                    socket_room_server.connect((sys.argv[1], int(sys.argv[2])))
                    CmdWin.insert(1.0, "\nConnected to room server")
                    (add, port) = socket_room_server.getsockname()  

                # send the joining request 
                join_msg = "J:"+roomname+":"+username+":"+add+":"+sys.argv[3]+"::\r\n"
                socket_room_server.send(join_msg.encode("ascii"))

                try:
                    respond = socket_room_server.recv(1024).decode("ascii")
                except socket.error as err:
                    print("Recv errror:", err)

                if respond:
                    CmdWin.insert(1.0, "\n"+respond)
                    if respond[0] == 'M': # a list of group members in that group
                        # update peer_list 
                        try:
                            peer_list = respond.split("::")[0].split(':', 2)[2].split(':')
                            print(peer_list)
                        except IndexError:
                            peer_list = []

                        # update msid
                        msid = respond.split("::")[0].split(':')[1]


                        joined = True

                        # if keep_alive:
                        my_keep_alive_thread = keep_alive_thread()
                        my_keep_alive_thread.setDaemon(True)
                        my_keep_alive_thread.start()

                        # start listening to UDP requests
                        my_listen_thread = listen_to_udp_request()
                        my_listen_thread.setDaemon(True)
                        my_listen_thread.start()

                        # connect to a peer
                        my_forward_connect_thread = forward_connect()
                        my_forward_connect_thread.setDaemon(True)
                        my_forward_connect_thread.start()

                        # listening to TCP connections
                        my_tcp_listen_thread = listen_to_tcp()
                        my_tcp_listen_thread.setDaemon(True)
                        my_tcp_listen_thread.start()


def do_Send():
    global roomname, username, joined, my_socket_list, msgID
    CmdWin.insert(1.0, "\n")

    msg_to_send = userentry.get()
    userentry.delete(0, END)
    # only take actions if there's input
    if msg_to_send:
        if not joined: # the user has not joined any chatroom yet
            CmdWin.insert(1.0, "\nNot in any chatroom yet. Join one first.")
        else:
            with lock_messageID:
                msgID += 1

            with lock_peer_list:
                pList = copy.deepcopy(peer_list)

            # get my info
            my_index = pList.index(username)
            my_add = pList[my_index+1]
            my_port = pList[my_index+2]
            my_hash = sdbm_hash(username+my_add+my_port)
            
            msgLength = len(msg_to_send)

            # forward the message together with msgID to every connecting peer
            smsg = "T:" + roomname + ":" + str(my_hash) + ":" + username + ":" + str(msgID) + ":" + str(msgLength) + ":" + msg_to_send + "::\r\n"

            print("number of sockets in socket_list: ", len(my_socket_list))
            send_msg(smsg)

            # display username and message content to MsgWin
            MsgWin.insert(1.0, "\n[" + username + "] " + msg_to_send)


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

                try:
                    sockpk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP send POKE socket
                    sockpk.sendto(poke_msg.encode("ascii"), (peer_address, int(peer_port)))
                except socket.error as err:
                    print("UDP send message error: ", err)
                    CmdWin.insert(1.0, "\nError in sending POKE. Please try again.")
                
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
    global  my_socket_list, socket_room_server, udp_server_socket

    # close sockets
    socket_room_server.close()
    udp_server_socket.close()
    for sock in my_socket_list:
        sock[0].close()

    CmdWin.insert(1.0, "\nPress Quit")
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

