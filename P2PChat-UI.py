#!/usr/bin/python3

# Student name and No.:
# Student name and No.:
# Development platform:
# Python version:
# Version:


from tkinter import *
import sys
import socket
import select
import threading
import time

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
def print_time( threadName, delay):
   count = 0
   while count < 5:
      time.sleep(delay)
      count += 1
      print ("%s: %s" % ( threadName, time.ctime(time.time()) ))

class keep_alive_thread (threading.Thread):
	def __init__(self, msg):
		threading.Thread.__init__(self)
		self.msg = msg
	def run(self):
		while True:
			time.sleep(20.0)
			global sockfd
			sockfd.send(self.msg.encode("ascii"))
			# CmdWin.insert(1.0, "\nKept alive")


			try:
				respond = sockfd.recv(1024).decode("ascii")
			except socket.error as err:
				print("Recv errror:", err)

			if respond:
				CmdWin.insert(1.0, "\n"+respond)
				if respond[0] == 'M': # a list of group members in that group
					# should check whether msid changed
					
					# update peer_list
					global peer_list
					try:
						peer_list = respond.split("::")[0].split(':', 3)[2].split(':')
					except IndexError:
						peer_list = []

					# update msid
					global msid
					msid = respond.split("::")[0].split(':')[1]




#
# Functions to handle user input
#

def do_User():
	#only available before join

	if not joined:
		if userentry.get():
			global username
			username = userentry.get()
			outstr = "\n[User] username: " + username
			CmdWin.insert(1.0, outstr)
			userentry.delete(0, END)
		else:
			CmdWin.insert(1.0, "\nPlease input user name")




def do_List():
	msg = "L::\r\n"
	global sockfd
	try:
		sockfd.send(msg.encode("ascii"))
	except:
		sockfd.connect((sys.argv[1], int(sys.argv[2])))
		CmdWin.insert(1.0, "\nConnected to room server")
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
			for room_name in room_list:
				CmdWin.insert(1.0, "\n\t"+room_name)
			CmdWin.insert(1.0, "\nHere are the active chatrooms:")

		else:
			CmdWin.insert(1.0, "\nError: "+respond.split(':')[1])


def do_Join():
	if not username:
		CmdWin.insert(1.0, "\nPlease input user name")
	else: # username is ready
		global roomname
		roomname = userentry.get()
		if not roomname:
			CmdWin.insert(1.0, "\nPlease input room name")
		else: # room name is entered in the entry box
			userentry.delete(0, END)

			global sockfd
			# try:
			# 	(add, port) = sockfd.getsockname()
			# except:
			# 	sockfd = socket.socket()
			# 	try:
			# 		sockfd.connect((sys.argv[1], int(sys.argv[2])))
			# 	except socket.error as err:
			# 		print("Connection error: ", err)
			# 	else:
			# 		CmdWin.insert(1.0, "\nConnected to room server")
			# 		(add, port) = sockfd.getsockname()

			(add, port) = sockfd.getsockname()
			if add == '0.0.0.0': # TCP connection is not established
				sockfd.connect((sys.argv[1], int(sys.argv[2])))
				CmdWin.insert(1.0, "\nConnected to room server")

			(add, port) = sockfd.getsockname()	

			msg = "J:"+roomname+":"+username+":"+add+":"+str(port)+"::\r\n"

			sockfd.send(msg.encode("ascii"))

			# try:
			# 	sockfd.send(msg.encode("ascii"))
			# except: #  TCP connection has not been established
			# 	sockfd.connect((sys.argv[1], int(sys.argv[2])))
			# 	CmdWin.insert(1.0, "\nConnected to room server")
			# 	sockfd.send(msg.encode("ascii"))


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
						peer_list = respond.split("::")[0].split(':', 3)[2].split(':')
					except IndexError:
						peer_list = []

					# update msid
					global msid
					msid = respond.split("::")[0].split(':')[1]

					
					global joined
					global keep_alive

					if joined == False:
						keep_alive = True
					else:
						keep_alive = False

					joined = True

					if keep_alive:
						my_keep_alive_thread = keep_alive_thread(msg)
						my_keep_alive_thread.start()



				#elif respond[0] == 'F': # encounters error, e.g. already joined another chatroom



def do_Send():
	CmdWin.insert(1.0, "\nPress Send")


def do_Poke():
	global joined
	try:
		joined
	except NameError:
		joined = False
	
	if joined:
		peer = userentry.get()
		try:
			peer
		except NameError: # nickname not provided
			for i in range(0, len(peer_list)):
				CmdWin.insert(1.0, "\n")
				if i%3 == 0:
					CmdWin.insert(1.0, peer_list[i]+"  ")

			CmdWin.insert(1.0, "\nWho do you want to send the poke?")
		else: # nickname is provided
			match = False
			print(peer_list)
			for i in range(0, len(peer_list)):
				if i%3 == 0:
					if peer_list[i] == peer:
						match = True
						peer_add = peer_list[i+1]
						peer_port = int(peer_list[i+2])

			if match:
				sockpk = socket.socket()
				msg = "K:"+roomname+":"+username+"::\r\n"
				sockpk.sendto(bytes(msg, "utf-8"), (peer_add, peer_port))
				CmdWin.insert(1.0, "\nHave sent a poke to "+peer)

				sockpk.listen(5)
				readList = [sockpk]
				Rready, Wready, Eready = select.select(readList, [], [], 2.0)
				if Rready:
					for fd in Rready:
						if fd == sockpk:
							try:
								new, who = fd.accept()
							except socket.error as err:
								print("Socket accept error: ", err)	
							else:
								data, addr = fd.recvfrom(1024)
								#print ack
				else:
					CmdWin.insert(1.0, "\nNo ACK received")
				sockpk.close()

			else: # nickname is not a member of the chatroom network or is self
				CmdWin.insert(1.0, "\nWrong nickname")

	CmdWin.insert(1.0, "\nPress Poke")


def do_Quit():
	CmdWin.insert(1.0, "\nPress Quit")
	try:
		sockfd.close()
	except:
		sys.exit(0)

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

