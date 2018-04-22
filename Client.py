from tkinter import *
from  tkinter.ttk import *
from Crypto.Cipher import DES
from Crypto.Hash import BLAKE2s
from Crypto import Random
#from twisted.internet import tksupport, reactor, address


import socket
import _thread


# need to add encryption methods, need some kind of log in feature.


class client(Frame):

        def __init__(self, root):
            Frame.__init__(self, root)
            self.root = root
            self.initUI()
            self.buffersize = 4096
            self.serverStatus = 0
            self.serverSoc = None
            self.allClients = {}
            self.counter = 0
            self.encrypted = 0

       #     self.preKey = passCode
        #    self.key = BLAKE2s.new(digest_bits=64,)
         #   self.key.update(bytes(passCode, encoding = 'utf-8'))
         #   self.eKey = self.key.digest()
         #   self.cipher = DES.new(self.eKey, DES.MODE_OFB)
         #   self.mode = DES.MODE_OFB
            # place holder for key, take passcode parameter and generate key here or in main.


    #initialize the User Interface
        def initUI(self):
            self.root.title("phase I p2p client")
            ScreenX = self.root.winfo_screenwidth()
            ScreenY = self.root.winfo_screenheight()
            self.Framex = 800
            self.Framey = 600
            Frame_pos_x = (ScreenX - self.Framex)/2
            Frame_pos_y = (ScreenY - self.Framey)/2
            self.root.geometry("%dx%d+%d+%d" % (self.Framex, self.Framey, Frame_pos_x, Frame_pos_y))
            self.root.resizable(width=False, height=False)

            paddingx = 10
            paddingy = 10
            parentFrame = Frame(self.root)
            parentFrame.grid(padx=paddingx, pady=paddingy, stick=E+W+N+S)

            igroup = Frame(parentFrame)
            serverLabel = Label(igroup, text="Set: ")
            self.passCode = StringVar()
            self.passCode.set("Password: ")
            passField = Entry(igroup, width=10, textvariable=self.passCode)
            passFieldLabel = Label(igroup, text="PassCode:")
            passCodeSetter = Button(igroup, text="Enter", width=10, command=self.setPassCode)
            self.nameVar = StringVar()
            self.nameVar.set("SBH")
            nameField = Entry(igroup, width=10, textvariable=self.nameVar)
            self.serverIPVar = StringVar()
            self.serverIPVar.set("127.0.0.1")
            serverIPField = Entry(igroup, width=15, textvariable=self.serverIPVar)
            self.serverPortVar = StringVar()
            self.serverPortVar.set("8088")
            serverPortField = Entry(igroup, width=5, textvariable=self.serverPortVar)
            serverSetButton = Button(igroup, text="Set", width=10, command=self.handleSetServer)
            addClientLabel = Label(igroup, text="Add Friend")
            self.clientIPVar = StringVar()
            self.clientIPVar.set("127.0.0.1")
            clientIPField = Entry(igroup, width=15, textvariable=self.clientIPVar)
            self.clientPortVar = StringVar()
            self.clientPortVar.set("8089")
            clientPortField = Entry(igroup, width=5, textvariable=self.clientPortVar)
            clientSetButton = Button(igroup, text="Add", width=10, command=self.handleAddClient)
            serverLabel.grid(row=0, column=0)
            nameField.grid(row=0, column=1)
            passField.grid(row=1, column=6)
            passFieldLabel.grid(row=1, column=5)
            serverIPField.grid(row=0, column=2)
            serverPortField.grid(row=0, column=3)
            serverSetButton.grid(row=0, column=4, padx=5)
            passCodeSetter.grid(row=1, column=8)
            addClientLabel.grid(row=0, column=5)
            clientIPField.grid(row=0, column=6)

            clientPortField.grid(row=0, column=7)
            clientSetButton.grid(row=0, column=9, padx=5)

            readChatGroup = Frame(parentFrame)
            self.receivedChats = Text(readChatGroup, bg="white", width=60, height=30, state=DISABLED)
            self.friends = Listbox(readChatGroup, bg="white", width=30, height=30)
            self.receivedChats.grid(row=0, column=0, sticky=W+N+S, padx=(0, 10))
            self.friends.grid(row=0, column=1, sticky=E+N+S)

            writeChatGroup = Frame(parentFrame)
            self.chatVar = StringVar() #changed from StringVar()
            self.ChatField = Entry(writeChatGroup, width=80, textvariable=self.chatVar)
            sendChatButton = Button(writeChatGroup, text="Send", width=10, command=self.handleSendChat)
            self.ChatField.grid(row=0, column=0, sticky=W)
            sendChatButton.grid(row=0, column=1, padx=5)

            self.statusLabel = Label(parentFrame)

            bottomLabel = Label(parentFrame, text="This is version .01")

            igroup.grid(row=0, column=0)
            readChatGroup.grid(row=1, column=0)
            writeChatGroup.grid(row=2, column=0, pady=10)
            self.statusLabel.grid(row=3, column=0)
            bottomLabel.grid(row=4, column=0, pady=10)

        def setPassCode(self):
            self.passCode = self.passCode.get().strip()
            self.key = BLAKE2s.new(digest_bits=64,)
            self.key.update(bytes(self.passCode, encoding = 'utf-8'))
            self.eKey = self.key.digest()
            self.cipher = DES.new(self.eKey, DES.MODE_OFB)
            self.mode = DES.MODE_OFB
            # place holder for key, take passcode parameter and generate key here or in main.
            self.encrypted = 1

        def handleSetServer(self):
            if self.encrypted == 0:
                return
            if self.serverSoc != None:
                self.serverSoc.close()
                self.serverSoc = None
                self.serverStatus = 0
            serveraddr = (self.serverIPVar.get().replace('',''), int(self.serverPortVar.get().replace(' ',' ')))
            try:
                    self.serverSoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.serverSoc.bind(serveraddr)
                    self.serverSoc.listen(5)
                    self.setStatus("Server listening on %s:%s" % serveraddr)
                    _thread.start_new_thread(self.listenClients, ())
                    self.serverStatus = 1
                    self.name = self.nameVar.get().replace(' ',' ')
                    if self.name == '':
                        self.name = "%s:%s" % serveraddr
            except:
                self.setStatus("Error initializing server")

        def listenClients(self):
            while 1:

                clientsoc, clientaddr = self.serverSoc.accept()
                self.setStatus("Client connected from %s:%s:" % clientaddr)
                self.addClient(clientsoc, clientaddr)
                _thread.start_new_thread(self.handleClientMessages, (clientsoc, clientaddr))
            self.serverSoc.close()

        def handleAddClient(self):
            if self.serverStatus == 0:
                self.setStatus("Set Server Address First")
                return
            clientaddr = (self.clientIPVar.get().replace(' ',' '), int(self.clientPortVar.get().replace(' ',' ')))
            try:
                clientsoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                clientsoc.connect(clientaddr)
                self.setStatus("connected to client on %s:%s" % clientaddr)
                self.addClient(clientsoc, clientaddr)
                _thread.start_new_thread(self.handleClientMessages, (clientsoc, clientaddr))

            except:
                self.setStatus("Error connecting to client")

        def handleClientMessages(self, clientsoc, clientaddr):
            while 1:
                try:

                    data = clientsoc.recv(self.buffersize)

                    if not data:
                        self.addChat("no data")
                        break
                    #self.addChat("them", str(data) )

                    cText = data[:len(data)-8]
                    initVector = data[len(cText):]
                    des2 = DES.new(self.eKey, self.mode, initVector)
                    pText = des2.decrypt(cText)
                    self.addChat("%s:%s[Encrypted]" % clientaddr, str(data))
                    self.addChat("%s:%s" % clientaddr, str(pText.decode('utf-8')))
                except:
                    self.addChat("exception occured")
                    break
            self.removeClient(clientsoc, clientaddr)
            clientsoc.close()
            self.setStatus("Client disconnected from %s:%s" % clientaddr)

        def handleSendChat(self):
            if self.serverStatus == 0:
                self.setStatus("Set server address first")
                return
            msg = self.chatVar.get().strip()
            if msg == '':
                return
            self.addChat("me", msg)
            iv = Random.get_random_bytes(8)
            des = DES.new(self.eKey, self.mode,iv)
            cText = des.encrypt(msg.encode('utf-8'))
          #  initVector = str(iv)
          #  initVector.encode('utf-8')
            data = cText + iv
            self.addChat('me[encrypted]', str(cText))
            for client in self.allClients.keys():
                client.send(data)


        def addChat(self,client,msg):
            self.receivedChats.config(state=NORMAL)
            self.receivedChats.insert("end", client + ": " +msg+"\n" )
            self.receivedChats.config(state=DISABLED)

        def setStatus(self, msg):
            self.statusLabel.config(text=msg)
            print(msg)


        def addClient(self, clientsoc, clientaddr):
            self.allClients[clientsoc]=self.counter
            self.counter += 1
            self.friends.insert(self.counter, "%s:%s" % clientaddr)

        def removeClient(self, clientsoc, clientaddr):
            print(self.allClients)
            self.friends.delete(self.allClients[clientsoc])
            del self.allClients[clientsoc]
            print(self.allClients)

        def encryptionHandler(self, msg):
            cipherText = self.cipher.iv + self.cipher.encrypt(bytes(msg, encoding='utf-8'))

        def decryptionHandler(self, cipherText):
            cipherText.decode('utf-8')
            data = self.cipher.decrypt(cipherText)


def main():
    # make it so main opens a window and prompts for passcode, then call client with pass code as a parameter

        root = Tk()



      #  passCode = input("enter pcode: ")
        app = client(root)
        root.mainloop()

if __name__ == '__main__':
        main()


