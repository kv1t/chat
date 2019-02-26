from socket import *
from tkinter import *
from tkinter.ttk import *
from tkinter.scrolledtext import *
from threading import Thread

HOST = '127.0.0.1'
PORT = 7555
#new_msg = StringVar()
sender = 'Default'

def send_msg(host, sender, msg):
    with socket(AF_INET, SOCK_STREAM) as sock_cl:
        sock_cl.connect((host, PORT))
        sock_cl.sendall(str.encode(msg))
        answer = sock_cl.recv(8)
        print('Client: received ' + answer.decode())
#        return int(answer.decode())

def server():
    with socket(AF_INET, SOCK_STREAM) as sock:
        sock.bind((HOST, PORT))
        sock.listen()
        print('Start listening on', HOST, PORT)

        while True:
            client, addr = sock.accept()
            print('Incoming connection from', addr)
            with client:
                while True:
                    msg = client.recv(1024)
                    if not msg:
                        break
                    sender = addr
                    new_msg.set(msg.decode())
                    client.sendall(b'1')

def chat_gui():

    chat_window = Tk()
    chat_window.title('P-2-P Chat')
    main_frame = Frame(chat_window)
    nick_var = StringVar()
    nick_var.set('User')
    new_msg = StringVar()
    msg_var = StringVar()

    def msg_send():
        msg = msg_var.get()
        if msg != '':
            print(msg)
            send_msg(HOST, nick_var.get(), msg_var.get())
            text_entry.config(state=NORMAL)
            text_entry.insert(END, nick_var.get()+': '+msg+'\n')
            text_entry.config(state=DISABLED)
            msg_var.set('')

    def msg_get():
        text_entry.config(state=NORMAL)
        text_entry.insert(END, sender+': '+new_msg.get()+'\n')
        text_entry.config(state=DISABLED)

    new_msg.trace("w", msg_get)

    entry_frame = Frame(main_frame)

    nick_lbl = LabelFrame(main_frame, text='Enter your nick name 3-16 characters')
    nick_entry = Entry(nick_lbl, textvariable = nick_var).pack(fill=X)
    Button(nick_lbl, text='Set').pack(fill=X)
    nick_lbl.pack(padx = 15, pady = 15)

    text_entry = ScrolledText(main_frame, wrap=WORD, width=50, height=20)
    text_entry.pack()

    for i in range(10):
        string = 'string number: '+str(i)+'\n'
        text_entry.insert(INSERT, string)
    text_entry.config(state=DISABLED)


    msg_entry = Entry(entry_frame, textvariable = msg_var, width=60).grid(row=1,column=1)
    Button(entry_frame, text='Send', command=msg_send).grid(row=1,column=2)
    entry_frame.pack()

    Thread(target=server).start()
    main_frame.pack()
    chat_window.mainloop()


if __name__ == '__main__':
    chat_gui()
