from socket import *
from tkinter import *
from tkinter.ttk import *
from tkinter.scrolledtext import ScrolledText
from threading import Thread

HOST = '192.168.1.163'
PORT = 7555

def send_msg(host, sender, msg):
    #host = '192.168.1.116'
    #sender = 'win_user'
    with socket(AF_INET, SOCK_STREAM) as sock_cl:
        sock_cl.connect((host, PORT))
        sock_cl.sendall(str.encode(sender.ljust(16) + msg))
        answer = sock_cl.recv(8)

def server():
    with socket(AF_INET, SOCK_STREAM) as sock:
        sock.bind((HOST, PORT))
        sock.listen()
        while True:
            client, addr = sock.accept()
            print('Incoming connection from', addr)
            with client:
                while True:
                    msg = client.recv(1024)
                    if not msg:
                        break
                    msg = msg.decode()
                    inc_sender.set(msg[:16].strip())
                    new_msg.set(msg[16:])
                    client.sendall(b'1')

def chat_gui():
    chat_window = Tk()
    chat_window.title('P-2-P Chat')
    main_frame = Frame(chat_window)
    nick_var = StringVar()
    nick_var.set('User')
    global inc_sender
    global new_msg
    new_msg = StringVar()
    inc_sender = StringVar()
    msg_var = StringVar()
    ip_var = StringVar()

    def button_msg_send():
        msg = msg_var.get()
        if msg != '':
            print(msg)
            send_msg(ip_var.get(), nick_var.get(), msg_var.get())
            text_entry.config(state=NORMAL)
            text_entry.insert(END, nick_var.get()+': '+msg+'\n')
            text_entry.config(state=DISABLED)
            msg_var.set('')

    def msg_get():
        text_entry.config(state=NORMAL)
        text_entry.insert(END, inc_sender.get()+': '+new_msg.get()+'\n')
        text_entry.config(state=DISABLED)

    def button_param_set():
        nick = nick_var.get()
        ip = ip_var.get()
        if ((3 <= len(nick) <= 16) and (nick.isalnum())):
            try:
                inet_aton(ip)
                msg_entry.config(state=NORMAL)
                warn_label.pack_forget()
            except error:
                warn_label.config(text='Invalid IP')
        else:
            warn_label.config(text='Nick name not valid')


    entry_frame = Frame(main_frame)
    nick_lbl = LabelFrame(main_frame, text='Enter target ip and your nick name (3-16 characters)')
    nick_entry = Entry(nick_lbl, textvariable = nick_var).grid(row=1, column=2)
    connect_ip_entry = Entry(nick_lbl, textvariable=ip_var).grid(row=1, column=1)
    warn_label = Label(nick_lbl, text="Nick name and target ip is required to start chatting", foreground="red")
    warn_label.grid(row=2, column=1, columnspan=3)
    Button(nick_lbl, text='Set', command=button_param_set).grid(row=1, column=3)
    nick_lbl.pack(padx=5, pady=5)

    new_msg.trace("w", lambda *args: msg_get())

    text_entry = ScrolledText(main_frame, wrap=WORD, width=50, height=20, state=DISABLED)
    text_entry.pack()

    msg_entry = Entry(entry_frame, textvariable=msg_var, width=60, state=DISABLED)
    msg_entry.grid(row=1,column=1)
    Button(entry_frame, text='Send', command=button_msg_send).grid(row=1,column=2)
    entry_frame.pack()

    Thread(target=server).start()
    main_frame.pack()
    chat_window.mainloop()


if __name__ == '__main__':
    chat_gui()
