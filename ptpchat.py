from socket import *
from tkinter import *
from tkinter.ttk import *
from tkinter.scrolledtext import ScrolledText
from tkinter.messagebox import showinfo
from threading import Thread
import configparser

shutdown = False
HOST = ''
PORT = None

#init settings from config
def start_init():
    config = configparser.ConfigParser()
    config.read('settings.ini')
    global HOST
    global PORT
    HOST = config['DEFAULT']['HOST_IP']
    PORT = int(config['DEFAULT']['PORT'])

#sending msg to target ip
def send_msg(host, sender, msg):
    with socket(AF_INET, SOCK_STREAM) as sock_cl:
        try:
            sock_cl.connect((host, PORT))
            sock_cl.sendall(str.encode(sender.ljust(16) + msg))
            return True
        except:
            return False

#full time listening
def server():
    with socket(AF_INET, SOCK_STREAM) as sock:
        sock.bind((HOST, PORT))
        sock.listen()
        while True:
            #try:
            client, addr = sock.accept()
            global shutdown
            if shutdown == True: break
            print('Incoming connection from', addr)
            with client:
                while True:
                    msg = client.recv(1024)
                    if not msg:
                        break
                    msg = msg.decode()
                    inc_sender.set(msg[:16].strip())
                    new_msg.set(msg[16:])
                    inc_addr.set(addr)
                    client.sendall(b'1')
            #except:
                #pass

#main part(gui + etc.)
def chat_gui():
    #gui init + variables + config inits
    log_use = True
    start_init()
    chat_window = Tk()
    chat_window.title('P-2-P Chat')
    main_frame = Frame(chat_window)
    nick_var = StringVar()
    global inc_sender
    global new_msg
    global inc_addr
    inc_addr = StringVar()
    new_msg = StringVar()
    inc_sender = StringVar()
    msg_var = StringVar()
    ip_var = StringVar()
    log_dict = configparser.ConfigParser()
    set_dict = configparser.ConfigParser()


    #set last valid target ip and nickname as default
    def second_init():
        nonlocal set_dict
        set_dict.read('settings.ini')
        nonlocal ip_var
        ip = set_dict['DEFAULT']['LAST_IP']
        ip_var.set(ip)
        nonlocal nick_var
        nick = set_dict['DEFAULT']['LAST_NICKNAME']
        nick_var.set(nick)

    #save to config params from last valid message send
    def set_config(ip, nick):
        nonlocal set_dict
        config = configparser.ConfigParser()
        set_dict['DEFAULT']['LAST_IP'] = ip
        set_dict['DEFAULT']['LAST_NICKNAME'] = nick

    #send and write target msg
    def button_msg_send():
        msg = msg_var.get()
        if msg != '':
            #print(msg)
            msg_var.set('')
            is_sended = send_msg(ip_var.get(), nick_var.get(), msg)
            if is_sended == True:
                text_entry.config(state=NORMAL)
                text_entry.insert(END, nick_var.get()+': '+msg+'\n')
                text_entry.config(state=DISABLED)
                set_config(ip_var.get(),nick_var.get())
                fill_log(HOST, nick_var.get(), msg)
            else:
                showinfo("warning", "no connection to the specified server")

    #write incomming msg
    def msg_get():
        text_entry.config(state=NORMAL)
        text_entry.insert(END, inc_sender.get()+': '+new_msg.get()+'\n')
        text_entry.config(state=DISABLED)
        nonlocal log_use
        if log_use: fill_log(inc_addr.get(), inc_sender.get(), new_msg.get())

    #fill log file
    def fill_log(ip, sender, msg):
        nonlocal log_dict
        rec_num = int(log_dict['INFO']['RECORDS_NUMBER'])
        les = int(log_dict['INFO']['LAST_ENTRY_SHOWN'])
        log_dict['CHAT_LOG'][str(rec_num+1)] = ip + sender + msg
        log_dict['PARSE'][str(rec_num+1)] = "I" + str(len(ip)) + "S" + str(len(sender)) + "M" + str(len(msg))
        log_dict['INFO']['RECORDS_NUMBER'] = str(rec_num+1)
        if (rec_num - les) > 20: log_dict['INFO']['LAST_ENTRY_SHOWN'] = str(les+1)

    #save log dicts to files
    def write_log():
        nonlocal log_dict
        with open('log.ini', 'w') as log_file:
            log_dict.write(log_file)
        nonlocal set_dict
        with open('settings.ini', 'w') as configfile:
            set_dict.write(configfile)

    #fill chat from log file
    def fill_chat():
        nonlocal log_dict
        nonlocal log_use
        log_use = False
        log_dict = configparser.ConfigParser()
        log_dict.read('log.ini')
        rec_num = int(log_dict['INFO']['RECORDS_NUMBER'])
        les = int(log_dict['INFO']['LAST_ENTRY_SHOWN'])
        if rec_num > 0:
            for i in range(les, rec_num):
                logstr = log_dict['CHAT_LOG'][str(i+1)]
                parse = log_dict['PARSE'][str(i+1)]
                s_pos = parse.find("S")
                m_pos = parse.find("M")
                m_len = int(parse[(m_pos+1):])
                s_len = int(parse[(s_pos+1):(m_pos-len(parse))])
                msg = logstr[(len(logstr)-m_len):]
                logstr = logstr[:(-1*m_len)]
                sender = logstr[(len(logstr)-s_len):]
                inc_sender.set(sender)
                new_msg.set(msg)
                #msg_get()
        log_use = True

    #set basic params for chat session - target ip and nick
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

    #close programm
    def close_program():
        write_log()
        global shutdown
        shutdown = True
        with socket(AF_INET,SOCK_STREAM) as cl_sock:
            cl_sock.connect((HOST, PORT))
        chat_window.destroy()

    #gui tools init
    chat_window.protocol('WM_DELETE_WINDOW', close_program)
    second_init()
    entry_frame = Frame(main_frame)
    nick_lbl = LabelFrame(main_frame, text='Enter target ip and your nick name (3-16 characters)')
    nick_entry = Entry(nick_lbl, textvariable = nick_var).grid(row=1, column=2)
    connect_ip_entry = Entry(nick_lbl, textvariable=ip_var).grid(row=1, column=1)
    warn_label = Label(main_frame, text="Nick name and target ip is required to start chatting", foreground="red")
    warn_label.pack()
    Button(nick_lbl, text='Set', command=button_param_set).grid(row=1, column=3)
    nick_lbl.pack(padx=5, pady=5)

    new_msg.trace("w", lambda *args: msg_get())

    text_entry = ScrolledText(main_frame, wrap=WORD, width=50, height=20, state=DISABLED)
    text_entry.pack()


    msg_entry = Entry(entry_frame, textvariable=msg_var, width=60, state=DISABLED)
    msg_entry.grid(row=1,column=1)
    Button(entry_frame, text='Send', command=button_msg_send).grid(row=1,column=2)
    entry_frame.pack()
    fill_chat()

    #start listen and mainloop
    Thread(target=server).start()
    main_frame.pack()
    chat_window.mainloop()
    write_log()


if __name__ == '__main__':
    chat_gui()
