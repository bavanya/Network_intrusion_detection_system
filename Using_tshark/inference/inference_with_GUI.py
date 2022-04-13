from tkinter import *
from helper_functions.prepare_data_for_model2 import prepare_data_for_model2
from helper_functions.load_data import load_data

import sys, signal, os
import subprocess
import threading
from time import sleep
import pickle
import pandas as pd
import numpy as np
import warnings
import signal

warnings.filterwarnings("ignore")

process_id = -1

def signal_handler(sig, frame):
    print("\n(!) CTRL-C Pressed")
    print(process_id)
    os.kill(process_id, signal.SIGTERM)
    sys.exit(0)

def clicked():

    top= Toplevel(r)
    top.geometry("750x250")
    top.title("Child Window")
    Label(top, text= "100 Packets successfully captured!", font=('Mistral 18 bold')).place(x=150,y=80)    


    f = open('data_test/test.csv', "w")
    proc = subprocess.Popen(['tshark', '-c', '100', '-i', 'wlan0mon', '-T', 'fields', '-e', 'frame.encap_type', '-e', 'frame.len', '-e', 'frame.number', '-e', 'frame.time_delta', '-e', 'frame.time_delta_displayed', '-e', 'frame.time_epoch', '-e', 'frame.time_relative', '-e', 'radiotap.channel.freq', '-e', 'radiotap.length', '-e', 'wlan.duration', '-e', 'wlan.fc.ds', '-e', 'wlan.fc.frag', '-e', 'wlan.fc.order', '-e', 'wlan.fc.moredata', '-e', 'wlan.fc.protected', '-e', 'wlan.fc.pwrmgt', '-e', 'wlan.fc.type', '-e', 'wlan.fc.retry', '-e', 'wlan.fc.subtype', '-e', 'wlan.ra','-E' ,'header=y' ,'-E' ,'separator=* '], stdout = f)

    process_id = proc.pid

    random_forest_model = pickle.load(open('../intrusion_detector/rev_random_forest_model3.sav','rb'))

    l = ['Botnet','Deauth','Evil_Twin','Normal','SQL_Injection','Website_spoofing']
    l = np.array(l)

    n = 1

    while(n <= 100):
        df = load_data('data_test/test.csv', n, 1)
        if len(df) == 0: continue

        df = prepare_data_for_model2(df)
        
        inference_data = df.to_numpy()

        predictions = random_forest_model.predict(inference_data)
        
        l = ['Botnet','Deauth','Evil_Twin','Normal','SQL_Injection','Website_spoofing']
        l = np.array(l)

        for x in predictions:
            for y in range(len(x)):
                if(x[y]==1):
                    t = "Label for packet " + str(n) + " is " + str(l[y])
                    listbox.insert(END, t)
                    listbox.yview(END) 
                    break   
            n +=1

def close():
    signal.signal(signal.SIGINT, signal_handler)
    r.destroy()
    

r = Tk()
r.title('Counting Seconds')
r.geometry('900x900')
r.config(bg = "#464342")
r.resizable(0, 0)

listbox = Listbox(r, height = 40, 
                    width = 40, 
                    bg = "grey",
                    activestyle = 'dotbox', 
                    font = "Helvetica",
                    fg="white")  
scrollbar = Scrollbar(r)

listbox.config(yscrollcommand = scrollbar.set)
scrollbar.config(command = listbox.yview)
listbox.grid(column=200, row=350)


btn = Button(r, text = "Start Intrusion Detector", width=25, fg = "blue", command=clicked)
btn.grid(column=400, row=350)


button = Button(r, text='Close', fg = "red", width=25, command=close)
button.grid(column=600, row=350)

r.mainloop()
