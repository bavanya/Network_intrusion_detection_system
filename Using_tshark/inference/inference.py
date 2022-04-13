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
import tkinter as tk

def signal_handler(sig, frame):
    print("\n(!) CTRL-C Pressed")
    os.kill(os.getpid(), signal.SIGTERM)
    sys.exit(0)

warnings.filterwarnings("ignore")
signal.signal(signal.SIGINT, signal_handler)

f = open('data_test/test.csv', "w")
proc = subprocess.Popen(['tshark', '-i', 'wlan0mon', '-T', 'fields', '-e', 'frame.encap_type', '-e', 'frame.len', '-e', 'frame.number', '-e', 'frame.time_delta', '-e', 'frame.time_delta_displayed', '-e', 'frame.time_epoch', '-e', 'frame.time_relative', '-e', 'radiotap.channel.freq', '-e', 'radiotap.length', '-e', 'wlan.duration', '-e', 'wlan.fc.ds', '-e', 'wlan.fc.frag', '-e', 'wlan.fc.order', '-e', 'wlan.fc.moredata', '-e', 'wlan.fc.protected', '-e', 'wlan.fc.pwrmgt', '-e', 'wlan.fc.type', '-e', 'wlan.fc.retry', '-e', 'wlan.fc.subtype', '-e', 'wlan.ra','-E' ,'header=y' ,'-E' ,'separator=* '], stdout = f)

random_forest_model = pickle.load(open('../intrusion_detector/rev_random_forest_model3.sav','rb'))

l = ['Botnet','Deauth','Evil_Twin','Normal','SQL_Injection','Website_spoofing']
l = np.array(l)

n = 1

while(True):
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
                print(t)
                break   
        n +=1
