from time import sleep
import pandas as pd

def load_data(file_path, n, rows):
    loaded = False
    while loaded == False:
        try:
            df = pd.read_csv(file_path, sep='*', skiprows=range(1, n), nrows=rows)
            loaded = True
        except:
            #print('(!) WARN: EOF reached, retrying in 3 seconds')
            sleep(3)
    return df
