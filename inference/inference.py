import pandas as pd 
import numpy as np
import pickle	
import os
from helper_functions.prepare_data_for_model import prepare_data_for_model

os.system('bash capture_traffic.sh')
df = pd.read_csv('data_files/dataset_records.csv')

# Add code to run inference.
df = prepare_data_for_model(df)

#print(df)
random_forest_model = pickle.load(open('../intrusion_detector/random_forest_model.sav','rb'))

inference_data=df.to_numpy()

predictions = random_forest_model.predict(inference_data)

#print(predictions)
print("no of connections found = " + str(len(predictions)))


l=['Normal','DoS','Probe','R2L','U2R']
l=np.array(l)

counter = 0

for x in predictions:
    counter+=1
    for y in range(len(x)):
        if x.sum()==0:
            print("Label for connection " + str(counter) + " is Normal")
            break
        if x[y]==1:
            print("Label for connection " + str(counter) + " is " + str(l[y]))
            break
