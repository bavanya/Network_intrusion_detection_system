import numpy as np
import pandas as pd
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.metrics import classification_report,confusion_matrix
from sklearn.multiclass import OneVsRestClassifier
from sklearn.ensemble import RandomForestClassifier
import pickle 

def classify(data,label):
    type=[]
    for i in data['label']:
        if i == 'normal':
            type.append('Normal')
        elif i in R2L:
            type.append('R2L')
        elif i in U2R:
            type.append('U2R')
        elif i in DoS:
            type.append('DoS')
        else:
            type.append('Probe')
    return type

def prepare_data_for_model(data1):
    data1['protocol_type'] = data1['protocol_type'].astype('category')
    data1['service'] = data1['service'].astype('category')
    data1['flag'] = data1['flag'].astype('category')
    cat_columns = data1.select_dtypes(['category']).columns
    data1[cat_columns] = data1[cat_columns].apply(lambda x: x.cat.codes)

    df = data1.drop_duplicates(subset=None, keep='first')

    return df

if __name__ == "__main__":

    data = pd.read_csv('training_data.csv')

    R2L=['warezmaster','warezclient','spy','phf','multihop','imap','guess_passwd','ftp_write']

    U2R=['rootkit','perl','loadmodule','buffer_overflow']
    DoS=['smurf','teardrop','back','land','neptune','pod']
    Probe=['ipsweep','nmap','portsweep','satan']

    data['check']=classify(data,'label')

    data1 = data[['src_bytes',
    'service',
    'protocol_type',
    'flag',
    'dst_bytes',
    'duration',
    'wrong_fragment',
    'num_failed_logins',
    'logged_in',
    'lnum_compromised',
    'logged_in',
    'is_guest_login',
    'label',
    'check'
    ]]

    data1.rename(columns = {'label':'attack_types', 'check':'label'}, inplace = True) 

    df = prepare_data_for_model(data1)

    dummies = pd.get_dummies(df[['label']],drop_first=False)
    df = df.drop(['label'],axis=1)
    df = pd.concat([df,dummies],axis=1)

    xn=df.drop(['label_DoS','label_Normal','label_Probe','label_U2R','label_R2L','attack_types'],axis=1)
    #xn=df.drop(['attack_types','label'],axis=1)
    yn=df[['label_Normal','label_DoS','label_Probe','label_R2L','label_U2R']]

    xtrn,xten,ytrn,yten=train_test_split(xn,yn,test_size=0.35,random_state=69) 

    clf1 = RandomForestClassifier()

    scores = cross_val_score(clf1, xtrn, ytrn, cv=3, scoring='accuracy')
    print("Accuracy: %.2f (+/- %.2f) [%s]" %(scores.mean(), scores.std(), 'Random Forest'))
    m = OneVsRestClassifier(clf1)
    m.fit(xtrn, ytrn)
    pred=m.predict(xten)
    print(classification_report(yten,pred))
    ytt=yten.to_numpy()
    #ptt=pred.to_numpy()
    print(confusion_matrix(ytt.argmax(axis=1),pred.argmax(axis=1)))

    filename = 'random_forest_model.sav'

    pickle.dump(m, open(filename, 'wb'))