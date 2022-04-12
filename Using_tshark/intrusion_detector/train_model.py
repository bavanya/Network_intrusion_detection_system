import numpy as np
import pandas as pd
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.metrics import classification_report,confusion_matrix
from sklearn.multiclass import OneVsRestClassifier
from sklearn.ensemble import RandomForestClassifier
import pickle


def prepare_data_for_model(data1):
    #data1['radiotap.present.tsft'] = data1['radiotap.present.tsft'].astype('category')  #string
    #data1['radiotap.rxflags'] = data1['radiotap.rxflags'].astype('category')
    data1['wlan.fc.ds'] = data1['wlan.fc.ds'].astype('category')
    data1['wlan.ra'] = data1['wlan.ra'].astype('category')

    cat_columns = data1.select_dtypes(['category']).columns
    data1[cat_columns] = data1[cat_columns].apply(lambda x: x.cat.codes)

    df = data1.drop_duplicates(subset=None, keep='first')

    return df

if __name__ == "__main__":

    # load : get the data from file
    file_path = r"C:\Users\91876\Desktop\Sem 8\Network Security\IDS-main\Wireless-Intrusion-Detection-System-main\IDS-Live\data"
    data = pickle.load(open(file_path + r"\smaller_good_data.pkl", "rb"))
    #small_data = data[1:1000]

    labels = ['Botnet','Deauth','Evil_Twin','Normal','SQL_Injection','Website_spoofing']

    #data['check'] = data[:,'Label']
    data1 = data[['frame.encap_type',
                  'frame.len',
                  'frame.number',
                  'frame.time_delta',
                  'frame.time_delta_displayed',
                  'frame.time_epoch',
                  'frame.time_relative',
                  'radiotap.length',
                  'wlan.duration',
                  'wlan.fc.ds',
                  'wlan.fc.frag',
                  'wlan.fc.order',
                  'wlan.fc.moredata',
                  'wlan.fc.protected',
                  'wlan.fc.pwrmgt',
                  'wlan.fc.type',
                  'wlan.fc.retry',
                  'wlan.fc.subtype',
                  'wlan.ra',
                  'Label']]

    #data1.rename(columns = {'label':'attack_types', 'check':'label'}, inplace = True)

    print(data1.dtypes)
    df = prepare_data_for_model(data1)
    print(df.dtypes)
    
    dummies = pd.get_dummies(df[['Label']],drop_first=False)
    df = df.drop(['Label'],axis=1)
    df = pd.concat([df,dummies],axis=1)
    
    xn=df.drop(['Label_Botnet','Label_Deauth','Label_Evil_Twin','Label_Normal','Label_SQL_Injection','Label_Website_spoofing'],axis=1)
    #xn=df.drop(['attack_types','label'],axis=1)
    yn=df[['Label_Botnet','Label_Deauth','Label_Evil_Twin','Label_Normal','Label_SQL_Injection','Label_Website_spoofing']]

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

    filename = 'rev_random_forest_model3.sav'
    
    pickle.dump(m, open(filename, 'wb'))