def prepare_data_for_model2(data1):

    data1 = data1[['frame.encap_type',
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
                  'wlan.ra']]
        
    data1['wlan.fc.ds'] = data1['wlan.fc.ds'].astype('category')
    data1['wlan.ra'] = data1['wlan.ra'].astype('category')

    cat_columns = data1.select_dtypes(['category']).columns
    data1[cat_columns] = data1[cat_columns].apply(lambda x: x.cat.codes)

    df = data1.drop_duplicates(subset=None, keep='first')

    return df
