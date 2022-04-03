def prepare_data_for_model(data1):
    data1['protocol_type'] = data1['protocol_type'].astype('category')
    data1['service'] = data1['service'].astype('category')
    data1['flag'] = data1['flag'].astype('category')
    cat_columns = data1.select_dtypes(['category']).columns
    data1[cat_columns] = data1[cat_columns].apply(lambda x: x.cat.codes)

    df = data1.drop_duplicates(subset=None, keep='first')

    return df