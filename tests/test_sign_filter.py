from client.tip712 import SignFilter
from dataset import DataSet, ADVANCED_DATA_SETS, TOKENS, TRUSTED_NAMES, FILT_TN_TYPES
from pathlib import Path
import json
import os

index = 2
def test_sign_712_filtering_advanced():
    print("712 message:", ADVANCED_DATA_SETS[index].data)
    SignFilter.sign_filter_data(ADVANCED_DATA_SETS[index].data, ADVANCED_DATA_SETS[index].filters)

    assert True == True

def test_sign_712_filtering_file():
    filters = None
    data = None

    file_name = "12-sign_in"
    main_name = f"{os.path.dirname(__file__)}/tip712_input_files/{file_name}"
    filterfile = Path(f"{main_name}-filter.json")
    if filterfile.exists():
        with open(filterfile, encoding="utf-8") as f:
            filters = json.load(f)
    
    datafile = Path(f"{main_name}-data.json")
    with open(datafile, encoding="utf-8") as f:
        data = json.load(f)

    print("input_file 712 message:", data)
    print("input_file 712 filters:", filters)
    SignFilter.sign_filter_data(data, filters)

    assert True == True
