from client.tip712 import SignFilter
from dataset import DataSet, ADVANCED_DATA_SETS, TOKENS, TRUSTED_NAMES, FILT_TN_TYPES

index = 2
def test_sign_712_filtering():
    print("712 message:", ADVANCED_DATA_SETS[index].data)
    SignFilter.sign_filter_data(ADVANCED_DATA_SETS[index].data, ADVANCED_DATA_SETS[index].filters)

    assert True == True