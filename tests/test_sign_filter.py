from client.tip712 import SignFilter
from dataset import DataSet, ADVANCED_DATA_SETS, TOKENS, TRUSTED_NAMES, FILT_TN_TYPES

def test_sign_712_filtering():
    SignFilter.sign_filter_data(ADVANCED_DATA_SETS[0].data, ADVANCED_DATA_SETS[0].filters)

    assert True == True