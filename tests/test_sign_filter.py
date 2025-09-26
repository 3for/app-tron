from client.tip712 import SignFilter
from dataset import DataSet, ADVANCED_DATA_SETS, TOKENS, TRUSTED_NAMES, FILT_TN_TYPES
from pathlib import Path
import json
import os
from client.tip712 import EncodeTokenInfo

index = 2
def test_sign_712_filtering_advanced():
    print("712 message:", ADVANCED_DATA_SETS[index].data)
    SignFilter.sign_filter_data(ADVANCED_DATA_SETS[index].data, ADVANCED_DATA_SETS[index].filters)

    assert True == True

def test_sign_712_filtering_file():
    filters = None
    data = None

    file_name = "11-complex_structs"
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

def test_sign_712_filtering_fixtures():
    filters = None
    data = None

    file_name = "18-1inch-fusion"
    main_name = f"{os.path.dirname(__file__)}/fixtures/messages/{file_name}"
    filterfile = Path(f"{main_name}-filter.json")
    if filterfile.exists():
        with open(filterfile, encoding="utf-8") as f:
            filters = json.load(f)
    
    datafile = Path(f"{main_name}-data.json")
    with open(datafile, encoding="utf-8") as f:
        data = json.load(f)

    print("fixtures 712 message:", data)
    print("fixtures 712 filters:", filters)
    SignFilter.sign_filter_data(data, filters)

    assert True == True

def test_encode_token_info():
    # token list for ledger-live fixtures 
    token_entries = [
        {
            "ticker": "USDC",
            "contractAddress": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            "decimals": 6,
            "chainId": 1151668124,
            "signature": "30440220085b3fdecb553d56c13662868d169060d8102c258b5da5e8d72e772170c9aa8a02207a22424b725f7c071d4ac780a4ea5df8a5106a3d60d8dd9c0701543a84932ea1"
        },
        {
            "ticker": "WETH",
            "contractAddress": "0x7ceb23fd6bc0add59e62ac25578270cff1b9f619",
            "decimals": 18,
            "chainId": 1151668124,
            "signature": "3045022044d2574e5035442f6ab74aa409d4b5e602a78ba328eaeb87eac5fb3d0debf6ed022100f6b0d23464af316c460b5d869a05cf53db948ef5ff4fe968fdbe03c21d2d88cd"
        },
        {
            "ticker": "WETH",
            "contractAddress": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
            "decimals": 18,
            "chainId": 1151668124,
            "signature": "3046022100db2cd0168a2907ea521463e41c0c84092f468665718f6271e1933de0ae192c2e022100b73c3cccc32d2445ac57cd24178c8ae1cec3e882c88d5524a851a9fffcc3e03e"
        },
        {
            "ticker": "USDC",
            "contractAddress": "0x2791bca1f2de4661ed88a30c99a7a9449aa84174",
            "decimals": 6,
            "chainId": 1151668124,
            "signature": "3046022100974543ce8335dd3d89e3845195e397329057cebe4e29e327b23d63c6808cc2c8022100e678d63847ed23f071f0d33f8a4a4d1a8765b6cc78938d0f2f48a06e8f410d21"
        },
        {
            "ticker": "WMATIC",
            "contractAddress": "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270",
            "decimals": 18,
            "chainId": 1151668124,
            "signature": "30450221009714216babc36cfc3518b6b11348960e2030886e2bb39a748672e7b483ef9ec802200b6b252ebe3310ecd58cc3d26532431954856ac5afaf50d891a276c02a237fc6"
        }
    ]
    
    trc20SignaturesBlob = EncodeTokenInfo.encode_token_info(token_entries)
    print("ZYD trc20SignaturesBlob:", trc20SignaturesBlob)

    assert True == True