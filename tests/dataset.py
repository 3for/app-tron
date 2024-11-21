from ctypes import c_uint64
import web3
import pytest
import InputData as InputData

class DataSet():
    data: dict
    filters: dict
    suffix: str

    def __init__(self, data: dict, filters: dict, suffix: str = ""):
        self.data = data
        self.filters = filters
        self.suffix = suffix


ADVANCED_DATA_SETS = [
    DataSet(
        {
            "domain": {
                "chainId": 1151668124,
                "name": "Advanced test",
                "verifyingContract":
                "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
                "version": "1"
            },
            "message": {
                "with": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
                "token_send": "0x6B175474E89094C44Da98b954EedeAC495271d0F",
                "value_send": 24500000000000000000,
                "token_recv": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
                "value_recv": 10000000000000000,
                "expires": 1714559400,
            },
            "primaryType": "Transfer",
            "types": {
                "EIP712Domain": [{
                    "name": "name",
                    "type": "string"
                }, {
                    "name": "version",
                    "type": "string"
                }, {
                    "name": "chainId",
                    "type": "uint256"
                }, {
                    "name": "verifyingContract",
                    "type": "address"
                }],
                "Transfer": [
                    {
                        "name": "with",
                        "type": "address"
                    },
                    {
                        "name": "token_send",
                        "type": "address"
                    },
                    {
                        "name": "value_send",
                        "type": "uint256"
                    },
                    {
                        "name": "token_recv",
                        "type": "address"
                    },
                    {
                        "name": "value_recv",
                        "type": "uint256"
                    },
                    {
                        "name": "expires",
                        "type": "uint64"
                    },
                ]
            }
        }, {
            "name":
            "Advanced Filtering",
            "tokens": [
                {
                    "addr": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
                    "ticker": "WETH",
                    "decimals": 18,
                    "chain_id": 1151668124,
                },
                {
                    "addr": "0x6b175474e89094c44da98b954eedeac495271d0f",
                    "ticker": "DAI",
                    "decimals": 18,
                    "chain_id": 1151668124,
                },
            ],
            "fields": {
                "value_send": {
                    "type": "amount_join_value",
                    "name": "Send",
                    "token": 1,
                },
                "token_send": {
                    "type": "amount_join_token",
                    "token": 1,
                },
                "value_recv": {
                    "type": "amount_join_value",
                    "name": "Receive",
                    "token": 0,
                },
                "token_recv": {
                    "type": "amount_join_token",
                    "token": 0,
                },
                "with": {
                    "type": "raw",
                    "name": "With",
                },
                "expires": {
                    "type": "datetime",
                    "name": "Will Expire"
                },
            }
        }),
    DataSet(
        {
            "types": {
                "EIP712Domain": [
                    {
                        "name": "name",
                        "type": "string"
                    },
                    {
                        "name": "version",
                        "type": "string"
                    },
                    {
                        "name": "chainId",
                        "type": "uint256"
                    },
                    {
                        "name": "verifyingContract",
                        "type": "address"
                    },
                ],
                "Permit": [
                    {
                        "name": "owner",
                        "type": "address"
                    },
                    {
                        "name": "spender",
                        "type": "address"
                    },
                    {
                        "name": "value",
                        "type": "uint256"
                    },
                    {
                        "name": "nonce",
                        "type": "uint256"
                    },
                    {
                        "name": "deadline",
                        "type": "uint256"
                    },
                ]
            },
            "primaryType": "Permit",
            "domain": {
                "name": "ENS",
                "version": "1",
                "verifyingContract":
                "0xC18360217D8F7Ab5e7c516566761Ea12Ce7F9D72",
                "chainId": 1151668124,
            },
            "message": {
                "owner": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
                "spender": "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
                "value": 4200000000000000000,
                "nonce": 0,
                "deadline": 1719756000,
            }
        }, {
            "name":
            "Permit filtering",
            "tokens": [
                {
                    "addr": "0xC18360217D8F7Ab5e7c516566761Ea12Ce7F9D72",
                    "ticker": "ENS",
                    "decimals": 18,
                    "chain_id": 1151668124,
                },
            ],
            "fields": {
                "value": {
                    "type": "amount_join_value",
                    "name": "Send",
                },
                "deadline": {
                    "type": "datetime",
                    "name": "Deadline",
                },
            }
        }, "_permit"),
    DataSet(
        {
            "types": {
                "EIP712Domain": [
                    {
                        "name": "name",
                        "type": "string"
                    },
                    {
                        "name": "version",
                        "type": "string"
                    },
                    {
                        "name": "chainId",
                        "type": "uint256"
                    },
                    {
                        "name": "verifyingContract",
                        "type": "address"
                    },
                ],
                "Root": [
                    {
                        "name": "token_big",
                        "type": "address"
                    },
                    {
                        "name": "value_big",
                        "type": "uint256"
                    },
                    {
                        "name": "token_biggest",
                        "type": "address"
                    },
                    {
                        "name": "value_biggest",
                        "type": "uint256"
                    },
                ]
            },
            "primaryType": "Root",
            "domain": {
                "name": "test",
                "version": "1",
                "verifyingContract":
                "0x0000000000000000000000000000000000000000",
                "chainId": 1151668124,
            },
            "message": {
                "token_big": "0x6b175474e89094c44da98b954eedeac495271d0f",
                "value_big": c_uint64(-1).value,
                "token_biggest": "0x6b175474e89094c44da98b954eedeac495271d0f",
                "value_biggest": int(web3.constants.MAX_INT, 0),
            }
        }, {
            "name":
            "Unlimited test",
            "tokens": [
                {
                    "addr": "0x6b175474e89094c44da98b954eedeac495271d0f",
                    "ticker": "DAI",
                    "decimals": 18,
                    "chain_id": 1151668124,
                },
            ],
            "fields": {
                "token_big": {
                    "type": "amount_join_token",
                    "token": 0,
                },
                "value_big": {
                    "type": "amount_join_value",
                    "name": "Big",
                    "token": 0,
                },
                "token_biggest": {
                    "type": "amount_join_token",
                    "token": 0,
                },
                "value_biggest": {
                    "type": "amount_join_value",
                    "name": "Biggest",
                    "token": 0,
                },
            }
        }, "_unlimited"),
]

filtering_empty_array_test_data = {
    'data': {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
                "Person": [
                    {"name": "name", "type": "string"},
                    {"name": "addr", "type": "address"},
                ],
                "Message": [
                    {"name": "title", "type": "string"},
                    {"name": "to", "type": "Person[]"},
                ],
                "Root": [
                    {"name": "text", "type": "string"},
                    {"name": "subtext", "type": "string[]"},
                    {"name": "msg_list1", "type": "Message[]"},
                    {"name": "msg_list2", "type": "Message[]"},
                ],
            },
            "primaryType": "Root",
            "domain": {
                "name": "test",
                "version": "1",
                "verifyingContract": "0x0000000000000000000000000000000000000000",
                "chainId": 1151668124,
            },
            "message": {
                "text": "This is a test",
                "subtext": [],
                "msg_list1": [
                    {
                        "title": "This is a test",
                        "to": [],
                    }
                ],
                "msg_list2": [],
            }
    },
    'filters': {
            "name": "Empty array filtering",
            "fields": {
                "text": {
                    "type": "raw",
                    "name": "Text",
                },
                "subtext.[]": {
                    "type": "raw",
                    "name": "Sub-Text",
                },
                "msg_list1.[].to.[].addr": {
                    "type": "raw",
                    "name": "(1) Recipient addr",
                },
                "msg_list2.[].to.[].addr": {
                    "type": "raw",
                    "name": "(2) Recipient addr",
                },
            }
    }
}


TOKENS = [
    [
        {
            "addr": "0x1111111111111111111111111111111111111111",
            "ticker": "SRC",
            "decimals": 18,
            "chain_id": 1151668124,
        },
        {},
    ],
    [
        {},
        {
            "addr": "0x2222222222222222222222222222222222222222",
            "ticker": "DST",
            "decimals": 18,
            "chain_id": 1151668124,
        },
    ]
]

advanced_missing_token_test_data = {
    'data': {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
                "Root": [
                    {"name": "token_from", "type": "address"},
                    {"name": "value_from", "type": "uint256"},
                    {"name": "token_to", "type": "address"},
                    {"name": "value_to", "type": "uint256"},
                ]
            },
            "primaryType": "Root",
            "domain": {
                "name": "test",
                "version": "1",
                "verifyingContract": "0x0000000000000000000000000000000000000000",
                "chainId": 1,
            },
            "message": {
                "token_from": "0x1111111111111111111111111111111111111111",
                "value_from": web3.Web3.to_wei(3.65, "ether"),
                "token_to": "0x2222222222222222222222222222222222222222",
                "value_to": web3.Web3.to_wei(15.47, "ether"),
            }
    },
    
    'filters': {
            "name": "Token not in CAL test",
            "tokens": None,
            "fields": {
                "token_from": {
                    "type": "amount_join_token",
                    "token": 0,
                },
                "value_from": {
                    "type": "amount_join_value",
                    "name": "From",
                    "token": 0,
                },
                "token_to": {
                    "type": "amount_join_token",
                    "token": 1,
                },
                "value_to": {
                    "type": "amount_join_value",
                    "name": "To",
                    "token": 1,
                },
            }
    }
}


advanced_trusted_name_test_data = {
    'data': {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
                "Root": [
                    {"name": "validator", "type": "address"},
                    {"name": "enable", "type": "bool"},
                ]
            },
            "primaryType": "Root",
            "domain": {
                "name": "test",
                "version": "1",
                "verifyingContract": "0x0000000000000000000000000000000000000000",
                "chainId": 1151668124,
            },
            "message": {
                "validator": "0x1111111111111111111111111111111111111111",
                "enable": True,
            }
    },
    
    'filters': {
            "name": "Trusted name test",
            "fields": {
                "validator": {
                    "type": "trusted_name",
                    "name": "Validator",
                    "tn_type": None,
                    "tn_source": [InputData.TrustedNameSource.CAL],
                },
                "enable": {
                    "type": "raw",
                    "name": "State",
                },
            }
    }
}

TRUSTED_NAMES = [
    (InputData.TrustedNameType.CONTRACT, InputData.TrustedNameSource.CAL, "Validator contract"),
    (InputData.TrustedNameType.ACCOUNT, InputData.TrustedNameSource.ENS, "validator.eth"),
]

FILT_TN_TYPES = [
    [InputData.TrustedNameType.CONTRACT],
    [InputData.TrustedNameType.ACCOUNT],
    [InputData.TrustedNameType.CONTRACT, InputData.TrustedNameType.ACCOUNT],
    [InputData.TrustedNameType.ACCOUNT, InputData.TrustedNameType.CONTRACT],
]