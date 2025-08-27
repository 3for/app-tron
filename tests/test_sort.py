from typing import Any, Dict, List, Union

def sort_object_alphabetically(obj: Union[Dict[str, Any], List[Any]]) -> Union[Dict[str, Any], List[Any]]:
    if isinstance(obj, dict):
        sorted_obj: Dict[str, Any] = {}
        for key in sorted(obj.keys()):
            value = obj[key]
            if isinstance(value, list):
                value = [
                    sort_object_alphabetically(v) if isinstance(v, dict) else v
                    for v in value
                ]
                # 如果是对象数组，按 "name" 排序
                value.sort(key=lambda x: str(x.get("name")) if isinstance(x, dict) else "")
            sorted_obj[key] = value
        return sorted_obj

    elif isinstance(obj, list):
        return [
            sort_object_alphabetically(v) if isinstance(v, dict) else v
            for v in obj
        ]

    return obj

def test_sort_object_alphabetically():
    obj = {
        "Transfer": [
            {"name": "value_recv", "type": "uint256"},
            {"type": "address", "name": "with"},
            {"name": "token_send", "type": "address"},
            {"name": "value_send", "type": "uint256"},
            {"name": "token_recv", "type": "address"},
            {"name": "expires", "type": "uint64"},
        ],
        "EIP712Domain": [
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "name", "type": "string"},
            {"type": "address", "name": "verifyingContract"},
        ],
    }

    expected_obj = {
        "EIP712Domain": [
            {"name": "chainId", "type": "uint256"},
            {"name": "name", "type": "string"},
            {"name": "verifyingContract", "type": "address"},
            {"name": "version", "type": "string"},
        ],
        "Transfer": [
            {"name": "expires", "type": "uint64"},
            {"name": "token_recv", "type": "address"},
            {"name": "token_send", "type": "address"},
            {"name": "value_recv", "type": "uint256"},
            {"name": "value_send", "type": "uint256"},
            {"name": "with", "type": "address"},
        ],
    }

    assert sort_object_alphabetically(obj) == expected_obj
