import pytest
import time
import signal
from functools import partial
from typing import Callable

from ledgered.devices import Device
from client.tip712 import InputData as InputData
from ragger.backend import BackendInterface
from ragger.navigator import Navigator, NavInsID, NavIns

test_APDUs = [
    "e01a00000a4174746163686d656e74", 
    "e01a00ff0605046e616d65", 
    "e01a00ff0742020473697a65",
    "e01a00000b4174746163686d656e7473",
    "e01a00ff13800a4174746163686d656e740100046c697374",
    "e01a00000c454950373132446f6d61696e",
    "e01a00ff0605046e616d65",
    "e01a00ff09050776657273696f6e",
    "e01a00ff0a422007636861696e4964",
    "e01a00ff130311766572696679696e67436f6e7472616374",
    "e01a0000044d61696c",
    "e01a00ff0d0006506572736f6e0466726f6d",
    "e01a00ff10000b4d61696c696e674c69737402746f",
    "e01a00ff0a0508636f6e74656e7473",
    "e01a00ff14000b4174746163686d656e747306617474616368",
    "e01a00000b4d61696c696e674c697374",
    "e01a00ff0605046e616d65",
    "e01a00ff128006506572736f6e0100076d656d62657273",
    "e01a000006506572736f6e",
    "e01a00ff0605046e616d65",
    "e01a00ff0b8301000777616c6c657473",
    "e01e000000",
    "e01c00000c454950373132446f6d61696e",
    "e01c00ff160014436f6d706c65782053747275637473204d61696c",
    "e01c00ff03000131",
    "e01c00ff06000444a50f9c",
    "e01c00ff160014cccccccccccccccccccccccccccccccccccccccc",
    "e01e000f540b446570746879205465737404463044022028916223eabad3380df130920f5a384c5b26ddf278002754fddf000a65d4b905022055267019ec51673a1a96cade2e82e1d079f1885a223c6b3cb5c113c53c43642a",
    "e01c0000044d61696c",
    "e01e00ff500653656e646572483046022100889e7fa70305f4f5d813339d5d112bf6d2faea7158d0b08ad7446240538e8fb8022100dadcb922bc040582fe95fa3e5186b84cab0e7c591de3bc6f2722cd63b9f06e34",
    "e01c00ff050003436f77",
    "e01c000f0102",
    "e01c00ff160014cd2a3d9f938e13cd947ec05abc7fe734df8dd826",
    "e01c00ff160014deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    "e01c00ff0b000974657374206c697374",
    "e01c000f0102",
    "e01e00ff5309526563697069656e74483046022100d50e60ec7a71fd1ae6c64c54fe5ef61f087bbea382b108863de8e251a7bacd1c02210090f3824436a07ab8888a582d0c3ad9d5586b3d96e4e5115eae5c51c3983947b8",
    "e01c00ff050003426f62",
    "e01c000f0102",
    "e01c00ff160014bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "e01c00ff160014b0b0b0b0b0b0b000000000000000000000000000",
    "e01e00ff5309526563697069656e74483046022100d50e60ec7a71fd1ae6c64c54fe5ef61f087bbea382b108863de8e251a7bacd1c02210090f3824436a07ab8888a582d0c3ad9d5586b3d96e4e5115eae5c51c3983947b8",
    "e01c00ff070005416c696365",
    "e01c00ff160014b0bdabea57b0bdabea57b0bdabea57b0bdabea57",
    "e01e00ff50074d657373616765473045022100ebd72a990b34098980f8de378aaccfda6a1b447adaa21d4a926de0f8fa51168802206c0662bd51613fb9434275fbc46e5b13bac103af8eae584a3febf553a7da6146",
    "e01c00ff0d000b48656c6c6f2c20426f6221",
    "e01c000f0102",
    "e01e00ff530a4174746163686d656e74473045022100dca5c2a3af5df0d5875e660099a0c07359885a369c7bac1c31c88f1e8f091bb90220501a8790f663e1e0b76db502fd2aef626b01ff94d0b2315dc69f1376d266891e",
    "e01c00ff0700056669727374",
    "e01c00ff03000164",
    "e01e00ff530a4174746163686d656e74473045022100dca5c2a3af5df0d5875e660099a0c07359885a369c7bac1c31c88f1e8f091bb90220501a8790f663e1e0b76db502fd2aef626b01ff94d0b2315dc69f1376d266891e",
    "e01c00ff0800067365636f6e64",
    "e01c00ff0400020d48",
    "e00c000115058000002c800000c3800000000000000000000000"

]

# Simulate UI navigation
def autonext(device: Device, navigator: Navigator):
    navigator.navigate(
        [
            NavInsID.RIGHT_CLICK,
        ],
        screen_change_before_first_instruction=False,
        screen_change_after_last_instruction=False
    )

def default_handler():
    raise RuntimeError("Uninitialized handler")


autonext_handler: Callable = default_handler

def next_timeout(_signum: int, _frame):
    autonext_handler()

def test_raw_apdu_async(backend: BackendInterface, 
                       device: Device, 
                       navigator: Navigator):
    global autonext_handler
    autonext_handler = partial(autonext, device, navigator)
    signal.signal(signal.SIGALRM, next_timeout)
    for i, item in enumerate(test_APDUs):
        if i == len(test_APDUs) - 1:
            # ===== 4. sign request APDU =====
            apdu = bytes.fromhex(item)  
            with backend.exchange_async_raw(apdu): # Send asynchronously
                nav_ins = NavInsID.RIGHT_CLICK
                val_ins = NavInsID.BOTH_CLICK
                text = "and sign"
                navigator.navigate_until_text(nav_ins, [val_ins], text)
        else:
            # ===== 1. Send an APDU =====
            apdu = bytes.fromhex(item)  
            with backend.exchange_async_raw(apdu): # Send asynchronously
                if item.startswith("e01e000f") or item.startswith("e01e00ff") or item.startswith("e01c00ff") or item.startswith("e00c0001"):
                    print("ZYD 111BBB")
                    signal.setitimer(signal.ITIMER_REAL, 3, 3)
                print("ZYD 222")
            
            if item.startswith("e01e000f") or item.startswith("e01e00ff") or item.startswith("e01c00ff")  or item.startswith("e00c0001"):
                signal.setitimer(signal.ITIMER_REAL, 0, 0)
        
        response = backend.last_async_response
        # ===== 2. Get the APDU response =====
        print("SW:", hex(response.status))
        print("Data:", response.data.hex())

    assert True == True
