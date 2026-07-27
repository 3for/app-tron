"""
P1 skeleton for Generic Clear Signing (generic_tx_parser) on app-tron.

Pipeline under test:

    0xC4 (P2=STORE)  -> stream TriggerSmartContract, park EVM calldata + tx_ctx
    0x26 TX_INFO     -> CAL-signed descriptor (selector + fields_hash commitment)
    0x28 FIELD x N   -> per-field render rules; running hash must equal fields_hash

`test_gcs_store_parks_calldata` exercises only the 0xC4/P2=STORE bridge, which
returns 0x9000 once the calldata is parked.

`test_gcs_p1_end_to_end` drives the full skeleton: STORE -> 0x26 -> 0x28(raw) and
asserts the firmware validates the running fields_hash. The serialization mirrors
the app-ethereum GCS contract (the same Ledger backend / CAL key) verbatim:

  * TX_INFO struct hash  : SHA-256 over every tag except 0xFF, verified against the
                           CALLDATA PKI public key (CERTIFICATE_PUBLIC_KEY_USAGE_CALLDATA).
  * fields_hash          : SHA3-256 (NIST, cx_sha3_init(...,256)) over the raw bytes
                           of each 0x28 FIELD payload -- NOT keccak256.
  * signature            : SECP256K1 over the struct hash, signed with the CALLDATA
                           test key (keychain/calldata.pem); TronClient loads the
                           matching CALLDATA PKI certificate.
"""
import sys
import hashlib
import json
from pathlib import Path
from struct import pack
from typing import Optional

import pytest
from web3 import Web3

from client.command_builder import (CLA, MAX_APDU_LEN, InsType, P1Type, P2Type)
from client.enum_value import EnumValue
from client.gating import Gating
from client.proxy_info import ProxyInfo
from client.gcs import (ContainerPath, DataPath, DatetimeType, Field, ParamAmount,
                        ParamCalldata, ParamDatetime, ParamEnum, ParamRaw,
                        ParamNetwork, ParamNFT, ParamToken, ParamTokenAmount,
                        ParamTrustedName, ParamType, PathLeaf, PathLeafType,
                        PathRef, PathTuple, TxInfo, TypeFamily, Value,
                        VisibleType)
from client.trusted_name import TrustedName, TrustedNameSource, TrustedNameType
from client.tlv import eth_to_tron_base58
from fields_utils import (get_all_paths, get_all_tuple_array_paths,
                          get_all_tuple_paths)
from gcs_utils import ABIS_FOLDER, compute_inst_hash
from ragger.error import ExceptionRAPDU
from ragger.backend import BackendInterface
from ragger.bip import pack_derivation_path
from ragger.navigator.navigation_scenario import NavigateWithScenario
from client.status_word import StatusWord
from settings import SettingID, settings_toggle
from tron import TRON_MAINNET_ADDRESS_PREFIX, TronClient
from utils import (check_tx_signature, get_challenge, get_selector_from_data,
                   to_sun, to_units)

PROTO_PATH = str(Path(__file__).resolve().parents[2] / "proto")
if PROTO_PATH not in sys.path:
    sys.path.insert(0, PROTO_PATH)
from core import Contract_pb2 as contract
from core import Tron_pb2 as tron

# --- APDU constants (mirror src/apdu_constants.h) ---------------------------
P1_FIRST = P1Type.FIRST
P1_SIGN = P1Type.SIGN
P1_MORE = P1Type.MORE
P1_LAST = P1Type.LAST
P2_GCS_STORE = P2Type.GCS_STORE
P2_GCS_START_FLOW = P2Type.GCS_START_FLOW

# TRON mainnet chain id used by the GCS descriptors (chain_config.h).
TRON_MAINNET_CHAINID = 728126428
# A simple TRC20 `transfer(address,uint256)` call: selector + 2 ABI words.
TRC20_CONTRACT_B58 = "TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16"
# Same contract as a 20-byte TVM address (0x41 mainnet prefix stripped), i.e.
# `base58check_decode(TRC20_CONTRACT_B58)[1:]` -- the form generic_tx_parser (and a
# gating descriptor) matches against.
TRC20_CONTRACT_ADDR20 = bytes.fromhex("14183f3bbca4ae9fc1de55b9bbe2d071942dc1a6")
TRC20_TRANSFER_SELECTOR = bytes.fromhex("a9059cbb")
TRC20_TRANSFER_CALLDATA = bytes.fromhex(
    "a9059cbb"
    "000000000000000000000000364b03e0815687edaf90b81ff58e496dea7383d7"
    "00000000000000000000000000000000000000000000000000000000000f4240")
BATCH_CONTRACT20 = bytes.fromhex("2cc8475177918e8c4d840150b68815a4b6f0f5f3")
# A deliberately over-long calldata for the streaming-decode test (see
# test_gcs_long_calldata). Shielded-mint signature, ~1 KB:
#   mint(uint256 rawValue, bytes32[9] output, bytes32[2] bindingSignature, bytes32[21] c)
# Mirrors dev_app-plugin-boilerplate's test_long_mint.py MINT_CALLDATA.
MINT_CONTRACT_B58 = "TNnFMMykZzwhPZkurKtNMyVGvgeSkCrnPi"
MINT_CALLDATA = bytes.fromhex(
    "855d175e"
    "0000000000000000000000000000000000000000000000003782dace9d900000"
    "432464fe1e9c33eaf99edad710ef11359d0291506bc81f7445f1447ba112ab18"
    "30579dd4decdd0ed38f33215375c00e1fb324f0f35892991aa0b8f5eb2a9dfcb"
    "1533ca563b77de5177a41e8ffefb2fd688334af95bcd1143470318c026b00e2e"
    "86227c50592880dd3f0c362258714e50b9b9d54eb193b0bba6cc04cf348d841d"
    "55261810658d9eeaeb2920005179f9e099c9eaf06c793ccc3ec2f30c8f52d939"
    "4d0f6084bc53f142663d713f6ef575db86b0c55abfe9aacf6515bb0a5986a0b2"
    "14bc1c48c9678906c88a4c625336b8d8a9be49d1ec75762bb60338f738ad9989"
    "1b98ce18c723e76e70f53dce7c03b247aa937354a6954feac4f8858ae5830b3c"
    "fc0466421864b2ffc5740dc19210e691d5d4fccf9a3e7d1f4ef6e2a676975dec"
    "cd63c5990d8275dc35d0922be3bd5dc7c4a81494e8276b282e61a19fbe9cca05"
    "32592b05623b7bffee09ef81fb298cbaf4ece9c42fe5ac80a716e90c7dff7f01"
    "2c1215f739c89e715ffab693eff699b5eb6368753af0c0087274db0f14c38ce7"
    "b0b36100f9a2f51cc7f6eca87eb750544f9fbe18ea79dbd8595028c4d33da6ee"
    "62afe4eca52cfe40f164f00063abe1c76e3d0fc0af2db17aad96b3f472d41f0b"
    "56d8dd4fa5b9d6de028678731425871cbf134701c351aba7edeaad07e8d40060"
    "1e245bc1751ebb514365c774e5108c348a39533e836a10338ab8ae00ceb0f819"
    "f3f45268ee88bdf9fdadf6c921269d707fe457fa25d6997a5da382ac8b4f960a"
    "381ab539c33421931569785dbe6dfa59914ca6bc597576e9e33314eb62326658"
    "c8548c22622f3a9a06b3fe40842210018bedbda8e95662a2a7bb1db9121e39bc"
    "c2f6d004c9b7cf5131d3989a32a3ade8c447d34b4244841a0cb071efdd7ed68e"
    "7c02d1aeadbda9ab1f6e5f3f2b0227e07a8d5e30418e354f000329f12f4462aa"
    "c4db0dbd034e85ed9b3dc2cac483c41bdfa690fefacfc038dd20067b1e8dc1e7"
    "72e1c719ad4e6b14c87c779b4477daa5edb47a5218ad5d4afb6983d460aa012e"
    "6415ac67135a9f9cb438ca9f9655fd2dfd44a43785d2eb7e8b4d77e81573f7f0"
    "2355f114601e9909793ec437d9d2257512c799c0ee769876bb98842995d73468"
    "e1a81ef9c8dc5e6702179d25632cfe8ec8214b76b6bceab5741ade28f5fa10ff"
    "a72abfcfaffb7e8224fc89fe65a2c440fa9a291e974f366ec5c87302e86d1df7"
    "4b73396f5e35030106dcc9ac54f20557a58dabba7975decbce146536f4a1b13d"
    "71f549e7b7d8c5e61b3c92118dbf0f6dacd09a24f3514d1642f711d02b6c29d4"
    "7f5d3f4a2b7c66dd941eb9f02ba311a72c00f449a837767c5d71e99414c84cf9"
    "e8c37ef731efaaa8266cdd309311615aea396f264389fe115abb0a1967a9af14"
    "b972f20d8bf31550d9c4e67366161b5546b58003000000000000000000000000")
MINT_SELECTOR = MINT_CALLDATA[:4]

# Shielded `transfer(bytes32[10][] input, bytes32[2][] spendAuthoritySignature,
# bytes32[9][] output, bytes32[2] bindingSignature, bytes32[21][] c)` -- all dynamic
# arrays, so (like the boilerplate plugin's SHIELDED_TRANSFER) there is no scalar value
# to show; the GCS descriptor carries no fields, only the contract/intent header.
# Same contract as MINT_CONTRACT_B58. See dev_app-plugin-boilerplate/test_long_transfer.py.
SHIELDED_TRANSFER_SELECTOR = bytes.fromhex("9110a55b")
SHIELDED_TRANSFER_CALLDATA = SHIELDED_TRANSFER_SELECTOR + bytes.fromhex(
    "00000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000"
    "0000000000000000000000000000000000000220000000000000000000000000000000000000000000000000"
    "0000000000000280ce6afaf724f66efac204f6368123fcd2ef6ab565477400bab70e39ca68a581b94fc11db9"
    "de0f6951270d3fd7bea878fe4bad59f126fe446b33a66bfc8af3f70600000000000000000000000000000000"
    "000000000000000000000000000003c000000000000000000000000000000000000000000000000000000000"
    "00000001951e4c9456e7dbeed6831cd60b75d4727badc33e03bb08ab0ada011b9213747ac26c3206afaba02c"
    "8454263eb9bb6c9e2506704995b4e41989f9f47550045e5b616035300ff5e029ccdebfe596d4723f370b85e6"
    "88e21aacd6083e6139af5ca175efb6b823520d481440d1474b5b6f5bc2d1d534a7763ac5a688d2d1ec529898"
    "a040447b31a528060bcc561cc2a8d7adc6f726a6f6c7d6f03bab88d21af12f3b97a48b52da15c01cd5043b32"
    "f21d3454a742654aa4985072c9cedb8934a65c30d6e373e104e428b80c966dad68d28a5440d8f09e629009e2"
    "ca43774a7307e01e112691a20dedb4f79c182531ced0a5dce04b5e78836425d5ecf45d8fe5221b6da53d6f10"
    "ea310afd1d16184e502d00e3b1c43f91a2bf21c5a003fe9f106a51fc861ef502b01e82c6df897ae4786645db"
    "8f4f6a453be039f6bfaaf501ecaacf9200000000000000000000000000000000000000000000000000000000"
    "000000016ce9d10243a28f900cf2d2b5e9bec5cb3615ce2fa36e5e16050cb81865ae43b874e74feb01c94b3d"
    "282e46e39e615431a2aed82c10dc26cfb6f6e0227c2503050000000000000000000000000000000000000000"
    "000000000000000000000001233c627d5b726522420f072681c0905e3b13bfc68605a74eee2cc9b55acb2350"
    "7ae1e689515ff7301f3777ce11378b17c86ec6a443c79def76bd9eca613aa4b3b96780a9e19627cedf75b2a3"
    "c3bd3f4dda950fcec42e63f1696f12928ce1638b94f265307618c4dce68bd992e21fee80083870faca0ccbfd"
    "e2b32689327d37e1564f4c58eb9aaf87777c42a238569cb7b9aeae4478650121c0913b41319b165000eb0e88"
    "da3a041242f9c5961ae8367df889dd8018053f1cea342524b606467202635eafe3eb084a530bf024151c27be"
    "783662c9d29de7ea03d2ad8d8b39fec98348addd026f862ff9d06bebf0ad75a097f9a82d5bb1965d8fc3f7ca"
    "01688bf7e3f84b206fbab3baab8f9a9bf5b240e3726bf5293d7a862bd511fc80b0e1bf380000000000000000"
    "000000000000000000000000000000000000000000000001e47864bd06637a361b0567f911da6a3d6fb1eb78"
    "8b2348b90edf9d76b2906e59fc6a8923bfe76b1eb541170b85b9ff923d8da00deeefd5a2a93d1243845de484"
    "7712504f32927f792a1c81de64cc4e05d79882f80eccad69e2b0152470fdf65a5e0ee20e1d6c84e992267cb0"
    "931eb2c4f42eb95c1cdee9ee12da86f2d3e8da644df188bf81507da1409d3aef51dd7b3408bdb787acc9baae"
    "eb91b23d11727e6e111489852685aa809d97d6b066f73c54e88540e0fadacf3a7cae30c5f94527e485a1e324"
    "9f7bc3a82f80dc815f3a9172e61bc1bdd57de58826856957e989048f185bf6dcdd2b508b5761fb34c603df7a"
    "cb997ead52a5c6194c9bae77851f87fc4d0eb504e1c0b9dfd1a0f9c5593b5cf766eb00743043ca8441577c84"
    "536c7d9dc9203ff8911c1020f553c57ba34f59a7f3270eca785ca4a33c60f8df19fcbeab6c757093b4c89e18"
    "6c9956d9e3ee7610537f590bfb740fa1f544d4b797a0dd8a578817c41770ac0627ff4c8b4be7061a11768227"
    "5a5e38c9509c6deaa48929c908efb32d8a430c780d319157a24f020afad022494d72345ff64c3620afb6a0e6"
    "70dd4641b182ac97bd79b8052b97cefb0f1f5a8c6e26f0dea53c4a79cc4965fcddf3bf7d1b726c717d5ec1ee"
    "aca9b07ba83f0cd209f59bb35ccb59127919fcf080a1c04b63683e7159d78bb419cc84df6adf1849130e602d"
    "114ff54bf6b6e11544f17959af97cc83a16aa734ff740300538739e10dac20c7c4af8ddfef14d4f8e786162b"
    "5efbe9975acfa3cf13bf17c4c1857ef12858a5db6186570570b0a33368aa026221933e96c83d173937ef3703"
    "acea5c1cde95de19fbb9b46fdb0ed9a7395caad66ad89ec3f3a5ff35d5c49decaffbb34e9d5f05275139c15d"
    "bfd4b54d5f9284afea671fc7c913ad6097dc9ff021daf4a7000000000000000000000000")

# Shielded `burn(bytes32[10] input, bytes32[2] spendAuthoritySignature, uint256 rawValue,
# bytes32[2] bindingSignature, address payTo, bytes32[3] burnCipher, bytes32[9][] output,
# bytes32[21][] c)` -- the head's fixed arrays push `rawValue` to calldata word 12 (10 +
# 2). Like the boilerplate's SHIELDED_BURN, show `rawValue` as a token amount + the
# contract. See dev_app-plugin-boilerplate/test_long_burn.py.
SHIELDED_BURN_SELECTOR = bytes.fromhex("cc105875")
# 0x41-prefixed mainnet address; strip the prefix for generic_tx_parser (20-byte form).
SHIELDED_BURN_CONTRACT20 = bytes.fromhex("8C8705769E5ec53F5F9C42A3bc3305624AD37192")
SHIELDED_BURN_RAW_VALUE_WORD = 12
# payTo (address) sits after rawValue + bindingSignature[2]: word 12 + 1 + 2 = 15.
SHIELDED_BURN_PAY_TO_WORD = 15
SHIELDED_BURN_CALLDATA = SHIELDED_BURN_SELECTOR + bytes.fromhex(
    "411fcd54cea8939bd45b9ad7b2c0001872eb50903f8e6e063bd6d46aff890206afa8e0e221d5997d57547d76"
    "66a7c2f776317b2a2906c58055551972622a7d6fc9074c2907d279a4e6cf6d5c7098516b338564c554010876"
    "05e2b1f554f146d83c71fc1792c27f464fc1c5a7dfe0a6806cc6921cef46a41008de6a18e78dfee7a0e0f3ec"
    "e3fd4d7a3db027e11c3fa8f58346539502eb9dd17db76fd60f79657303b95dcfa2e2e8bc069a793fc71d501d"
    "a737ff5deee54e1f659f1fda4ce5428c18b3cca5f816ef3308dd3d2bf323de1bd361183d829ebd21b3198c30"
    "6d30176506efba80a1a341ea8eae32d3f263294b5cd48e16a7f481230c83cb0fa198718fba949736aba6e1b7"
    "cfcffbb7aca62624867e948c97cda7e4e4b0038bd51933bed2d56ff884d4ac7c12e8fb3a84ccddb6f3830b36"
    "424ac2f1c09b2ed784d2208cb8dfa7a9aa61016cc74876572938c48edd9ae4e9061501db182991030596aca5"
    "791900aba9c4dfb97f1ebb328f27b7d470e90aa4d7c56ad2184abb4c45b1f408000000000000000000000000"
    "00000000000000000000000029a2241af62c00000423e07a9c2e1f4bc5192f5dc42e413e508cc85bbd4bdfb5"
    "1022c626e890cadedf7737598997f77d9639ca3764f56e54950f6e4dc3148c3bf585135af1108f0200000000"
    "000000000000004119580b8d292f590d254ab037320975ab367891945d4188e801642649a5d69f6ba4a174aa"
    "57b97410d5a2ba17c7dae76462b3e1e23e3007946b5f21510ed860e048e638a6dbd76c5670b753b83383962e"
    "b486e693e92fbbdc97a835c02a93c33030a888f5000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000002a00000000000000000000000000000000000000000"
    "0000000000000000000003e00000000000000000000000000000000000000000000000000000000000000001"
    "f4f835357d8ca230e33488f80c83bacc79bc234333d60b5a73c1a8e5255b336263861fb9e1882c9be89afe4f"
    "7c5529c87e38c8aa5da2a663dddce5d620f786247ff151f8bcca7cc3c968a18fab7ea8f291263356ad18a45a"
    "b37d6235689be33aa7a0d63bb0247c9b8fa870f496ced81c1096e7a35f171d10b704f098e91d6be554f8248b"
    "86566c5a6f66af4cca0b9557a1a11a6aaa8d054f644dbcba9a77ada5e245870d23f1ee4e29c1063507bbba52"
    "6a596b93930fb5d8ae6895bace0818430e75585a8a655b342c2c9239675c95a54cabdd83d1590aa62acf3b47"
    "86648d94084084484f19496a722eb387b24599a688126cfc46dc75a8872e923add73763c74369413a73b9ce2"
    "0c44bfba051ebfd43bd075b1ca5d1eb11568a0721b8a63280000000000000000000000000000000000000000"
    "000000000000000000000001ff387be3765524f0b6ebb5552402188980d16e63559fc62f7b7e89720b213121"
    "ba385494a87c778d5c2ccd745888321f882658c2e26687ead9b21f46f3c7364388ed7c63ecb1aa66fe86e036"
    "ad2b40d2a1df90fa0c7a81aa24bd9e6010231e2d94a874954245fd48bbe6521933fef5f8bd78ae07dea625eb"
    "b2c0273cde2b1acf7f07883e5f4f05fb70b3f1b45735addcdf9410c81444d0575d177c5a5676b44c666948ce"
    "09cac6a1ea0d5710652f0ce31d372648b874f64ba487579a0045b4b44949a9fa1a22fc949c3cad5da1c334ee"
    "25d5357ae41dad9ed54e6433c5ba2d31101f652e992c7e922e1fd40ba9221a0c53c54eb89c49c68395eb61e1"
    "b489882759a788a4ea383167950e3adc80ebd3bbea11b490d402a64634006cd10170ad84cbb34c6c4a239df3"
    "3b962fb4dedd62fefc1c03089a5481da96f6e09c47c5197ea58dfd3193cde8e9e3acf4fa74beefca94df5bf9"
    "c99dacfc298e14cab2360a10f7d76a77ecc4471d513be5262a7ffe52177c11ba24e626cbc33e12cddbf02bb4"
    "2d80aabcd86e03fd4f733ede78a9682842803605a924b99cd1048984a4131780935d70975f99c5685445e1d3"
    "345cb4848e4fc68df984049cf5abd02abb5525c8df5870797d8a0905ecff4f37b9f0e1d25ae99c6d31174983"
    "0208f7c2cb47043afc1dc44c9f2dbdbeeb54e352d77ab5b629917b659f7e69e91521577ae1b3c7aff99ed318"
    "48ea7302e07cff9851213bda670cd6c895bbeb37a991ca09d2debe034fb37e1a0aa791323217790f72cde2d4"
    "1c1f5e32878253d8b0f5db896a22a6ab2437c5f8d126e7505412a109939ccdd634cc04993a197725d0b8e2f4"
    "350f3d041199c9b6d7756a863afa9793293b25ff17d2472499b64f321c4e9fecf4fcee7e79ba7e62fe2c3dc0"
    "34d381f7d65c9d310349a8e4000000000000000000000000")

# Proxy fixtures shared with test_gcs_proxy / the proxied gating test: a
# `transferOwnership(address)` call whose TO is the proxy but whose descriptor
# (and gating descriptor) targets the implementation behind it.
PROXY_ADDR20 = bytes.fromhex("39053d51b77dc0d36036fc1fcc8cb819df8ef37a")
PROXY_IMPL_ADDR20 = bytes.fromhex("1784be6401339fc0fedf7e9379409f5c1bfe9dda")
# keccak256("transferOwnership(address)")[:4]
TRANSFER_OWNERSHIP_SELECTOR = bytes.fromhex("f2fde38b")


@pytest.fixture(name="tron_client")
def tron_client_fixture(backend: BackendInterface) -> TronClient:
    return TronClient(backend)


def build_trc20_transfer_tx(client: TronClient) -> bytes:
    return client.packContract(
        tron.Transaction.Contract.TriggerSmartContract,
        contract.TriggerSmartContract(
            owner_address=bytes.fromhex(client.getAccount(0)["addressHex"]),
            contract_address=bytes.fromhex(client.address_hex(TRC20_CONTRACT_B58)),
            data=TRC20_TRANSFER_CALLDATA))


def build_trigger_smart_contract_tx(client: TronClient,
                                    contract_addr20: bytes,
                                    calldata: bytes) -> bytes:
    return client.packContract(
        tron.Transaction.Contract.TriggerSmartContract,
        contract.TriggerSmartContract(
            owner_address=bytes.fromhex(client.getAccount(0)["addressHex"]),
            contract_address=bytes([TRON_MAINNET_ADDRESS_PREFIX]) + contract_addr20,
            data=calldata))


def gcs_store_calldata(client: TronClient, backend: BackendInterface, path: str,
                       tx: bytes) -> int:
    """Stream a TriggerSmartContract through INS_SIGN_GCS (0xD4) with P2=GCS_STORE.

    The firmware parks the calldata into the generic_tx_parser context and waits for
    the 0x26 / 0x28 descriptors; no UI is shown. Returns the final status word.
    """
    data = bytearray(pack_derivation_path(path))
    data += pack(">I", len(tx))  # include_tx_len
    max_first = MAX_APDU_LEN - len(data)
    assert max_first >= 0
    data += tx[:max_first]
    rest = tx[max_first:]

    messages = [bytes(data)]
    while rest:
        messages.append(rest[:MAX_APDU_LEN])
        rest = rest[MAX_APDU_LEN:]

    for i, msg in enumerate(messages[:-1]):
        p1 = P1_FIRST if i == 0 else P1_MORE
        backend.exchange(CLA, InsType.SIGN_GCS, p1, P2_GCS_STORE, msg)
    # The last chunk must trigger the GCS finalize so the firmware registers the
    # parked calldata as the root tx context and enters APP_STATE_SIGNING_TX.
    # P1_LAST finalizes a multi-chunk stream; a single chunk must use P1_SIGN,
    # which both initializes *and* finalizes in one APDU (sign_gcs.c).
    p1 = P1_SIGN if len(messages) == 1 else P1_LAST
    return backend.exchange(CLA, InsType.SIGN_GCS, p1, P2_GCS_STORE,
                            messages[-1]).status


def test_gcs_store_parks_calldata(tron_client: TronClient,
                                  backend: BackendInterface):
    """0xC4/P2=STORE on a TRC20 transfer parks the calldata and returns 0x9000."""
    tx = build_trc20_transfer_tx(tron_client)
    status = gcs_store_calldata(tron_client, backend,
                                tron_client.getAccount(0)["path"], tx)
    assert status == StatusWord.OK


@pytest.mark.parametrize("case", ["invalid_path", "missing_total_length"])
def test_gcs_store_initialization_error_resets_state(backend: BackendInterface,
                                                     case: str):
    client = TronClient(backend)
    if case == "invalid_path":
        payload = b"\x00"
        expected_status = StatusWord.INCORRECT_BIP32_PATH
    else:
        payload = pack_derivation_path(client.getAccount(0)["path"]) + b"\x00" * 3
        expected_status = StatusWord.INCORRECT_LENGTH

    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(CLA, InsType.SIGN_GCS, P1_FIRST, P2_GCS_STORE, payload)
    assert e.value.status == expected_status

    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(CLA, InsType.SIGN_GCS, P1_MORE, P2_GCS_STORE, b"\x00")
    assert e.value.status == StatusWord.CONDITION_NOT_SATISFIED


def test_gcs_invalid_tx_info_resets_state(backend: BackendInterface):
    client = TronClient(backend)
    tx = build_trc20_transfer_tx(client)
    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], tx) == StatusWord.OK

    # One-byte TLV payload containing an invalid structure.
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(CLA,
                         InsType.PROVIDE_TRANSACTION_INFO,
                         P1Type.FIRST_CHUNK,
                         0x00,
                         b"\x00\x01\xff")
    assert e.value.status == StatusWord.INVALID_DATA

    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(CLA, InsType.SIGN_GCS, P1_FIRST,
                         P2_GCS_START_FLOW, b"")
    assert e.value.status == StatusWord.CONDITION_NOT_SATISFIED


@pytest.mark.parametrize("case", [
    "oversized_calldata",
    "negative_call_value",
    "negative_token_value",
    "negative_token_id",
    "token_value_without_id",
    "reserved_token_id",
    "minimum_reserved_token_id",
    "negative_fee_limit",
])
def test_gcs_rejects_invalid_trigger_values(backend: BackendInterface,
                                            case: str):
    client = TronClient(backend)
    trigger = contract.TriggerSmartContract(
        owner_address=bytes.fromhex(client.getAccount(0)["addressHex"]),
        contract_address=bytes.fromhex(client.address_hex(TRC20_CONTRACT_B58)),
        data=(b"\xa9\x05\x9c\xbb" + b"\x00" * 4093)
        if case == "oversized_calldata" else TRC20_TRANSFER_CALLDATA,
    )
    fee_limit = None
    if case == "negative_call_value":
        trigger.call_value = -1
    elif case == "negative_token_value":
        trigger.call_token_value = -1
        trigger.token_id = 1_000_001
    elif case == "negative_token_id":
        trigger.token_id = -1
    elif case == "token_value_without_id":
        trigger.call_token_value = 1
    elif case == "reserved_token_id":
        trigger.token_id = 1
    elif case == "minimum_reserved_token_id":
        trigger.token_id = 1_000_000
    elif case == "negative_fee_limit":
        fee_limit = -1
    tx = client.packContract(tron.Transaction.Contract.TriggerSmartContract,
                             trigger,
                             fee_limit=fee_limit)

    with pytest.raises(ExceptionRAPDU) as error:
        gcs_store_calldata(client, backend, client.getAccount(0)["path"], tx)
    assert error.value.status == StatusWord.INVALID_DATA


@pytest.mark.parametrize("call_token_value", [0, 1])
def test_gcs_accepts_mainnet_trc10_trigger_values(backend: BackendInterface,
                                                  call_token_value: int):
    client = TronClient(backend)
    trigger = contract.TriggerSmartContract(
        owner_address=bytes.fromhex(client.getAccount(0)["addressHex"]),
        contract_address=bytes.fromhex(client.address_hex(TRC20_CONTRACT_B58)),
        data=TRC20_TRANSFER_CALLDATA,
        call_token_value=call_token_value,
        token_id=1_000_001,
    )
    tx = client.packContract(tron.Transaction.Contract.TriggerSmartContract,
                             trigger)

    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], tx) == StatusWord.OK


def test_gcs_accepts_maximum_incompressible_root_and_cleans_budget(
        backend: BackendInterface):
    """The 4096-byte root ceiling must still fit after tracked headers."""
    client = TronClient(backend)
    pattern = bytes(range(1, 256))
    calldata = b"\xa9\x05\x9c\xbb" + (pattern * 17)[:4092]
    assert len(calldata) == 4096
    trigger = contract.TriggerSmartContract(
        owner_address=bytes.fromhex(client.getAccount(0)["addressHex"]),
        contract_address=bytes.fromhex(client.address_hex(TRC20_CONTRACT_B58)),
        data=calldata,
    )
    tx = client.packContract(tron.Transaction.Contract.TriggerSmartContract,
                             trigger)

    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], tx) == StatusWord.OK

    # No descriptors were supplied, so START_FLOW fails and must release every
    # charged allocation before a new session is accepted.
    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange(CLA, InsType.SIGN_GCS, P1_FIRST,
                         P2_GCS_START_FLOW, b"")
    assert error.value.status == StatusWord.INVALID_DATA

    normal_tx = build_trc20_transfer_tx(client)
    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], normal_tx) == StatusWord.OK


def test_gcs_rejects_empty_continuation_and_resets(backend: BackendInterface):
    client = TronClient(backend)
    tx = build_trc20_transfer_tx(client)
    payload = (pack_derivation_path(client.getAccount(0)["path"])
               + pack(">I", len(tx)) + tx)

    assert backend.exchange(CLA, InsType.SIGN_GCS, P1_FIRST,
                            P2_GCS_STORE, payload).status == StatusWord.OK
    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange(CLA, InsType.SIGN_GCS, P1_MORE,
                         P2_GCS_STORE, b"")
    assert error.value.status == StatusWord.INCORRECT_LENGTH

    # The rejected continuation must have torn down the old stream completely.
    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], tx) == StatusWord.OK


def test_gcs_memo_respects_data_allowed(backend: BackendInterface,
                                        device,
                                        navigator,
                                        configuration):
    del configuration
    client = TronClient(backend)
    tx = client.packContract(
        tron.Transaction.Contract.TriggerSmartContract,
        contract.TriggerSmartContract(
            owner_address=bytes.fromhex(client.getAccount(0)["addressHex"]),
            contract_address=bytes.fromhex(client.address_hex(TRC20_CONTRACT_B58)),
            data=TRC20_TRANSFER_CALLDATA),
        data=b"GCS memo")

    # The default test-app setting is enabled; turn it off and preserve the
    # precise status word expected by the legacy INS_SIGN path.
    settings_toggle(device, navigator, [SettingID.DATA_ALLOWED])
    with pytest.raises(ExceptionRAPDU) as error:
        gcs_store_calldata(client, backend, client.getAccount(0)["path"], tx)
    assert error.value.status == StatusWord.MISSING_SETTING_DATA_ALLOWED

    settings_toggle(device, navigator, [SettingID.DATA_ALLOWED])
    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], tx) == StatusWord.OK


# --- Descriptor builders -----------------------------------------------------
# Keep the host-side GCS serialization in client.gcs, matching app-ethereum.


def build_data_path_static(tuple_index: int) -> DataPath:
    """Select one top-level static ABI word from calldata."""
    return DataPath(1, [PathTuple(tuple_index), PathLeaf(PathLeafType.STATIC)])


def _uint_value(type_size: int, data_path: DataPath) -> Value:
    return Value(1, TypeFamily.UINT, type_size=type_size, data_path=data_path)


def _address_value(data_path: DataPath) -> Value:
    return Value(1, TypeFamily.ADDRESS, type_size=32, data_path=data_path)


def build_field_raw(name: str, type_size: int, data_path: DataPath) -> Field:
    return Field(1, name, ParamRaw(1, _uint_value(type_size, data_path)))


def build_field_address(name: str, data_path: DataPath) -> Field:
    """Render a static calldata word as an address (e.g. burn's `payTo`)."""
    return Field(1, name, ParamRaw(1, _address_value(data_path)))


def build_field_from_address(name: str) -> Field:
    """Render the trigger tx's owner ("From") address via ContainerPath.FROM, which
    the generic_tx_parser resolves to get_current_tx_from() (the parked tx owner)."""
    return Field(1, name,
                 ParamRaw(1, Value(1, TypeFamily.ADDRESS,
                                   container_path=ContainerPath.FROM)))


def build_field_amount(name: str, type_size: int, data_path: DataPath) -> Field:
    return Field(1, name, ParamAmount(1, _uint_value(type_size, data_path)))


def build_field_trctoken(name: str, data_path: DataPath) -> Field:
    """Render a static 32-byte calldata word as a TVM trcToken (uint256 token id)."""
    return Field(1, name,
                 ParamRaw(1, Value(1, TypeFamily.TRC_TOKEN, type_size=32,
                                   data_path=data_path)))


def build_field_datetime(name: str, type_size: int, data_path: DataPath) -> Field:
    return Field(1,
                 name,
                 ParamDatetime(1,
                               _uint_value(type_size, data_path),
                               DatetimeType.DT_UNIX))


def build_field_token_amount(name: str, value_path: DataPath,
                             token_path: DataPath) -> Field:
    return Field(1,
                 name,
                 ParamTokenAmount(1,
                                  value=_uint_value(32, value_path),
                                  token=_address_value(token_path)))


def build_field_trusted_name(name: str, addr_path: DataPath,
                             types: list[TrustedNameType],
                             sources: list[TrustedNameSource]) -> Field:
    return Field(1,
                 name,
                 ParamTrustedName(1,
                                  _address_value(addr_path),
                                  types,
                                  sources))


def build_field_enum(name: str, enum_id: int, value_path: DataPath) -> Field:
    return Field(1,
                 name,
                 ParamEnum(1, enum_id, _uint_value(32, value_path)))


def build_enum_value(contract_addr20: bytes, selector: bytes, enum_id: int,
                     value: int, name: str) -> bytes:
    return EnumValue(1,
                     TRON_MAINNET_CHAINID,
                     eth_to_tron_base58(contract_addr20),
                     selector,
                     enum_id,
                     value,
                     name).serialize()


def build_tx_info(contract_addr20: bytes, selector: bytes, fields: list[Field],
                  operation: str) -> bytes:
    return TxInfo(1,
                  TRON_MAINNET_CHAINID,
                  eth_to_tron_base58(contract_addr20),
                  selector,
                  compute_inst_hash(fields),
                  operation).serialize()


def test_gcs_p1_end_to_end(tron_client: TronClient, backend: BackendInterface):
    """store -> 0x26 -> 0x28(raw) -> expect 0x9000 (fields_hash validated)."""
    tx = build_trc20_transfer_tx(tron_client)
    assert gcs_store_calldata(tron_client, backend,
                              tron_client.getAccount(0)["path"], tx) == StatusWord.OK

    # generic_tx_parser works on 20-byte EVM addresses (0x41 prefix stripped).
    contract_addr20 = bytes.fromhex(tron_client.address_hex(TRC20_CONTRACT_B58))[1:]

    # `transfer(address _to, uint256 _amount)`: _amount is arg index 1, static.
    amount_field = build_field_raw("Amount", 32,
                                   data_path=build_data_path_static(1))
    fields = [amount_field]

    tx_info = build_tx_info(contract_addr20, TRC20_TRANSFER_SELECTOR, fields,
                            "transfer")

    tron_client.provide_transaction_info(tx_info)
    for field in fields:
        tron_client.provide_transaction_field_desc(field.serialize())


def _abi_dynamic_calldata(selector: bytes, value: bytes,
                          corrupt_offset: bool = False,
                          corrupt_length: bool = False) -> bytes:
    offset_word = bytearray((32).to_bytes(32, "big"))
    length_word = bytearray(len(value).to_bytes(32, "big"))
    if corrupt_offset:
        offset_word[0] = 1
    if corrupt_length:
        length_word[0] = 1
    padding = bytes((-len(value)) % 32)
    return selector + bytes(offset_word) + bytes(length_word) + value + padding


@pytest.mark.parametrize(
    "case",
    [
        "string_nul",
        "string_control",
        "string_not_fully_displayable",
        "offset_high_bits",
        "length_high_bits",
        "bool_not_canonical",
        "address_high_bits",
        "address_wrong_tron_prefix",
        "uint8_high_bits",
        "bytes_constraint_hidden_suffix",
    ],
)
def test_gcs_rejects_ambiguous_or_noncanonical_raw_values(
        backend: BackendInterface, case: str):
    """A clear-sign field must describe every signed calldata bit exactly."""
    client = TronClient(backend)
    selector = bytes.fromhex("12345678")
    contract_addr20 = TRC20_CONTRACT_ADDR20
    visibility = VisibleType.ALWAYS
    constraints = None

    if case == "bytes_constraint_hidden_suffix":
        raw_value = b"A" * 127 + b"B"
        calldata = _abi_dynamic_calldata(selector, raw_value)
        value = Value(
            1,
            TypeFamily.BYTES,
            data_path=DataPath(
                1,
                [PathTuple(0), PathRef(), PathLeaf(PathLeafType.DYNAMIC)],
            ),
        )
        visibility = VisibleType.MUST_BE
        constraints = [b"A" * 127 + b"C"]
    elif case in {
            "string_nul",
            "string_control",
            "string_not_fully_displayable",
            "offset_high_bits",
            "length_high_bits",
    }:
        values = {
            "string_nul": b"pay Alice\0pay Mallory",
            "string_control": b"line1\nline2",
            "string_not_fully_displayable": b"A" * 256,
            "offset_high_bits": b"safe",
            "length_high_bits": b"safe",
        }
        calldata = _abi_dynamic_calldata(
            selector,
            values[case],
            corrupt_offset=case == "offset_high_bits",
            corrupt_length=case == "length_high_bits",
        )
        value = Value(
            1,
            TypeFamily.STRING,
            data_path=DataPath(
                1,
                [PathTuple(0), PathRef(), PathLeaf(PathLeafType.DYNAMIC)],
            ),
        )
    else:
        word = bytearray(32)
        if case == "bool_not_canonical":
            word[-1] = 2
            family = TypeFamily.BOOL
            type_size = None
        elif case == "address_high_bits":
            word[0] = 1
            word[-20:] = bytes.fromhex("23f8abfc2824c397ccb3da89ae772984107ddb99")
            family = TypeFamily.ADDRESS
            type_size = None
        elif case == "address_wrong_tron_prefix":
            word[-21] = 0x42
            word[-20:] = bytes.fromhex("23f8abfc2824c397ccb3da89ae772984107ddb99")
            family = TypeFamily.ADDRESS
            type_size = None
        else:
            word[0] = 1
            word[-1] = 7
            family = TypeFamily.UINT
            type_size = 1
        calldata = selector + bytes(word)
        value = Value(
            1,
            family,
            type_size=type_size,
            data_path=build_data_path_static(0),
        )

    tx = build_trigger_smart_contract_tx(client, contract_addr20, calldata)
    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], tx) == StatusWord.OK

    field = Field(1, "Value", ParamRaw(1, value), visibility, constraints)
    client.provide_transaction_info(
        build_tx_info(contract_addr20, selector, [field], "guarded call"))
    with pytest.raises((ExceptionRAPDU, AssertionError)):
        client.provide_transaction_field_desc(field.serialize())

    # The rejected descriptor must not poison the next GCS session.
    normal_tx = build_trc20_transfer_tx(client)
    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], normal_tx) == StatusWord.OK


def test_gcs_ui_partial_oom_cleans_and_allows_reentry(
        backend: BackendInterface):
    """Exhaust the tracked budget while ui_gcs() owns a partial NBGL tree."""
    client = TronClient(backend)
    selector = bytes.fromhex("12345678")
    string_value = b"A" * 128
    calldata = _abi_dynamic_calldata(selector, string_value)
    value = Value(
        1,
        TypeFamily.STRING,
        data_path=DataPath(
            1,
            [PathTuple(0), PathRef(), PathLeaf(PathLeafType.DYNAMIC)],
        ),
    )
    fields = [
        Field(1, f"F{idx}", ParamRaw(1, value))
        for idx in range(50)
    ]
    tx = build_trigger_smart_contract_tx(client, TRC20_CONTRACT_ADDR20,
                                         calldata)
    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], tx) == StatusWord.OK
    client.provide_transaction_info(
        build_tx_info(TRC20_CONTRACT_ADDR20, selector, fields, "budget guard"))
    for field in fields:
        client.provide_transaction_field_desc(field.serialize())

    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange(CLA, InsType.SIGN_GCS, P1_FIRST,
                         P2_GCS_START_FLOW, b"")
    assert error.value.status == StatusWord.INSUFFICIENT_MEMORY

    normal_tx = build_trc20_transfer_tx(client)
    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], normal_tx) == StatusWord.OK


def _client_from_scenario(scenario_navigator: NavigateWithScenario) -> TronClient:
    return TronClient(scenario_navigator.backend)


def _start_gcs_flow_and_assert(scenario_navigator: NavigateWithScenario,
                               client: TronClient, tx: bytes,
                               test_name: str | None = None,
                               nb_warnings: int = 0) -> None:
    backend = scenario_navigator.backend
    with backend.exchange_async(CLA, InsType.SIGN_GCS, P1_FIRST,
                                P2_GCS_START_FLOW, b""):
        if nb_warnings:
            scenario_navigator.review_approve_with_warning(
                test_name=test_name,
                nb_warnings=nb_warnings)
        else:
            scenario_navigator.review_approve(test_name=test_name)

    resp = backend.last_async_response
    assert resp.status == StatusWord.OK
    assert check_tx_signature(tx, resp.data[0:65],
                              client.getAccount(0)["publicKey"][2:])


def _provide_gating(client: TronClient, gating_params: Optional[Gating]) -> None:
    """Provide a gated-signing descriptor (INS_PROVIDE_GATING) before the review,
    matching app-ethereum's test_blind_sign()/test_eip712_new() gating wiring."""
    if gating_params is not None:
        assert client.provide_gating(gating_params.serialize()).status == StatusWord.OK


def _gating_warnings(scenario_navigator: NavigateWithScenario,
                     gating_params: Optional[Gating]) -> int:
    if gating_params is None:
        return 0

    # Match test_gating_tip712's navigation shape: an existing signing warning plus
    # the gating prelude. On Nano the prelude first shows the tiny URL, then needs one
    # more confirmation click to enter the actual review flow.
    return 2


def test_gcs_sign(scenario_navigator: NavigateWithScenario,
                  gating_params: Optional[Gating] = None):
    """Full keystone flow: STORE -> 0x26 -> 0x28 -> START_FLOW -> approve.

    Asserts the firmware renders the GCS review and returns a signature over
    sha256(tx) recoverable to the device key -- the first real end-to-end GCS
    signature (this is also the first execution of ui_gcs()).

    `gating_params` threads an optional gated-signing descriptor (INS_PROVIDE_GATING)
    into the flow, mirroring app-ethereum's test_blind_sign(); test_gating reuses this
    to exercise the "Discover safer signing" prelude.
    """
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)
    tx = build_trc20_transfer_tx(client)
    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], tx) == StatusWord.OK

    contract_addr20 = bytes.fromhex(client.address_hex(TRC20_CONTRACT_B58))[1:]
    amount_field = build_field_raw("Amount", 32,
                                   data_path=build_data_path_static(1))
    fields = [amount_field]
    tx_info = build_tx_info(contract_addr20, TRC20_TRANSFER_SELECTOR, fields,
                            "transfer")

    client.provide_transaction_info(tx_info)
    for field in fields:
        client.provide_transaction_field_desc(field.serialize())

    _provide_gating(client, gating_params)

    # START_FLOW triggers the async GCS review; approve it, then collect the reply.
    _start_gcs_flow_and_assert(scenario_navigator,
                               client,
                               tx,
                               nb_warnings=_gating_warnings(scenario_navigator,
                                                            gating_params))


# keccak256("transferToken(address,uint256,trcToken)")[:4] -- the TVM native token
# transfer, whose 3rd argument is a real trcToken.
TRANSFER_TOKEN_SELECTOR = Web3.keccak(text="transferToken(address,uint256,trcToken)")[:4]


def build_transfer_token_calldata(to_addr20: bytes, token_value: int, token_id: int) -> bytes:
    """ABI-encode transferToken(address to, uint256 tokenValue, trcToken tokenId)."""
    return (TRANSFER_TOKEN_SELECTOR
            + bytes(12) + to_addr20            # word 0: address (left-padded to 32 bytes)
            + token_value.to_bytes(32, "big")  # word 1: uint256 tokenValue
            + token_id.to_bytes(32, "big"))    # word 2: trcToken tokenId


def test_gcs_trctoken(scenario_navigator: NavigateWithScenario):
    """Clear-sign transferToken(address,uint256,trcToken): its 3rd argument is a genuine
    TVM trcToken, rendered via TypeFamily.TRC_TOKEN (TF_TRC_TOKEN == uint256)."""
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)

    contract_addr20 = bytes.fromhex(client.address_hex(TRC20_CONTRACT_B58))[1:]
    to_addr20 = bytes.fromhex("23f8abfc2824c397ccb3da89ae772984107ddb99")
    calldata = build_transfer_token_calldata(to_addr20, 1000000, 1002000)
    tx = build_trigger_smart_contract_tx(client, contract_addr20, calldata)
    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], tx) == StatusWord.OK

    fields = [
        build_field_address("To", build_data_path_static(0)),
        build_field_raw("Token value", 32, build_data_path_static(1)),
        build_field_trctoken("Token id", build_data_path_static(2)),
    ]
    tx_info = build_tx_info(contract_addr20, TRANSFER_TOKEN_SELECTOR, fields, "transferToken")

    client.provide_transaction_info(tx_info)
    for field in fields:
        client.provide_transaction_field_desc(field.serialize())

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


def test_gcs_trigger_trc10_transfer(scenario_navigator: NavigateWithScenario):
    """A mainnet-valid TriggerSmartContract may transfer a native TRC-10 asset.

    The outer call_token_value/token_id pair is independent of calldata descriptors,
    so both values must be appended by the firmware as forced review fields.
    """
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)

    contract_addr20 = bytes.fromhex(client.address_hex(TRC20_CONTRACT_B58))[1:]
    trigger = contract.TriggerSmartContract(
        owner_address=bytes.fromhex(client.getAccount(0)["addressHex"]),
        contract_address=bytes([TRON_MAINNET_ADDRESS_PREFIX]) + contract_addr20,
        data=TRC20_TRANSFER_CALLDATA,
        call_token_value=2_200,
        token_id=1_000_001,
    )
    tx = client.packContract(tron.Transaction.Contract.TriggerSmartContract,
                             trigger)
    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], tx) == StatusWord.OK

    amount_field = build_field_raw("Amount", 32,
                                   data_path=build_data_path_static(1))
    fields = [amount_field]
    tx_info = build_tx_info(contract_addr20, TRC20_TRANSFER_SELECTOR, fields,
                            "transfer")
    client.provide_transaction_info(tx_info)
    client.provide_transaction_field_desc(amount_field.serialize())

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


def test_gcs_mint_long_calldata(scenario_navigator: NavigateWithScenario):
    """Over-long (~1 KB) calldata streamed through 0xC4/STORE then clear-signed via GCS.

    Mirrors dev_app-plugin-boilerplate's test_long_mint.py, both for the streaming and
    the on-screen result: the shielded-`mint` calldata is far larger than one APDU, so
    `gcs_store_calldata` parks it across several MAX_APDU_LEN chunks. This verifies
    generic_tx_parser reassembles the streamed calldata and decodes a field out of it.

    The field set reproduces the boilerplate plugin's SHIELDED_MINT screens (per
    shielded.abi.json `mint(uint256 rawValue, bytes32[9] output, bytes32[2]
    bindingSignature, bytes32[21] c)`): a "Value" screen rendering `rawValue` (arg 0)
    as a JST token amount (18 decimals), the token being the contract itself, plus the
    "Shielded Mint" contract/intent header.
    """
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)

    # generic_tx_parser works on 20-byte EVM addresses (0x41 prefix stripped).
    contract_addr20 = bytes.fromhex(client.address_hex(MINT_CONTRACT_B58))[1:]
    tx = build_trigger_smart_contract_tx(client, contract_addr20, MINT_CALLDATA)

    # Guard the premise: the calldata alone overflows a single APDU, so STORE must
    # stream it in multiple chunks (otherwise the test wouldn't exercise streaming).
    assert len(MINT_CALLDATA) > MAX_APDU_LEN

    # Token metadata for the contract itself (the tx TO) so the amount renders as
    # "<rawValue> JST", like test_long_mint.py's provide_trc20_token_information.
    client.provide_token_metadata("JST", eth_to_tron_base58(contract_addr20), 18, TRON_MAINNET_CHAINID)
    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], tx) == StatusWord.OK

    # `rawValue` (arg 0, static) shown as a token amount; the token is the TO address.
    # Plus the trigger tx's owner ("From") address, resolved from the parked tx.
    fields = [
        build_field_from_address("From"),
        Field(1,
              "Value",
              ParamTokenAmount(1,
                               value=_uint_value(32, build_data_path_static(0)),
                               token=Value(1,
                                           TypeFamily.ADDRESS,
                                           container_path=ContainerPath.TO))),
    ]
    tx_info = TxInfo(1, TRON_MAINNET_CHAINID, eth_to_tron_base58(contract_addr20), MINT_SELECTOR,
                     compute_inst_hash(fields), "Shielded Mint", creator_name="ShieldedJST",
                     contract_name="Shielded").serialize()

    client.provide_transaction_info(tx_info)
    for field in fields:
        client.provide_transaction_field_desc(field.serialize())

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


def test_gcs_transfer_long_calldata(scenario_navigator: NavigateWithScenario):
    """Over-long shielded-`transfer` calldata streamed through 0xC4/STORE, GCS-signed.

    Mirrors dev_app-plugin-boilerplate's test_long_transfer.py: `transfer` takes only
    dynamic arrays, so there is no scalar calldata value to render. The descriptor still
    shows the trigger tx's owner ("From") address (a tx-level container value, not from
    the calldata) on top of the "Shielded Transfer" contract/intent header. Exercises
    the streaming reassembly of a ~1.5 KB calldata.
    """
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)

    contract_addr20 = bytes.fromhex(client.address_hex(MINT_CONTRACT_B58))[1:]
    tx = build_trigger_smart_contract_tx(client, contract_addr20,
                                         SHIELDED_TRANSFER_CALLDATA)

    assert len(SHIELDED_TRANSFER_CALLDATA) > MAX_APDU_LEN
    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], tx) == StatusWord.OK

    # No calldata to decode; show only the trigger tx's owner ("From") address.
    fields = [build_field_from_address("From")]
    tx_info = TxInfo(1, TRON_MAINNET_CHAINID, eth_to_tron_base58(contract_addr20),
                     SHIELDED_TRANSFER_SELECTOR, compute_inst_hash(fields),
                     "Shielded Transfer", creator_name="ShieldedJST",
                     contract_name="Shielded").serialize()
    client.provide_transaction_info(tx_info)
    for field in fields:
        client.provide_transaction_field_desc(field.serialize())

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


def test_gcs_burn_long_calldata(scenario_navigator: NavigateWithScenario):
    """Over-long shielded-`burn` calldata streamed through 0xC4/STORE, GCS-signed.

    Mirrors dev_app-plugin-boilerplate's test_long_burn.py: the plugin's SHIELDED_BURN
    shows "Value" + "Contract". The `burn` head's fixed arrays (input[10],
    spendAuthoritySignature[2]) push `rawValue` to calldata word 12 and `payTo` to word
    15, so the descriptor decodes those words (a JST token amount and an address) -- plus
    the trigger tx's owner ("From") address -- verifying field decode at deep static
    offsets out of the reassembled long calldata, alongside a tx-level container value.
    """
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)

    contract_addr20 = SHIELDED_BURN_CONTRACT20
    tx = build_trigger_smart_contract_tx(client, contract_addr20,
                                         SHIELDED_BURN_CALLDATA)

    assert len(SHIELDED_BURN_CALLDATA) > MAX_APDU_LEN
    client.provide_token_metadata("JST", eth_to_tron_base58(contract_addr20), 18, TRON_MAINNET_CHAINID)
    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], tx) == StatusWord.OK

    # `rawValue` (word 12) as a token amount, `payTo` (word 15) as an address, and the
    # trigger tx's owner ("From") address resolved from the parked tx.
    fields = [
        build_field_from_address("From"),
        Field(1,
              "Value",
              ParamTokenAmount(1,
                               value=_uint_value(
                                   32, build_data_path_static(SHIELDED_BURN_RAW_VALUE_WORD)),
                               token=Value(1,
                                           TypeFamily.ADDRESS,
                                           container_path=ContainerPath.TO))),
        build_field_address("Pay To",
                            build_data_path_static(SHIELDED_BURN_PAY_TO_WORD)),
    ]
    tx_info = TxInfo(1, TRON_MAINNET_CHAINID, eth_to_tron_base58(contract_addr20), SHIELDED_BURN_SELECTOR,
                     compute_inst_hash(fields), "Shielded Burn", creator_name="ShieldedJST",
                     contract_name="Shielded").serialize()

    client.provide_transaction_info(tx_info)
    for field in fields:
        client.provide_transaction_field_desc(field.serialize())

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


def test_gcs_batch_empty_tx(scenario_navigator: NavigateWithScenario):
    """batchExecute(calls[].data=b"") exercises ParamCalldata empty nested tx."""
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)

    with Path(f"{ABIS_FOLDER}/batch.json").open(encoding="utf-8") as f:
        contract = Web3().eth.contract(
            abi=json.load(f),
            address=BATCH_CONTRACT20,
        )

    data = contract.encode_abi("batchExecute", [[
        (
            bytes.fromhex("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045"),
            to_sun(0),
            b"",
        ),
    ]])

    # Same batchExecute calldata as app-ethereum, but carried by a TRON protobuf
    # TriggerSmartContract transaction (not an ETH RLP one); park it via the 0xC4
    # STORE bridge instead of app_client.sign(mode=STORE).
    tx = build_trigger_smart_contract_tx(client, BATCH_CONTRACT20,
                                         bytes.fromhex(data[2:]))
    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], tx) == StatusWord.OK

    param_paths = get_all_tuple_array_paths(f"{ABIS_FOLDER}/batch.json",
                                            "batchExecute",
                                            "calls")
    fields = [
        Field(
            1,
            "Destination",
            ParamCalldata(
                1,
                Value(
                    1,
                    TypeFamily.BYTES,
                    data_path=DataPath(1, param_paths["data"]),
                ),
                Value(
                    1,
                    TypeFamily.ADDRESS,
                    data_path=DataPath(1, param_paths["to"]),
                ),
            ),
        ),
    ]

    # compute instructions hash
    inst_hash = compute_inst_hash(fields)

    tx_info = TxInfo(
        1,
        TRON_MAINNET_CHAINID,
        eth_to_tron_base58(BATCH_CONTRACT20),
        get_selector_from_data(data),
        inst_hash,
        "Batch transaction",
        creator_name="Ledger Multisig",
        creator_legal_name="Ledger",
    )

    client.provide_transaction_info(tx_info.serialize())
    for field in fields:
        client.provide_transaction_field_desc(field.serialize())

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


def test_gcs_nft(scenario_navigator: NavigateWithScenario):
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)

    with Path(f"{ABIS_FOLDER}/erc1155.json").open(encoding="utf-8") as f:
        contract = Web3().eth.contract(
            abi=json.load(f),
            address=None,
        )

    data = contract.encode_abi("safeBatchTransferFrom", [
        bytes.fromhex("1111111111111111111111111111111111111111"),
        bytes.fromhex("d8da6bf26964af9d7eed9e03e53415d37aa96045"),
        [
            2,
            4,
            8,
            16,
        ],
        [
            1,
            2,
            3,
            4,
        ],
        bytes.fromhex("deadbeef1337cafe"),
    ])

    collection_addr20 = bytes.fromhex(
        "495f947276749ce646f68ac8c248420045cb7b5e")
    tx = build_trigger_smart_contract_tx(client, collection_addr20,
                                         bytes.fromhex(data[2:]))
    param_paths = get_all_paths(f"{ABIS_FOLDER}/erc1155.json",
                                "safeBatchTransferFrom")
    fields = [
        Field(
            1,
            "From",
            ParamTrustedName(
                1,
                Value(
                    1,
                    TypeFamily.ADDRESS,
                    data_path=DataPath(1, param_paths["_from"]),
                ),
                [
                    TrustedNameType.ACCOUNT,
                ],
                [
                    TrustedNameSource.UD,
                    TrustedNameSource.ENS,
                    TrustedNameSource.FN,
                ],
                [
                    bytes.fromhex("0000000000000000000000000000000000000000"),
                    bytes.fromhex("1111111111111111111111111111111111111111"),
                    bytes.fromhex("2222222222222222222222222222222222222222"),
                ],
            ),
        ),
        Field(
            1,
            "To",
            ParamRaw(
                1,
                Value(
                    1,
                    TypeFamily.ADDRESS,
                    data_path=DataPath(1, param_paths["_to"]),
                ),
            ),
        ),
        Field(
            1,
            "NFTs",
            ParamNFT(
                1,
                Value(
                    1,
                    TypeFamily.UINT,
                    type_size=32,
                    data_path=DataPath(1, param_paths["_ids"]),
                ),
                Value(
                    1,
                    TypeFamily.ADDRESS,
                    container_path=ContainerPath.TO,
                ),
            ),
        ),
        Field(
            1,
            "Values",
            ParamRaw(
                1,
                Value(
                    1,
                    TypeFamily.UINT,
                    type_size=32,
                    data_path=DataPath(1, param_paths["_values"]),
                ),
            ),
        ),
        Field(
            1,
            "Data",
            ParamRaw(
                1,
                Value(
                    1,
                    TypeFamily.BYTES,
                    data_path=DataPath(1, param_paths["_data"]),
                ),
            ),
        ),
    ]

    inst_hash = compute_inst_hash(fields)
    tx_info = TxInfo(
        1,
        TRON_MAINNET_CHAINID,
        eth_to_tron_base58(collection_addr20),
        get_selector_from_data(data),
        inst_hash,
        "batch transfer NFTs",
    )

    device_addr20 = bytes.fromhex(client.getAccount(0)["addressHex"])[1:]
    client.provide_trusted_name(
        TrustedName(2,
                    eth_to_tron_base58(device_addr20),
                    "gerard.eth",
                    tn_type=TrustedNameType.ACCOUNT,
                    tn_source=TrustedNameSource.ENS,
                    chain_id=TRON_MAINNET_CHAINID,
                    challenge=get_challenge(client)))
    client.provide_nft_metadata("OpenSea Shared Storefront", eth_to_tron_base58(collection_addr20),
                                TRON_MAINNET_CHAINID)
    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], tx) == StatusWord.OK
    client.provide_transaction_info(tx_info.serialize())

    for field in fields:
        client.provide_transaction_field_desc(field.serialize())

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


def _poap_data() -> str:
    with Path(f"{ABIS_FOLDER}/poap.abi.json").open(encoding="utf-8") as f:
        contract = Web3().eth.contract(
            abi=json.load(f),
            address=None,
        )
    return contract.encode_abi("mintToken", [
        175676,
        7163978,
        bytes.fromhex("Dad77910DbDFdE764fC21FCD4E74D71bBACA6D8D"),
        1730621615,
        bytes.fromhex(
            "8991da687cff5300959810a08c4ec183bb2a56dc82f5aac2b24f1106c2d"
            "983ac6f7a6b28700a236724d814000d0fd8c395fcf9f87c4424432ebf30"
            "c9479201d71c"),
    ])


POAP_CONTRACT20 = bytes.fromhex("0bb4D3e88243F4A057Db77341e6916B0e449b158")


def _store_poap_tx(client: TronClient,
                   backend: BackendInterface) -> tuple[str, bytes]:
    data = _poap_data()
    tx = build_trigger_smart_contract_tx(client, POAP_CONTRACT20,
                                         bytes.fromhex(data[2:]))
    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], tx) == StatusWord.OK
    return data, tx


def _provide_gcs_descriptor(client: TronClient, contract_addr20: bytes,
                            data: str, fields: list[Field],
                            operation: str, **tx_info_kwargs) -> None:
    tx_info = TxInfo(1,
                     TRON_MAINNET_CHAINID,
                     eth_to_tron_base58(contract_addr20),
                     get_selector_from_data(data),
                     compute_inst_hash(fields),
                     operation,
                     **tx_info_kwargs)

    client.provide_transaction_info(tx_info.serialize())
    for field in fields:
        client.provide_transaction_field_desc(field.serialize())


def _store_contract_call(client: TronClient, backend: BackendInterface,
                         contract_addr20: bytes, data: str) -> bytes:
    tx = build_trigger_smart_contract_tx(client, contract_addr20,
                                         bytes.fromhex(data[2:]))
    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], tx) == StatusWord.OK
    return tx


def test_gcs_poap(scenario_navigator: NavigateWithScenario):
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)
    data, tx = _store_poap_tx(client, backend)

    param_paths = get_all_paths(f"{ABIS_FOLDER}/poap.abi.json", "mintToken")
    fields = [
        Field(
            1,
            "Event ID",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["eventId"])),
            ),
        ),
        Field(
            1,
            "Token ID",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["tokenId"])),
            ),
        ),
        Field(
            1,
            "Receiver",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["receiver"])),
            ),
        ),
        Field(
            1,
            "Expiration time",
            ParamDatetime(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["expirationTime"])),
                DatetimeType.DT_UNIX,
            ),
        ),
        Field(
            1,
            "Signature",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.BYTES,
                      data_path=DataPath(1, param_paths["signature"])),
            ),
        ),
    ]

    _provide_gcs_descriptor(client,
                            POAP_CONTRACT20,
                            data,
                            fields,
                            "mint POAP",
                            creator_name="POAP",
                            creator_legal_name="Proof of Attendance Protocol",
                            creator_url="poap.xyz",
                            contract_name="PoapBridge",
                            deploy_date=1646305200)
    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


@pytest.mark.parametrize("test_config", ["chain_id", "network"])
def test_gcs_formatter(scenario_navigator: NavigateWithScenario,
                       test_config: str):
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)
    data, tx = _store_poap_tx(client, backend)

    param_paths = get_all_paths(f"{ABIS_FOLDER}/poap.abi.json", "mintToken")
    fields = [
        Field(
            1,
            "Token ID",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["tokenId"])),
            ),
        ),
        Field(
            1,
            "Receiver",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["receiver"])),
            ),
        ),
        Field(
            1,
            "Expiration time",
            ParamDatetime(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["expirationTime"])),
                DatetimeType.DT_UNIX,
            ),
        ),
    ]
    if test_config == "chain_id":
        fields.append(
            Field(
                1,
                "Chain ID",
                ParamRaw(
                    1,
                    Value(1,
                          TypeFamily.UINT,
                          container_path=ContainerPath.CHAIN_ID),
                ),
            ))
    else:
        fields.append(
            Field(
                1,
                "Custom Network",
                ParamNetwork(
                    1,
                    Value(1,
                          TypeFamily.UINT,
                          container_path=ContainerPath.CHAIN_ID),
                ),
            ))

    _provide_gcs_descriptor(client,
                            POAP_CONTRACT20,
                            data,
                            fields,
                            "mint POAP",
                            creator_name="POAP",
                            creator_legal_name="Proof of Attendance Protocol",
                            creator_url="poap.xyz",
                            contract_name="PoapBridge",
                            deploy_date=1646305200)
    _start_gcs_flow_and_assert(
        scenario_navigator, client, tx,
        f"{scenario_navigator.test_name}_{test_config}")


@pytest.mark.parametrize(
    "test_config, visible, constraints",
    [
        ("if_not_0", VisibleType.IF_NOT_IN,
         [bytes.fromhex("0000000000000000000000000000000000000000")]),
        ("if_not_addr", VisibleType.IF_NOT_IN,
         [bytes.fromhex("Dad77910DbDFdE764fC21FCD4E74D71bBACA6D8D")]),
        ("must_be_addr", VisibleType.MUST_BE,
         [bytes.fromhex("Dad77910DbDFdE764fC21FCD4E74D71bBACA6D8D")]),
        ("must_be_0", VisibleType.MUST_BE,
         [bytes.fromhex("00"),
          bytes.fromhex("01"),
          bytes.fromhex("02")]),
    ],
)
def test_gcs_constraints(scenario_navigator: NavigateWithScenario,
                         test_config: str,
                         visible: VisibleType, constraints: list[bytes]):
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)
    data, tx = _store_poap_tx(client, backend)

    param_paths = get_all_paths(f"{ABIS_FOLDER}/poap.abi.json", "mintToken")
    fields = [
        Field(
            1,
            "Token ID",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["tokenId"])),
            ),
        ),
        Field(
            1,
            "Receiver",
            ParamTrustedName(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["receiver"])),
                [
                    TrustedNameType.ACCOUNT,
                    TrustedNameType.WALLET,
                ],
                [
                    TrustedNameSource.UD,
                    TrustedNameSource.ENS,
                    TrustedNameSource.FN,
                ],
            ),
            visible,
            constraints,
        ),
        Field(
            1,
            "Receiver uint",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["receiver"])),
            ),
            visible,
            constraints,
        ),
        Field(
            1,
            "Receiver addr",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      type_size=32,
                      data_path=DataPath(1, param_paths["receiver"])),
            ),
            visible,
            constraints,
        ),
        Field(
            1,
            "Expiration time",
            ParamDatetime(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["expirationTime"])),
                DatetimeType.DT_UNIX,
            ),
        ),
    ]

    tx_info = TxInfo(
        1,
        TRON_MAINNET_CHAINID,
        eth_to_tron_base58(POAP_CONTRACT20),
        get_selector_from_data(data),
        compute_inst_hash(fields),
        "mint POAP",
        creator_name="POAP",
        creator_legal_name="Proof of Attendance Protocol",
        creator_url="poap.xyz",
        contract_name="PoapBridge",
        deploy_date=1646305200,
    )
    client.provide_transaction_info(tx_info.serialize())

    if test_config == "must_be_0":
        with pytest.raises((ExceptionRAPDU, AssertionError)) as err:
            for field in fields:
                client.provide_transaction_field_desc(field.serialize())
        if isinstance(err.value, ExceptionRAPDU):
            assert err.value.status == StatusWord.INVALID_DATA
        return

    for field in fields:
        client.provide_transaction_field_desc(field.serialize())
    _start_gcs_flow_and_assert(
        scenario_navigator, client, tx,
        f"{scenario_navigator.test_name}_{test_config}")


def test_gcs_1inch(scenario_navigator: NavigateWithScenario):
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)

    with Path(f"{ABIS_FOLDER}/1inch.abi.json").open(encoding="utf-8") as f:
        contract = Web3().eth.contract(
            abi=json.load(f),
            address=None,
        )
    data = contract.encode_abi("swap", [
        bytes.fromhex("F313B370D28760b98A2E935E56Be92Feb2c4EC04"),
        [
            bytes.fromhex("EeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE"),
            bytes.fromhex("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
            bytes.fromhex("F313B370D28760b98A2E935E56Be92Feb2c4EC04"),
            bytes.fromhex("Dad77910DbDFdE764fC21FCD4E74D71bBACA6D8D"),
            to_sun("2200"),
            682119805,
            0,
        ],
        bytes(),
    ])
    contract_addr20 = bytes.fromhex("111111125421cA6dc452d289314280a0f8842A65")
    tx = build_trigger_smart_contract_tx(client, contract_addr20,
                                         bytes.fromhex(data[2:]))
    client.provide_token_metadata(
        "USDC",
        eth_to_tron_base58(bytes.fromhex("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")),
        6,
        TRON_MAINNET_CHAINID)
    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], tx) == StatusWord.OK

    param_paths = get_all_paths(f"{ABIS_FOLDER}/1inch.abi.json", "swap")
    tuple_paths = get_all_tuple_paths(f"{ABIS_FOLDER}/1inch.abi.json", "swap",
                                      "desc")
    fields = [
        Field(
            1,
            "Executor",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["executor"])),
            ),
        ),
        Field(
            1,
            "Send",
            ParamTokenAmount(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, tuple_paths["amount"])),
                token=Value(1,
                            TypeFamily.ADDRESS,
                            data_path=DataPath(1, tuple_paths["srcToken"])),
                native_currency=[
                    bytes.fromhex("EeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE"),
                ],
            ),
        ),
        Field(
            1,
            "Receive",
            ParamTokenAmount(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, tuple_paths["minReturnAmount"])),
                token=Value(1,
                            TypeFamily.ADDRESS,
                            data_path=DataPath(1, tuple_paths["dstToken"])),
                native_currency=[
                    bytes.fromhex("EeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE"),
                ],
            ),
        ),
    ]

    client.provide_transaction_info(
        TxInfo(1,
               TRON_MAINNET_CHAINID,
               eth_to_tron_base58(contract_addr20),
               get_selector_from_data(data),
               compute_inst_hash(fields),
               "swap",
               creator_name="1inch",
               creator_legal_name="1inch Network",
               creator_url="1inch.io",
               contract_name="Aggregation Router V6",
               deploy_date=1707724800).serialize())
    for field in fields:
        client.provide_transaction_field_desc(field.serialize())
    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


def test_gcs_proxy(scenario_navigator: NavigateWithScenario,
                   gating_params: Optional[Gating] = None):
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)
    new_owner = bytes.fromhex("2222222222222222222222222222222222222222")

    with Path(f"{ABIS_FOLDER}/proxy_implem.abi.json").open(
            encoding="utf-8") as f:
        contract = Web3().eth.contract(
            abi=json.load(f),
            address=None,
        )
    data = contract.encode_abi("transferOwnership", [new_owner])
    assert get_selector_from_data(data) == TRANSFER_OWNERSHIP_SELECTOR
    proxy_addr20 = PROXY_ADDR20
    impl_addr20 = PROXY_IMPL_ADDR20
    tx = build_trigger_smart_contract_tx(client, proxy_addr20,
                                         bytes.fromhex(data[2:]))

    param_paths = get_all_paths(f"{ABIS_FOLDER}/proxy_implem.abi.json",
                                "transferOwnership")
    fields = [
        Field(
            1,
            "New owner",
            ParamTrustedName(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["newOwner"])),
                [TrustedNameType.CONTRACT],
                [TrustedNameSource.CAL],
            ),
        ),
    ]

    tx_info = TxInfo(1,
                     TRON_MAINNET_CHAINID,
                     eth_to_tron_base58(impl_addr20),
                     get_selector_from_data(data),
                     compute_inst_hash(fields),
                     "transfer ownership",
                     creator_name="EigenLayer",
                     creator_legal_name="Eigen Labs",
                     creator_url="https://eigenlayer.xyz",
                     contract_name="Delegation Manager",
                     deploy_date=1711098731)

    client.provide_proxy_info(
        ProxyInfo(get_challenge(client),
                  eth_to_tron_base58(proxy_addr20),
                  tx_info.chain_id,
                  tx_info.contract_addr,
                  selector=tx_info.selector).serialize())

    impl_contract = bytes.fromhex("1111111111111111111111111111111111111111")
    client.provide_proxy_info(
        ProxyInfo(get_challenge(client), eth_to_tron_base58(new_owner), tx_info.chain_id,
                  eth_to_tron_base58(impl_contract)).serialize())
    client.provide_trusted_name(
        TrustedName(2,
                    eth_to_tron_base58(impl_contract),
                    "some contract",
                    tn_type=TrustedNameType.CONTRACT,
                    tn_source=TrustedNameSource.CAL,
                    chain_id=TRON_MAINNET_CHAINID,
                    challenge=get_challenge(client)))

    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], tx) == StatusWord.OK
    client.provide_transaction_info(tx_info.serialize())

    for field in fields:
        client.provide_transaction_field_desc(field.serialize())
    _provide_gating(client, gating_params)
    _start_gcs_flow_and_assert(scenario_navigator,
                               client,
                               tx,
                               nb_warnings=_gating_warnings(scenario_navigator,
                                                            gating_params))


def test_gcs_4226(scenario_navigator: NavigateWithScenario):
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)

    with Path(f"{ABIS_FOLDER}/rSWELL.abi.json").open(encoding="utf-8") as f:
        contract = Web3().eth.contract(
            abi=json.load(f),
            address=None,
        )
    data = contract.encode_abi("deposit", [
        to_units("4.20", 18),
        bytes.fromhex("Dad77910DbDFdE764fC21FCD4E74D71bBACA6D8D"),
    ])
    contract_addr20 = bytes.fromhex("358d94b5b2F147D741088803d932Acb566acB7B6")
    tx = build_trigger_smart_contract_tx(client, contract_addr20,
                                         bytes.fromhex(data[2:]))

    swell_token_addr = bytes.fromhex("0a6e7ba5042b38349e437ec6db6214aec7b35676")
    param_paths = get_all_paths(f"{ABIS_FOLDER}/rSWELL.abi.json", "deposit")
    fields = [
        Field(
            1,
            "Deposit asset",
            ParamTokenAmount(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["assets"])),
                token=Value(1, TypeFamily.ADDRESS, constant=swell_token_addr),
            ),
        ),
        Field(
            1,
            "Receive shares",
            ParamToken(
                1,
                Value(1, TypeFamily.ADDRESS, container_path=ContainerPath.TO),
            ),
        ),
        Field(
            1,
            "Send shares to",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["receiver"])),
            ),
        ),
    ]

    client.provide_token_metadata("rSWELL", eth_to_tron_base58(contract_addr20), 18,
                                  TRON_MAINNET_CHAINID)
    client.provide_token_metadata("SWELL", eth_to_tron_base58(swell_token_addr), 18,
                                  TRON_MAINNET_CHAINID)
    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], tx) == StatusWord.OK
    client.provide_transaction_info(
        TxInfo(1,
               TRON_MAINNET_CHAINID,
               eth_to_tron_base58(contract_addr20),
               get_selector_from_data(data),
               compute_inst_hash(fields),
               "deposit",
               creator_name="Swell",
               creator_legal_name="Swell Network",
               creator_url="www.swellnetwork.io",
               contract_name="rSWELL Token",
               deploy_date=1726817291).serialize())
    for field in fields:
        client.provide_transaction_field_desc(field.serialize())
    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


# https://etherscan.io/tx/0x07a80f1b359146129f3369af39e7eb2457581109c8300fc2ef81e997a07cf3f0
def test_gcs_nested_createProxyWithNonce(
        scenario_navigator: NavigateWithScenario):
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)

    safe_l2_setup_addr = bytes.fromhex(
        "BD89A1CE4DDe368FFAB0eC35506eEcE0b1fFdc54")
    with Path(f"{ABIS_FOLDER}/safe_l2_setup_1.4.1.abi.json").open(
            encoding="utf-8") as f:
        safe_l2_setup = Web3().eth.contract(abi=json.load(f),
                                            address=safe_l2_setup_addr)
    safe_l2_setup_data = safe_l2_setup.encode_abi("setupToL2", [
        bytes.fromhex("29fcB43b46531BcA003ddC8FCB67FFE91900C762")
    ])

    safe_addr = bytes.fromhex("41675C099F32341bf84BFc5382aF534df5C7461a")
    with Path(f"{ABIS_FOLDER}/safe_1.4.1.abi.json").open(
            encoding="utf-8") as f:
        safe = Web3().eth.contract(abi=json.load(f), address=safe_addr)
    safe_data = safe.encode_abi("setup", [
        [
            bytes.fromhex("6535d5F76F021FE65E2ac73D086dF4b4Bd7ee5D9"),
            bytes.fromhex("3fB2C8699C3D0Cedde210F383435C537C86D91B8"),
        ],
        2,
        safe_l2_setup_addr,
        safe_l2_setup_data,
        bytes.fromhex("fd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99"),
        bytes.fromhex("0000000000000000000000000000000000000000"),
        0,
        bytes.fromhex("5afe7A11E7000000000000000000000000000000"),
    ])

    safe_proxy_factory_addr = bytes.fromhex(
        "4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67")
    with Path(f"{ABIS_FOLDER}/safe_proxy_factory_1.4.1.abi.json").open(
            encoding="utf-8") as f:
        safe_proxy_factory = Web3().eth.contract(
            abi=json.load(f), address=safe_proxy_factory_addr)
    data = safe_proxy_factory.encode_abi("createProxyWithNonce",
                                         [safe_addr, safe_data, 0])
    tx = _store_contract_call(client, backend, safe_proxy_factory_addr, data)

    param_paths = get_all_paths(
        f"{ABIS_FOLDER}/safe_proxy_factory_1.4.1.abi.json",
        "createProxyWithNonce")
    fields = [
        Field(
            1,
            "_singleton",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["_singleton"])),
            ),
        ),
        Field(
            1,
            "initializer",
            ParamCalldata(
                1,
                Value(1,
                      TypeFamily.BYTES,
                      data_path=DataPath(1, param_paths["initializer"])),
                Value(1,
                      TypeFamily.BYTES,
                      data_path=DataPath(1, param_paths["_singleton"])),
            ),
        ),
        Field(
            1,
            "saltNonce",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["saltNonce"])),
            ),
        ),
    ]

    tx_info = TxInfo(
        1,
        TRON_MAINNET_CHAINID,
        eth_to_tron_base58(safe_proxy_factory_addr),
        get_selector_from_data(data),
        compute_inst_hash(fields),
        "create a Safe account",
        creator_name="Safe",
        creator_legal_name="Safe Ecosystem Foundation",
        creator_url="safe.global",
    )
    client.provide_transaction_info(tx_info.serialize())

    param_paths = get_all_paths(f"{ABIS_FOLDER}/safe_1.4.1.abi.json", "setup")
    sub_fields = [
        Field(
            1,
            "_owners",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["_owners"])),
            ),
        ),
        Field(
            1,
            "_threshold",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["_threshold"])),
            ),
        ),
        Field(
            1,
            "to",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["to"])),
            ),
        ),
        Field(
            1,
            "data",
            ParamCalldata(
                1,
                Value(1,
                      TypeFamily.BYTES,
                      data_path=DataPath(1, param_paths["data"])),
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["to"])),
            ),
        ),
        Field(
            1,
            "fallbackHandler",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["fallbackHandler"])),
            ),
        ),
        Field(
            1,
            "paymentToken",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["paymentToken"])),
            ),
        ),
        Field(
            1,
            "payment",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["payment"])),
            ),
        ),
        Field(
            1,
            "paymentReceiver",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["paymentReceiver"])),
            ),
        ),
    ]
    sub_tx_info = TxInfo(1, TRON_MAINNET_CHAINID, eth_to_tron_base58(safe_addr),
                         get_selector_from_data(safe_data),
                         compute_inst_hash(sub_fields), "setup")

    param_paths = get_all_paths(
        f"{ABIS_FOLDER}/safe_l2_setup_1.4.1.abi.json", "setupToL2")
    sub_sub_fields = [
        Field(
            1,
            "l2Singleton",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["l2Singleton"])),
            ),
        ),
    ]
    sub_sub_tx_info = TxInfo(1, TRON_MAINNET_CHAINID, eth_to_tron_base58(safe_l2_setup_addr),
                             get_selector_from_data(safe_l2_setup_data),
                             compute_inst_hash(sub_sub_fields), "L2 setup")

    for field in fields:
        client.provide_transaction_field_desc(field.serialize())
        if field.param.type == ParamType.CALLDATA:
            client.provide_transaction_info(sub_tx_info.serialize())
            for sub_field in sub_fields:
                client.provide_transaction_field_desc(sub_field.serialize())
                if sub_field.param.type == ParamType.CALLDATA:
                    client.provide_transaction_info(sub_sub_tx_info.serialize())
                    for sub_sub_field in sub_sub_fields:
                        client.provide_transaction_field_desc(
                            sub_sub_field.serialize())

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


# https://etherscan.io/tx/0xc5545f13bfaf6f69ae937bc64337405060dc56ce7649ea7051d2bbc3b4316b79
def test_gcs_nested_execTransaction_send(
        scenario_navigator: NavigateWithScenario):
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)

    contract_addr = bytes.fromhex("23F8abfC2824C397cCB3DA89ae772984107dDB99")
    with Path(f"{ABIS_FOLDER}/safe_1.4.1.abi.json").open(
            encoding="utf-8") as f:
        contract = Web3().eth.contract(abi=json.load(f), address=contract_addr)
    data = contract.encode_abi("execTransaction", [
        contract_addr,
        4_200,  # 0.0042 TRX in SUN
        bytes(),
        0,
        0,
        0,
        0,
        bytes.fromhex("0000000000000000000000000000000000000000"),
        bytes.fromhex("0000000000000000000000000000000000000000"),
        bytes.fromhex(
            "a974345670d8e06c52eeb7bfe59b1ed0fc879223ff0938c859c3852110c8"
            "c58016ec4bf0c68e84d3a40e3ac519f0a0db6954e7c4107fc6985de7d"
            "c683603f62a1b"),
    ])
    tx_to = bytes.fromhex("C1897a9Acbdd54028dA5f7b76B5833A91553AaF6")
    tx = _store_contract_call(client, backend, tx_to, data)

    param_paths = get_all_paths(f"{ABIS_FOLDER}/safe_1.4.1.abi.json",
                                "execTransaction")
    fields = [
        Field(
            1,
            "data",
            ParamCalldata(
                1,
                Value(1,
                      TypeFamily.BYTES,
                      data_path=DataPath(1, param_paths["data"])),
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["to"])),
                amount=Value(1,
                             TypeFamily.UINT,
                             type_size=32,
                             data_path=DataPath(1, param_paths["value"])),
                spender=Value(1,
                              TypeFamily.ADDRESS,
                              container_path=ContainerPath.TO),
            ),
        ),
    ]

    client.provide_transaction_info(
        TxInfo(1,
               TRON_MAINNET_CHAINID,
               eth_to_tron_base58(tx_to),
               get_selector_from_data(data),
               compute_inst_hash(fields),
               "execute a Safe action",
               creator_name="Safe",
               creator_legal_name="Safe Ecosystem Foundation",
               creator_url="safe.global").serialize())
    for field in fields:
        client.provide_transaction_field_desc(field.serialize())

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


# https://etherscan.io/tx/0xbeafe22c9e3ddcf85b06f65a56cc3ea8f5b02c323cc433c93c103ad3526db88d
def test_gcs_nested_execTransaction_addOwnerWithThreshold(
        scenario_navigator: NavigateWithScenario):
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)

    contract_addr = bytes.fromhex("23F8abfC2824C397cCB3DA89ae772984107dDB99")
    with Path(f"{ABIS_FOLDER}/safe_1.4.1.abi.json").open(
            encoding="utf-8") as f:
        contract = Web3().eth.contract(abi=json.load(f), address=contract_addr)
    sub_data = contract.encode_abi("addOwnerWithThreshold", [
        bytes.fromhex("FD6765Ad4eE64668701356a16aB28B123B3A4170"),
        2,
    ])
    data = contract.encode_abi("execTransaction", [
        contract_addr,
        to_sun(0),
        sub_data,
        1,  # operation
        0,
        0,
        0,
        bytes.fromhex("0000000000000000000000000000000000000000"),
        bytes.fromhex("0000000000000000000000000000000000000000"),
        bytes.fromhex(
            "c14660c23f715fc85c01326c7fa7f05ddeb71147fc7bad912eace6ee55"
            "c24a314f814262b3c8ca64fc77377ce6e65b20bdc902c34931888c433e"
            "23ab0069843d1bf3d2dfb18fd6bd807002bffec3326755c928e325981"
            "f30e1518e999b348a5f011446931b8bd9fbb152cdc00d945b7cd030c"
            "14e48c7826d31f9c09a1376f694de1b"),
    ])
    param_paths = get_all_paths(f"{ABIS_FOLDER}/safe_1.4.1.abi.json",
                                "execTransaction")
    fields = [
        Field(
            1,
            "to",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["to"])),
            ),
        ),
        Field(
            1,
            "value",
            ParamAmount(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["value"])),
            ),
        ),
        Field(
            1,
            "data",
            ParamCalldata(
                1,
                Value(1,
                      TypeFamily.BYTES,
                      data_path=DataPath(1, param_paths["data"])),
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["to"])),
            ),
        ),
        Field(
            1,
            "Operation type",
            ParamEnum(
                1,
                0,
                Value(1,
                      TypeFamily.UINT,
                      type_size=1,
                      data_path=DataPath(1, param_paths["operation"])),
            ),
        ),
        Field(
            1,
            "safeTxGas",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["safeTxGas"])),
            ),
        ),
        Field(
            1,
            "dataGas",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["baseGas"])),
            ),
        ),
        Field(
            1,
            "gasPrice",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["gasPrice"])),
            ),
        ),
        Field(
            1,
            "gasToken",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["gasToken"])),
            ),
        ),
        Field(
            1,
            "refundReceiver",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["refundReceiver"])),
            ),
        ),
        Field(
            1,
            "signatures",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.BYTES,
                      data_path=DataPath(1, param_paths["signatures"])),
            ),
        ),
    ]

    tx_info = TxInfo(
        1,
        TRON_MAINNET_CHAINID,
        eth_to_tron_base58(contract_addr),
        get_selector_from_data(data),
        compute_inst_hash(fields),
        "execute a Safe action",
        creator_name="Safe",
        creator_legal_name="Safe Ecosystem Foundation",
        creator_url="safe.global",
    )
    param_paths = get_all_paths(f"{ABIS_FOLDER}/safe_1.4.1.abi.json",
                                "addOwnerWithThreshold")
    sub_fields = [
        Field(
            1,
            "owner",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["owner"])),
            ),
        ),
        Field(
            1,
            "_threshold",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["_threshold"])),
            ),
        ),
    ]
    sub_tx_info = TxInfo(1, TRON_MAINNET_CHAINID, eth_to_tron_base58(contract_addr),
                         get_selector_from_data(sub_data),
                         compute_inst_hash(sub_fields),
                         "add owner with threshold")

    enum_values = [
        (0, "Call"),
        (1, "Delegate Call"),
        (2, "Unknown"),
    ]
    for enum_val in enum_values:
        client.provide_enum_value(
            EnumValue(1, tx_info.chain_id, tx_info.contract_addr,
                      tx_info.selector, 0, enum_val[0],
                      enum_val[1]).serialize())

    tx = _store_contract_call(client, backend, contract_addr, data)
    client.provide_transaction_info(tx_info.serialize())

    for field in fields:
        client.provide_transaction_field_desc(field.serialize())
        if field.param.type == ParamType.CALLDATA:
            client.provide_transaction_info(sub_tx_info.serialize())
            for sub_field in sub_fields:
                client.provide_transaction_field_desc(sub_field.serialize())

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


# https://etherscan.io/tx/0x5047fedc98f46d2afd94d0a2813ddf0c8fe777ec0739ffd327586a91e1e5a89a
def test_gcs_nested_execTransaction_changeThreshold(
        scenario_navigator: NavigateWithScenario):
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)

    contract_addr = bytes.fromhex("23F8abfC2824C397cCB3DA89ae772984107dDB99")
    with Path(f"{ABIS_FOLDER}/safe_1.4.1.abi.json").open(
            encoding="utf-8") as f:
        contract = Web3().eth.contract(abi=json.load(f), address=contract_addr)
    sub_data = contract.encode_abi("changeThreshold", [3])
    data = contract.encode_abi("execTransaction", [
        contract_addr,
        to_sun(0),
        sub_data,
        0,
        0,
        0,
        0,
        bytes.fromhex("0000000000000000000000000000000000000000"),
        bytes.fromhex("0000000000000000000000000000000000000000"),
        bytes.fromhex(
            "d3a6ddfb9dffe883d609129d9e87dda928a4a9b9d5d2f4a93879d03"
            "ccb0d32b12df7dcf9acd9c5f73443c82b0e01183794436a381148cf"
            "2fb928f7df776a01701b2fc9ebbc15bfdae0f5ef1b6f4ad1389d31"
            "f1dc137e51e7a184e255fd0ed065911ad684bd97ee43892013b4ee"
            "bdaec528020ed657b92b90562f4df5a18540e4b91b"),
    ])
    param_paths = get_all_paths(f"{ABIS_FOLDER}/safe_1.4.1.abi.json",
                                "execTransaction")
    fields = [
        Field(
            1,
            "to",
            ParamTrustedName(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["to"])),
                [TrustedNameType.ACCOUNT],
                [TrustedNameSource.MULTISIG_ADDRESS_BOOK],
            ),
        ),
        Field(
            1,
            "value",
            ParamAmount(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["value"])),
            ),
        ),
        Field(
            1,
            "data",
            ParamCalldata(
                1,
                Value(1,
                      TypeFamily.BYTES,
                      data_path=DataPath(1, param_paths["data"])),
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["to"])),
            ),
        ),
        Field(
            1,
            "operation",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=1,
                      data_path=DataPath(1, param_paths["operation"])),
            ),
        ),
        Field(
            1,
            "safeTxGas",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["safeTxGas"])),
            ),
        ),
        Field(
            1,
            "dataGas",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["baseGas"])),
            ),
        ),
        Field(
            1,
            "gasPrice",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["gasPrice"])),
            ),
        ),
        Field(
            1,
            "gasToken",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["gasToken"])),
            ),
        ),
        Field(
            1,
            "refundReceiver",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["refundReceiver"])),
            ),
        ),
        Field(
            1,
            "signatures",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.BYTES,
                      data_path=DataPath(1, param_paths["signatures"])),
            ),
        ),
    ]

    tx_info = TxInfo(
        1,
        TRON_MAINNET_CHAINID,
        eth_to_tron_base58(contract_addr),
        get_selector_from_data(data),
        compute_inst_hash(fields),
        "execute a Safe action",
        creator_name="Safe",
        creator_legal_name="Safe Ecosystem Foundation",
        creator_url="safe.global",
    )
    param_paths = get_all_paths(f"{ABIS_FOLDER}/safe_1.4.1.abi.json",
                                "changeThreshold")
    sub_fields = [
        Field(
            1,
            "newThreshold",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["_threshold"])),
            ),
        ),
    ]
    sub_tx_info = TxInfo(1, TRON_MAINNET_CHAINID, eth_to_tron_base58(contract_addr),
                         get_selector_from_data(sub_data),
                         compute_inst_hash(sub_fields), "change threshold")

    derivation_path = client.getAccount(0)["path"]
    wallet_addr = bytes.fromhex(client.getAccount(0)["addressHex"])[1:]
    client.provide_trusted_name(
        TrustedName(2,
                    eth_to_tron_base58(contract_addr),
                    "My Safe",
                    tn_type=TrustedNameType.ACCOUNT,
                    tn_source=TrustedNameSource.MULTISIG_ADDRESS_BOOK,
                    chain_id=tx_info.chain_id,
                    challenge=get_challenge(client),
                    owner=wallet_addr,
                    owner_deriv_path=derivation_path))

    tx = _store_contract_call(client, backend, contract_addr, data)
    client.provide_transaction_info(tx_info.serialize())

    for field in fields:
        client.provide_transaction_field_desc(field.serialize())
        if field.param.type == ParamType.CALLDATA:
            client.provide_transaction_info(sub_tx_info.serialize())
            for sub_field in sub_fields:
                client.provide_transaction_field_desc(sub_field.serialize())

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


def test_gcs_nested_no_param(scenario_navigator: NavigateWithScenario):
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)

    sub_contract_addr = bytes.fromhex("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")
    with Path(f"{ABIS_FOLDER}/erc20.json").open(encoding="utf-8") as f:
        sub_contract = Web3().eth.contract(abi=json.load(f),
                                           address=sub_contract_addr)
    sub_data = sub_contract.encode_abi("totalSupply", [])

    contract_addr = bytes.fromhex("23F8abfC2824C397cCB3DA89ae772984107dDB99")
    with Path(f"{ABIS_FOLDER}/safe_1.4.1.abi.json").open(
            encoding="utf-8") as f:
        contract = Web3().eth.contract(abi=json.load(f), address=contract_addr)
    data = contract.encode_abi("execTransaction", [
        sub_contract_addr,
        to_sun(0),
        sub_data,
        0,
        0,
        0,
        0,
        bytes.fromhex("0000000000000000000000000000000000000000"),
        bytes.fromhex("0000000000000000000000000000000000000000"),
        bytes(),
    ])
    tx = _store_contract_call(client, backend, contract_addr, data)

    param_paths = get_all_paths(f"{ABIS_FOLDER}/safe_1.4.1.abi.json",
                                "execTransaction")
    fields = [
        Field(
            1,
            "data",
            ParamCalldata(
                1,
                Value(1,
                      TypeFamily.BYTES,
                      data_path=DataPath(1, param_paths["data"])),
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["to"])),
            ),
        ),
    ]

    tx_info = TxInfo(
        1,
        TRON_MAINNET_CHAINID,
        eth_to_tron_base58(contract_addr),
        get_selector_from_data(data),
        compute_inst_hash(fields),
        "execute a Safe action",
        creator_name="Safe",
        creator_legal_name="Safe Ecosystem Foundation",
        creator_url="safe.global",
    )
    client.provide_transaction_info(tx_info.serialize())

    sub_tx_info = TxInfo(
        1,
        TRON_MAINNET_CHAINID,
        eth_to_tron_base58(sub_contract_addr),
        get_selector_from_data(sub_data),
        hashlib.sha3_256().digest(),
        "get total supply",
        creator_name="WETH",
        creator_legal_name="Wrapped Ether",
        creator_url="weth.io",
    )

    for field in fields:
        client.provide_transaction_field_desc(field.serialize())
        if field.param.type == ParamType.CALLDATA:
            client.provide_transaction_info(sub_tx_info.serialize())

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


def test_gcs_no_param(scenario_navigator: NavigateWithScenario):
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)

    contract_addr = bytes.fromhex("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")
    with Path(f"{ABIS_FOLDER}/erc20.json").open(encoding="utf-8") as f:
        contract = Web3().eth.contract(abi=json.load(f), address=contract_addr)
    data = contract.encode_abi("totalSupply", [])
    tx = _store_contract_call(client, backend, contract_addr, data)

    tx_info = TxInfo(
        1,
        TRON_MAINNET_CHAINID,
        eth_to_tron_base58(contract_addr),
        get_selector_from_data(data),
        hashlib.sha3_256().digest(),
        "get total supply",
        creator_name="WETH",
        creator_legal_name="Wrapped Ether",
        creator_url="weth.io",
    )
    client.provide_transaction_info(tx_info.serialize())

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


def test_gcs_trusted_name_token(scenario_navigator: NavigateWithScenario):
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)

    tokens = [
        {
            "name": "WETH",
            "address": bytes.fromhex("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
        },
        {
            "name": "USDC",
            "address": bytes.fromhex("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
        },
    ]

    with Path(f"{ABIS_FOLDER}/1inch.abi.json").open(encoding="utf-8") as f:
        contract = Web3().eth.contract(abi=json.load(f), address=None)
    data = contract.encode_abi("swap", [
        bytes.fromhex("F313B370D28760b98A2E935E56Be92Feb2c4EC04"),
        [
            tokens[0]["address"],
            tokens[1]["address"],
            bytes.fromhex("F313B370D28760b98A2E935E56Be92Feb2c4EC04"),
            bytes.fromhex("Dad77910DbDFdE764fC21FCD4E74D71bBACA6D8D"),
            to_units("0.22", 18),
            682119805,
            0,
        ],
        bytes(),
    ])
    contract_addr20 = bytes.fromhex("111111125421cA6dc452d289314280a0f8842A65")
    param_paths = get_all_tuple_paths(f"{ABIS_FOLDER}/1inch.abi.json", "swap",
                                      "desc")
    fields = [
        Field(
            1,
            "Send token",
            ParamTrustedName(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["srcToken"])),
                [TrustedNameType.TOKEN],
                [TrustedNameSource.CAL],
            ),
        ),
        Field(
            1,
            "Receive token",
            ParamTrustedName(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["dstToken"])),
                [TrustedNameType.TOKEN],
                [TrustedNameSource.CAL],
            ),
        ),
    ]

    tx_info = TxInfo(
        1,
        TRON_MAINNET_CHAINID,
        eth_to_tron_base58(contract_addr20),
        get_selector_from_data(data),
        compute_inst_hash(fields),
        "swap",
        creator_name="1inch",
        creator_legal_name="1inch Network",
        creator_url="1inch.io",
        contract_name="Aggregation Router V6",
        deploy_date=1707724800,
    )
    for i in range(len(fields)):
        client.provide_trusted_name(
            TrustedName(2,
                        eth_to_tron_base58(tokens[i]["address"]),
                        tokens[i]["name"],
                        tn_type=TrustedNameType.TOKEN,
                        tn_source=TrustedNameSource.CAL,
                        chain_id=TRON_MAINNET_CHAINID,
                        challenge=get_challenge(client)))

    tx = _store_contract_call(client, backend, contract_addr20, data)
    client.provide_transaction_info(tx_info.serialize())
    for field in fields:
        client.provide_transaction_field_desc(field.serialize())

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


def test_gcs_batch(scenario_navigator: NavigateWithScenario):
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)

    tokens = [
        {
            "ticker": "USDT",
            "address": bytes.fromhex("dac17f958d2ee523a2206206994597c13d831ec7"),
            "decimals": 6,
        },
        {
            "ticker": "WETH",
            "address": bytes.fromhex("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
            "decimals": 18,
        },
    ]
    with Path(f"{ABIS_FOLDER}/erc20.json").open(encoding="utf-8") as f:
        contract = Web3().eth.contract(abi=json.load(f), address=None)
    data0 = contract.encode_abi("transfer", [
        bytes.fromhex("0000000000000000000000000000000000000000"),
        int(500 * pow(10, tokens[0]["decimals"])),
    ])
    data1 = contract.encode_abi("transfer", [
        bytes.fromhex("1111111111111111111111111111111111111111"),
        int(0.25 * pow(10, tokens[1]["decimals"])),
    ])

    with Path(f"{ABIS_FOLDER}/batch.json").open(encoding="utf-8") as f:
        contract = Web3().eth.contract(abi=json.load(f),
                                       address=tokens[1]["address"])
    data = contract.encode_abi("batchExecute", [[
        (tokens[0]["address"], to_sun(0), data0),
        (tokens[1]["address"], to_sun(0), data1),
    ]])
    param_paths = get_all_paths(f"{ABIS_FOLDER}/erc20.json", "transfer")
    sub_fields = [
        Field(
            1,
            "To",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["_to"])),
            ),
        ),
        Field(
            1,
            "Amount",
            ParamTokenAmount(
                1,
                Value(1,
                      TypeFamily.UINT,
                      32,
                      DataPath(1, param_paths["_value"])),
                Value(1, TypeFamily.ADDRESS, container_path=ContainerPath.TO),
            ),
        ),
    ]

    param_paths = get_all_tuple_array_paths(f"{ABIS_FOLDER}/batch.json",
                                            "batchExecute", "calls")
    fields = [
        Field(
            1,
            "Destination",
            ParamCalldata(
                1,
                Value(1,
                      TypeFamily.BYTES,
                      data_path=DataPath(1, param_paths["data"])),
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["to"])),
                amount=Value(1,
                             TypeFamily.UINT,
                             data_path=DataPath(1, param_paths["value"])),
            ),
        ),
    ]

    tx_info = TxInfo(
        1,
        TRON_MAINNET_CHAINID,
        eth_to_tron_base58(tokens[1]["address"]),
        get_selector_from_data(data),
        compute_inst_hash(fields),
        "Batch transaction",
        creator_name="WETH",
        creator_legal_name="Wrapped Ether",
        creator_url="weth.io",
    )
    sub_inst_hash = compute_inst_hash(sub_fields)
    sub_tx_info = [
        TxInfo(
            1,
            TRON_MAINNET_CHAINID,
            eth_to_tron_base58(tokens[0]["address"]),
            get_selector_from_data(data0),
            sub_inst_hash,
            "Transfer token",
        ),
        TxInfo(
            1,
            TRON_MAINNET_CHAINID,
            eth_to_tron_base58(tokens[1]["address"]),
            get_selector_from_data(data1),
            sub_inst_hash,
            "Transfer token",
        ),
    ]

    for token in tokens:
        client.provide_token_metadata(token["ticker"],
                                      eth_to_tron_base58(token["address"]),
                                      token["decimals"], TRON_MAINNET_CHAINID)

    tx = _store_contract_call(client, backend, tokens[1]["address"], data)
    client.provide_transaction_info(tx_info.serialize())
    for field in fields:
        client.provide_transaction_field_desc(field.serialize())
        for sub_info in sub_tx_info:
            client.provide_transaction_info(sub_info.serialize())
            for sub_field in sub_fields:
                client.provide_transaction_field_desc(sub_field.serialize())

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


def test_gcs_batch_2(scenario_navigator: NavigateWithScenario):
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)

    tokens = [
        {
            "ticker": "USDC",
            "address": bytes.fromhex("3c499c542cef5e3811e1192ce70d8cc03d5c3359"),
            "decimals": 6,
        },
        {
            "ticker": "USDC",
            "address": bytes.fromhex("3c499c542cef5e3811e1192ce70d8cc03d5c3359"),
            "decimals": 6,
        },
    ]
    with Path(f"{ABIS_FOLDER}/erc20.json").open(encoding="utf-8") as f:
        contract = Web3().eth.contract(abi=json.load(f), address=None)
    token_data0 = contract.encode_abi("transfer", [
        bytes.fromhex("B8C8EB8EFC68796E766F6AB320DB8C165C064949"),
        int(0.004 * pow(10, tokens[0]["decimals"])),
    ])
    token_data1 = contract.encode_abi("transfer", [
        bytes.fromhex("4DDA64E1EC1A2C00D0766F25877F6A3BC77F717E"),
        int(0.008 * pow(10, tokens[1]["decimals"])),
    ])

    with Path(f"{ABIS_FOLDER}/batch.json").open(encoding="utf-8") as f:
        batch_contract = Web3().eth.contract(abi=json.load(f),
                                             address=tokens[1]["address"])
    batch_data = batch_contract.encode_abi("batchExecute", [[
        (tokens[0]["address"], to_sun(0), token_data0),
        (tokens[1]["address"], to_sun(0), token_data1),
    ]])

    safe_addr = bytes.fromhex("60aa01971a2adc1d6b2b59b972fb47b2fec095fc")
    with Path(f"{ABIS_FOLDER}/safe_1.4.1.abi.json").open(
            encoding="utf-8") as f:
        contract = Web3().eth.contract(abi=json.load(f), address=safe_addr)
    exec_data_signature = (
        "93a3e6ff4d0798d51ba53f5d8287326adbe3e22dd0dc28bdbfab825be357"
        "ce8c76a13b8128f5d91530af675925220ede099e0f0a51af3a65760060"
        "d4b37db9281c")
    exec_tx_data = contract.encode_abi("execTransaction", [
        safe_addr,
        0,
        batch_data,
        1,
        0,
        0,
        0,
        bytes.fromhex("0000000000000000000000000000000000000000"),
        bytes.fromhex("0000000000000000000000000000000000000000"),
        bytes.fromhex(exec_data_signature),
    ])

    tx_to = bytes.fromhex("19a4d6928cd3b32Fa4Eb3962bfF1Abca91EB7C52")

    param_paths = get_all_paths(f"{ABIS_FOLDER}/safe_1.4.1.abi.json",
                                "execTransaction")
    l0_fields = [
        Field(
            1,
            "From Safe",
            ParamTrustedName(
                1,
                Value(1, TypeFamily.ADDRESS, container_path=ContainerPath.TO),
                [TrustedNameType.CONTRACT],
                [TrustedNameSource.CAL],
            ),
        ),
        Field(
            1,
            "Execution signer",
            ParamTrustedName(
                1,
                Value(1, TypeFamily.ADDRESS, container_path=ContainerPath.FROM),
                [TrustedNameType.ACCOUNT],
                [
                    TrustedNameSource.ENS,
                    TrustedNameSource.UD,
                    TrustedNameSource.FN,
                ],
            ),
        ),
        Field(
            1,
            "Transaction",
            ParamCalldata(
                1,
                Value(1,
                      TypeFamily.BYTES,
                      data_path=DataPath(1, param_paths["data"])),
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["to"])),
                amount=Value(1,
                             TypeFamily.UINT,
                             type_size=32,
                             data_path=DataPath(1, param_paths["value"])),
                spender=Value(1,
                              TypeFamily.ADDRESS,
                              container_path=ContainerPath.TO),
            ),
        ),
        Field(
            1,
            "Gas amount",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["safeTxGas"])),
            ),
        ),
        Field(
            1,
            "Gas price",
            ParamTokenAmount(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["baseGas"])),
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["gasPrice"])),
                [bytes.fromhex("0000000000000000000000000000000000000000")],
            ),
        ),
        Field(
            1,
            "Gas receiver",
            ParamTrustedName(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["refundReceiver"])),
                [
                    TrustedNameType.ACCOUNT,
                    TrustedNameType.CONTRACT,
                    TrustedNameType.TOKEN,
                ],
                [
                    TrustedNameSource.CAL,
                    TrustedNameSource.ENS,
                    TrustedNameSource.UD,
                    TrustedNameSource.FN,
                ],
            ),
        ),
    ]
    l0_tx_info = TxInfo(
        1,
        TRON_MAINNET_CHAINID,
        eth_to_tron_base58(bytes.fromhex("29fcb43b46531bca003ddc8fcb67ffe91900c762")),
        get_selector_from_data(exec_tx_data),
        compute_inst_hash(l0_fields),
        "sign multisig operation",
        creator_name="Safe",
        creator_legal_name="Safe{Wallet}",
        creator_url="https://app.safe.global/welcome",
        contract_name="SafeL2",
    )

    param_paths = get_all_tuple_array_paths(f"{ABIS_FOLDER}/batch.json",
                                            "batchExecute", "calls")
    l1_fields = [
        Field(
            1,
            "Transaction",
            ParamCalldata(
                1,
                Value(1,
                      TypeFamily.BYTES,
                      data_path=DataPath(1, param_paths["data"])),
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["to"])),
                amount=Value(1,
                             TypeFamily.UINT,
                             data_path=DataPath(1, param_paths["value"])),
            ),
        ),
    ]
    l1_hash = compute_inst_hash(l1_fields)
    l1_tx_info = [
        TxInfo(1,
               TRON_MAINNET_CHAINID,
               eth_to_tron_base58(safe_addr),
               get_selector_from_data(batch_data),
               l1_hash,
               "Batch transactions",
               creator_name="Ledger",
               creator_legal_name="Ledger Multisig",
               creator_url="https://www.ledger.com",
               contract_name="BatchExecutor"),
    ]

    param_paths = get_all_paths(f"{ABIS_FOLDER}/erc20.json", "transfer")
    l2_fields = [
        Field(
            1,
            "Amount",
            ParamTokenAmount(
                1,
                Value(1,
                      TypeFamily.UINT,
                      data_path=DataPath(1, param_paths["_value"]),
                      type_size=32),
                Value(1, TypeFamily.ADDRESS, container_path=ContainerPath.TO),
            ),
        ),
        Field(
            1,
            "To",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["_to"])),
            ),
        ),
    ]
    l2_hash = compute_inst_hash(l2_fields)
    l2_tx_info = [
        TxInfo(1, TRON_MAINNET_CHAINID, eth_to_tron_base58(tokens[0]["address"]),
               get_selector_from_data(token_data0), l2_hash, "Send",
               contract_name="USD_Coin"),
        TxInfo(1, TRON_MAINNET_CHAINID, eth_to_tron_base58(tokens[1]["address"]),
               get_selector_from_data(token_data1), l2_hash, "Send",
               contract_name="USD_Coin"),
    ]

    client.provide_proxy_info(
        ProxyInfo(get_challenge(client), eth_to_tron_base58(tx_to), l0_tx_info.chain_id,
                  l0_tx_info.contract_addr).serialize())
    for token in tokens:
        client.provide_token_metadata(token["ticker"],
                                      eth_to_tron_base58(token["address"]),
                                      token["decimals"], TRON_MAINNET_CHAINID)

    tx = _store_contract_call(client, backend, tx_to, exec_tx_data)
    client.provide_transaction_info(l0_tx_info.serialize())

    for f0 in l0_fields:
        client.provide_transaction_field_desc(f0.serialize())
        if f0.param.type == ParamType.CALLDATA:
            for i1 in l1_tx_info:
                client.provide_transaction_info(i1.serialize())
                for f1 in l1_fields:
                    client.provide_transaction_field_desc(f1.serialize())

                for i2 in l2_tx_info:
                    client.provide_transaction_info(i2.serialize())
                    for f2 in l2_fields:
                        client.provide_transaction_field_desc(f2.serialize())

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


def test_gcs_batch_complex(scenario_navigator: NavigateWithScenario) -> None:
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)

    tokens = [
        {
            "ticker": "USDT",
            "address": bytes.fromhex("dac17f958d2ee523a2206206994597c13d831ec7"),
            "decimals": 6,
        },
        {
            "ticker": "WETH",
            "address": bytes.fromhex("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
            "decimals": 18,
        },
    ]
    with Path(f"{ABIS_FOLDER}/erc20.json").open(encoding="utf-8") as f:
        contract = Web3().eth.contract(abi=json.load(f), address=None)
    data0 = contract.encode_abi("transfer", [
        bytes.fromhex("1111111111111111111111111111111111111111"),
        int(1.1 * pow(10, tokens[0]["decimals"])),
    ])
    data1 = contract.encode_abi("transfer", [
        bytes.fromhex("3333333333333333333333333333333333333333"),
        int(3.3 * pow(10, tokens[1]["decimals"])),
    ])

    with Path(f"{ABIS_FOLDER}/batch.json").open(encoding="utf-8") as f:
        contract = Web3().eth.contract(abi=json.load(f),
                                       address=BATCH_CONTRACT20)
    data = contract.encode_abi("batchExecute", [[
        (bytes.fromhex("0000000000000000000000000000000000000000"),
         to_sun(0), b""),
        (tokens[0]["address"], to_sun(0), data0),
        (bytes.fromhex("2222222222222222222222222222222222222222"),
         to_sun("2.2"), b""),
        (tokens[1]["address"], to_sun(0), data1),
        (bytes.fromhex("4444444444444444444444444444444444444444"),
         to_sun("4.4"), b""),
    ]])
    param_paths = get_all_paths(f"{ABIS_FOLDER}/erc20.json", "transfer")
    sub_fields = [
        Field(
            1,
            "To",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["_to"])),
            ),
        ),
        Field(
            1,
            "Amount",
            ParamTokenAmount(
                1,
                Value(1,
                      TypeFamily.UINT,
                      32,
                      DataPath(1, param_paths["_value"])),
                Value(1, TypeFamily.ADDRESS, container_path=ContainerPath.TO),
            ),
        ),
    ]

    param_paths = get_all_tuple_array_paths(f"{ABIS_FOLDER}/batch.json",
                                            "batchExecute", "calls")
    fields = [
        Field(
            1,
            "Destination",
            ParamCalldata(
                1,
                Value(1,
                      TypeFamily.BYTES,
                      data_path=DataPath(1, param_paths["data"])),
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["to"])),
                amount=Value(1,
                             TypeFamily.UINT,
                             data_path=DataPath(1, param_paths["value"])),
            ),
        ),
    ]

    tx_info = TxInfo(
        1,
        TRON_MAINNET_CHAINID,
        eth_to_tron_base58(BATCH_CONTRACT20),
        get_selector_from_data(data),
        compute_inst_hash(fields),
        "Batch transaction",
        creator_name="Ledger Multisig",
        creator_legal_name="Ledger",
    )
    client.provide_trusted_name(
        TrustedName(2,
                    eth_to_tron_base58(b"\x00" * 20),
                    "null.eth",
                    tn_type=TrustedNameType.ACCOUNT,
                    tn_source=TrustedNameSource.ENS,
                    chain_id=TRON_MAINNET_CHAINID,
                    challenge=get_challenge(client)))

    derivation_path = client.getAccount(0)["path"]
    wallet_addr = bytes.fromhex(client.getAccount(0)["addressHex"])[1:]
    client.provide_trusted_name(
        TrustedName(2,
                    eth_to_tron_base58(b"\x44" * 20),
                    "FOUR",
                    tn_type=TrustedNameType.ACCOUNT,
                    tn_source=TrustedNameSource.MULTISIG_ADDRESS_BOOK,
                    chain_id=TRON_MAINNET_CHAINID,
                    challenge=get_challenge(client),
                    owner=wallet_addr,
                    owner_deriv_path=derivation_path))

    for token in tokens:
        client.provide_token_metadata(token["ticker"],
                                      eth_to_tron_base58(token["address"]),
                                      token["decimals"], TRON_MAINNET_CHAINID)

    tx = _store_contract_call(client, backend, BATCH_CONTRACT20, data)
    client.provide_transaction_info(tx_info.serialize())

    sub_inst_hash = compute_inst_hash(sub_fields)
    sub_tx_info = [
        TxInfo(1, TRON_MAINNET_CHAINID, eth_to_tron_base58(tokens[0]["address"]),
               get_selector_from_data(data0), sub_inst_hash, "Transfer token"),
        TxInfo(1, TRON_MAINNET_CHAINID, eth_to_tron_base58(tokens[1]["address"]),
               get_selector_from_data(data1), sub_inst_hash, "Transfer token"),
    ]

    for field in fields:
        client.provide_transaction_field_desc(field.serialize())
        for sub_info in sub_tx_info:
            client.provide_transaction_info(sub_info.serialize())
            for sub_field in sub_fields:
                client.provide_transaction_field_desc(sub_field.serialize())

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


def _gcs_send_descriptor(client: TronClient, backend: BackendInterface,
                         fields: list[Field],
                         provision=None) -> bytes:
    """[provision] -> STORE -> 0x26 -> 0x28(xN); returns the parked tx.

    GCS freezes external metadata when STORE begins, so optional signed metadata
    is provisioned first and is already in place when FIELD formatting starts.
    """
    tx = build_trc20_transfer_tx(client)
    if provision is not None:
        provision()
    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], tx) == StatusWord.OK
    contract_addr20 = bytes.fromhex(client.address_hex(TRC20_CONTRACT_B58))[1:]
    tx_info = build_tx_info(contract_addr20, TRC20_TRANSFER_SELECTOR, fields,
                            "transfer")
    client.provide_transaction_info(tx_info)
    for field in fields:
        client.provide_transaction_field_desc(field.serialize())
    return tx

def test_gcs_amount_decimals(scenario_navigator: NavigateWithScenario):
    """AMOUNT field renders native TRX with 6 decimals (SUN_TO_TRX), not 18.

    Calldata _amount = 0xf4240 = 1_000_000; with TRON's 6 decimals this is
    "1 TRX". The old app-ethereum WEI_TO_ETHER (18) bug would render
    "0.000000000001 TRX", so the snapshot is the regression guard for the fix.
    """
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)
    amount_field = build_field_amount("Amount", 32,
                                      data_path=build_data_path_static(1))
    tx = _gcs_send_descriptor(client, backend, [amount_field])

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


def test_gcs_datetime(scenario_navigator: NavigateWithScenario):
    """DATETIME (DT_UNIX) field renders the calldata word as a UTC timestamp.

    Calldata word = 0xf4240 = 1_000_000 seconds since the epoch, which
    time_format_to_utc() renders as "1970-01-12 ... UTC" in the snapshot.
    """
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)
    dt_field = build_field_datetime("Deadline", 32,
                                    data_path=build_data_path_static(1))
    tx = _gcs_send_descriptor(client, backend, [dt_field])

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


# `transfer(address _to, uint256 _amount)` arg0 (_to) doubles as a stand-in token
# address: we register it via INS_PROVIDE_TRC20_TOKEN_INFORMATION so the
# TOKEN_AMOUNT formatter resolves it to a ticker/decimals from the TRC20 registry.
TKN_ADDR20 = bytes.fromhex("364b03e0815687edaf90b81ff58e496dea7383d7")


def test_gcs_token_amount(scenario_navigator: NavigateWithScenario):
    """TOKEN_AMOUNT resolves the token via the TRC20 registry (trc_tokens).

    arg0 is registered as "TKN" with 6 decimals; the amount word arg1 =
    1_000_000 then renders as "1 TKN" in the snapshot using the registry's
    decimals/ticker.
    """
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)
    field = build_field_token_amount("Amount",
                                     value_path=build_data_path_static(1),
                                     token_path=build_data_path_static(0))

    def provision() -> None:
        client.provide_token_metadata("TKN", eth_to_tron_base58(TKN_ADDR20), 6,
                                      TRON_MAINNET_CHAINID)

    tx = _gcs_send_descriptor(client, backend, [field], provision=provision)

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


def test_gcs_trusted_name(scenario_navigator: NavigateWithScenario):
    """TRUSTED_NAME resolves a calldata address via provideTrustedName (0x22).

    arg0 is registered as the account name "alice.eth"; the GCS TRUSTED_NAME
    field over arg0 then renders that name in the snapshot instead of the raw
    address -- the provideTrustedName path unblocked by get_public_key().
    """
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)
    field = build_field_trusted_name("To",
                                     addr_path=build_data_path_static(0),
                                     types=[TrustedNameType.ACCOUNT],
                                     sources=[TrustedNameSource.ENS])

    def provision() -> None:
        client.provide_trusted_name(
            TrustedName(2,
                        eth_to_tron_base58(TKN_ADDR20),
                        "alice.eth",
                        tn_type=TrustedNameType.ACCOUNT,
                        tn_source=TrustedNameSource.ENS,
                        chain_id=TRON_MAINNET_CHAINID,
                        challenge=get_challenge(client)))

    tx = _gcs_send_descriptor(client, backend, [field], provision=provision)

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


def test_gcs_enum(scenario_navigator: NavigateWithScenario):
    """ENUM field resolves a calldata byte via provide_enum_value (INS 0x24).

    arg1's low byte is 0x40 (0xf4240 & 0xff); an enum descriptor maps
    (contract, selector, id=0, value=0x40) -> "Deposit", which the ENUM field
    then renders in the snapshot instead of the raw value.
    """
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)
    contract_addr20 = bytes.fromhex(client.address_hex(TRC20_CONTRACT_B58))[1:]
    field = build_field_enum("Action", enum_id=0,
                             value_path=build_data_path_static(1))

    def provision() -> None:
        enum_desc = build_enum_value(contract_addr20, TRC20_TRANSFER_SELECTOR,
                                     enum_id=0, value=0x40, name="Deposit")
        client.provide_enum_value(enum_desc)

    tx = _gcs_send_descriptor(client, backend, [field], provision=provision)

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)
