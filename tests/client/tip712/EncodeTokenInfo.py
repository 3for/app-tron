import base64
import struct

def encode_token_info(entries):
    """
    Encode a list of TokenInfo into a base64 string.
    entries: list[dict]  Each dict structure:
        {
          "ticker": str,
          "contractAddress": str,  # hex string (40 chars, without 0x)
          "decimals": int,
          "chainId": int,
          "signature": str         # hex string (e.g., DER signature)
        }
    """
    buf = b""

    for entry in entries:
        ticker_bytes = entry["ticker"].encode("ascii")
        ticker_len = len(ticker_bytes)

        # Convert contract address to bytes
        contract_bytes = bytes.fromhex(entry["contractAddress"].lower().replace("0x", ""))
        if len(contract_bytes) != 20:
            raise ValueError("contractAddress must be 20 bytes")

        decimals = entry["decimals"]
        chain_id = entry["chainId"]

        # Convert signature hex string → bytes
        sig_hex = entry.get("signature", "")
        signature = bytes.fromhex(sig_hex) if sig_hex else b""

        # item does not include the 4-byte length prefix
        item = b""
        item += struct.pack("B", ticker_len)              # 1 byte ticker length
        item += ticker_bytes                             # ticker
        item += contract_bytes                           # 20-byte contract address
        item += struct.pack(">I", decimals)              # 4-byte decimals (big-endian)
        item += struct.pack(">I", chain_id)              # 4-byte chainId (big-endian)
        item += signature                                # remaining bytes (signature)

        # prepend with item length (4-byte big-endian)
        buf += struct.pack(">I", len(item)) + item

    # convert to base64
    return base64.b64encode(buf).decode("ascii")
