from client.tip712 import EncodeTokenInfo

def test_encode_tokeninfo_single():
    expected_blob = "AAAAaAV0VVNEQ3X68RTq+xvb4vAxbfiT/VjORqpNAAAABgAGbu4wRAIgFKnUYlqkCIMEeWAIauo7Q1vQEZoxL6bBLWn3nc8z/ngCIBjt3QKT5fZ9+Du9rmEJx22NfCoKJbOIPIgD05s4tQ0D"
    entries = [
        {
            "ticker": "tUSDC",
            "contractAddress": "0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d",
            "decimals": 6,
            "chainId": 421614,
            "signature": "3044022014a9d4625aa40883047960086aea3b435bd0119a312fa6c12d69f79dcf33fe78022018eddd0293e5f67df83bbdae6109c76d8d7c2a0a25b3883c8803d39b38b50d03",  # signature
        }
    ]

    blob = EncodeTokenInfo.encode_token_info(entries)
    assert blob == expected_blob

def test_encode_tokeninfo_multiple():
    expected_blob = "AAAAaAV0TElOS9FIOKaOivut5e+0EdWHHqABGv0oAAAAEgAGbu0wRAIgWsY1F7aaUAqUpHqfHjNeO3HayMiqFJ897Y5TDfV9twACICt+ohleHRzE3UywVVgcI5hrLxugWN7RwEigOl8IMGI3AAAAZwR0RkFVQcu6AYxO+QMDldqKiCwyyP67jVYAAAASAAZu7TBEAiAcWfQ09QODXDCpoTKGHa+0vl28xjU3VEYAfPaaAwca1gIgMqDKz5Sa8Luva0ZEzcvbSHPWM1bENLAGxdA8ZUp/GKw="
    entries = [
        {
            "ticker": "tLINK",
            "contractAddress": "0xd14838A68E8AFBAdE5efb411d5871ea0011AFd28",
            "decimals": 18,
            "chainId": 421613,
            "signature": "304402205ac63517b69a500a94a47a9f1e335e3b71dac8c8aa149f3ded8e530df57db70002202b7ea2195e1d1cc4dd4cb055581c23986b2f1ba058ded1c048a03a5f08306237",  # signature
        },
        {
            "ticker": "tFAU",
            "contractAddress": "0x41Cbba018C4EF9030395da8A882c32c8FEBb8d56",
            "decimals": 18,
            "chainId": 421613,
            "signature": "304402201c59f434f503835c30a9a132861dafb4be5dbcc635375446007cf69a03071ad6022032a0cacf949af0bbaf6b4644cdcbdb4873d63356c434b006c5d03c654a7f18ac",  # signature
        }
    ]

    blob = EncodeTokenInfo.encode_token_info(entries)
    assert blob == expected_blob