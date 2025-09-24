export const v2 = {
  "5:0xcccccccccccccccccccccccccccccccccccccccc:1fd77fb96a82b9c1de173fa836e20da791158ea832a3d07c6725f47c": {
    "contractName": {
      "label": "Anakin",
      "signature": "30440220014ab9506fa7ea26d6f695ea2ce2cd3742852c54ce1793cfd1ca462aabd93d39022033e3b7d399cec2eaabc0e9f595f20dea2182fe9915a0fcde266de068a788a149"
    },
    "fields": [
      {
        "path": "from.name",
        "format": "raw",
        "label": "From",
        "signature": "304502204184ab24eef5044a949d9dd4ab32daa7707633f40025c9ac93501b54a533742b022100eda25753ccbc815233ced751bee6f3cee480db54934b50733db4895e12198213"
      },
      {
        "path": "to.name",
        "format": "raw",
        "label": "To",
        "signature": "3044022057d81ea65f2a51d88cfee2f567fc8eb4d416cc2036a0473342c082ef1b36a225022026ffe715e5e8e6b1da399a5197ef8bb77a64bf7ff93849a01c160d0ef928106e"
      }
    ]
  },
  "5:0xcccccccccccccccccccccccccccccccccccccccc:f9a315b6c68ed811063e25014e88de5b2739ebc23fae9f15f8e0a0ce": {
    "contractName": {
      "label": "Chewie",
      "signature": "30450221009c88b2b389c53633a6acf8ac6e8eba336f9c6e8608e57f893480c4f227a4e078022010a4a7fcda49f396a44475c4374e86c39677ddfc5eb32e00d03f8d6d400d67ac"
    },
    "fields": [
      {
        "path": "from.name",
        "format": "raw",
        "label": "Sender",
        "signature": "3044022006c52c632b4b4ffd842d94abf16b505ad2ac1b92077c9ecec3e7a61e48c9963a022041652a972b7c62fecc4dafcfec49e087ed2f75c980edfb534670a6c3e07181ec"
      },
      {
        "path": "to.[].wallets.[]",
        "format": "raw",
        "label": "Recipients",
        "signature": "3045022100a8359190d4c9080c8becc70a01d931670fbf48af8552f25df8f1858192e88fce02205f939ca4bb8ec2ef2cb7cae1eb81a0ab42a117d92834ac9e414235e43838da2c"
      },
      {
        "path": "contents",
        "format": "raw",
        "label": "Message",
        "signature": "304502207d90a4e2be387cf5398e5d0462220ad3109788b4998b60b8cd3ee6732be22211022100bbc5db913dcbe28a63042eeaa85f952757fe8fa43befd92b72e22630ff1d2325"
      }
    ]
  },
  "1:0x7f268357a8c2552623316e2562d90e642bb538e5:d8e4f2bd77f7562e99ea5df4adb127291a2bfbc225ae55450038f27f": {
    "contractName": {
      "label": "Mace Windu",
      "signature": "3045022073cc8d51f50a641c5f649816afe149d68b4fe1991184d589bc11512b83fd0e6c022100adf59978f2a5d69a0044518407cb15d1540a7e291c9614f7095c718797e5c5cc"
    },
    "fields": [
      {
        "path": "maker",
        "format": "raw",
        "label": "Maker",
        "signature": "3045022045440d9956eab04674470ecf319d5957997088afccad4ac24f4c2938f4527d10022100aed8c198ef0eb7803fd3e87378fa7e8a8815915efdf3233850446d368bfbd531"
      },
      {
        "path": "taker",
        "format": "raw",
        "label": "Taker",
        "signature": "3046022100edb53ae572766258aafd3c1b2fd646a188b675ed6d7c2e91d4f30196074fc930022100adeed603c4b280095b579d581c4ed36b4d05f9f3d919f136327beafee2cf835f"
      },
      {
        "path": "basePrice",
        "format": "raw",
        "label": "Base Price",
        "signature": "3046022100909a48f16e71b423a7e7109d8fc513a8a3b6cc038e103aa957f081a4cb39c137022100fd3886d3415530052ec890a33fb9c3d08b72b3eabbfee618da2413ce1db48f94"
      },
      {
        "path": "expirationTime",
        "format": "raw",
        "label": "Expiration Time",
        "signature": "3046022100963ea1d26292e612d6e1657d3613efceb4287e121ce86c9e9430f7ad98adc19f0221009af83bf8deaff3c5a4ea55cbd8983c1ea3a62966c48fed1383708ff7b7336e24"
      }
    ]
  },
  "1284:0xcccccccccccccccccccccccccccccccccccccccc:087da43b1d5a46a4acfe9437df4197f443a524ec658fbd0e8d305798": {
    "contractName": {
      "label": "Yoda",
      "signature": "304602210082879b74f069c55b3785dad1667203fc35a4265f30d02b0f73643abb6b9bc0d0022100c3ac786cffb5b5213218ca06c68778523c0d30c3cefb11de95e666d897680f9f"
    },
    "fields": [
      {
        "path": "from",
        "format": "raw",
        "label": "Sender",
        "signature": "304402207521eb52ad759e37117db390d1b71838dbdcc9191b28c7030a5dcc44321e075b02207266ddebda9ed2b254dafff991c6b016956265b1672df98db2085c52b49cffd2"
      },
      {
        "path": "to.[]",
        "format": "raw",
        "label": "Recipients",
        "signature": "3046022100d55e2a2ac4cf2f0c0fc9ef822b69176e22b7c8bc7c9fc2ea417ea84e1c164c39022100b31002ee45a6862898462127ad8fa13a9c7da902d5ee2eb2d6cec3894dadf0a5"
      },
      {
        "path": "contents",
        "format": "raw",
        "label": "Message",
        "signature": "3046022100eec10ea4eb0846466871a8d256dde530b17b404fe7722736282c425e964762a7022100a09f271889f3e957afd351136853e84c9679a00c0337433215745773b84bfd7f"
      },
      {
        "path": "id",
        "format": "raw",
        "label": "Hello this is ID",
        "signature": "3045022100c57245b7832fb5cbae86bd35b3dd4c9f93a88b903285bc18f0db67a7133a29990220500b475c779985dd222b64cd76f93d6e08aefc21f356d29762c5b31da281ee93"
      }
    ]
  },
  "1:0x9757f2d2b135150bbeb65308d4a91804107cd8d6:139c059f886c2b9b41f05a6c4ec2578a048d18aaadbc095609e5df4b": {
    "contractName": {
      "label": "Boba",
      "signature": "3046022100ff890837754849bac57d6109f2dcc05a6222417501e7dea899865af11a12f0ca022100b253d961b361b3bb693a4336a7b88226b20bd2bd04c1681182bf594778ec01ba"
    },
    "fields": [
      {
        "path": "maker",
        "format": "raw",
        "label": "Maker",
        "signature": "304402201c4ce72a81bf1808ba5b0c797eccfbb625d673f817c73c0532cc57863c94447302205321f3c48855d22caf3e81c5de27d87a5175369fdaa3940054d3e33b73bb60ea"
      },
      {
        "path": "taker",
        "format": "raw",
        "label": "Taker",
        "signature": "3046022100ff48fa8b4c0269b9029d758e6af195a3e9891938fb49bc9a702bd7b0afb98ba0022100ffadb6396337a67c6efe54211b5e8c3664a83b240ea7d9fd01d5d8732e412e19"
      }
    ]
  },
  "0:0x0000000000000000000000000000000000000000:e30e691e8ad018c90b84c64217c2e4abfe9881d27bcd0f8dd999f6b4": {
    "contractName": {
      "label": "R2D2",
      "signature": "3046022100ab5dc977a4b06ad45aa15497fe6dbde7104392c4cb8cec5204cd7f0fdc12adff0221008d46f21ad09e83774d2ce33ce00856ba21303f844820ab500fdb2031b63e1fc4"
    },
    "fields": [
      {
        "path": "document.[].[]",
        "format": "raw",
        "label": "Document",
        "signature": "30450220048c28c88191b962fbd365e6545490a3ced9d48b3bc4703ba99b2ffeffa25842022100f7b84f1c9c92712d2d6990717818908390ea37765013d5984da24bb3a40c6ef8"
      },
      {
        "path": "proof.[].[]",
        "format": "raw",
        "label": "Proof",
        "signature": "30450221009107ff404875b9ae10e71898c72cbd9d0a377226400837dcd01f46ef03ca33c202207cdbbfdd440c2abebed092ffdbee847aafcd54279e7e889a372a6ea1517220ef"
      },
      {
        "path": "depthy.[].[].[].[]",
        "format": "raw",
        "label": "Depth",
        "signature": "3046022100a8957fb0acabb7b011250321403ca4cab82c03cc321aff2f9935e89b7ba69344022100d5281cdda0c0b56f665410d5089a6b61fcbf6899e6360ebd66598244636252bc"
      }
    ]
  },
  "5:0xcccccccccccccccccccccccccccccccccccccccc:7e916a5dd34dd8da7436fa22a4b79f250d77275e11273b38cdf5387c": {
    "contractName": {
      "label": "C3P0",
      "signature": "304502204a84b6192451644adf47eac6c022a92a4eb0fe33849a8db84d9979f35a3261470221008fb5d2565b160a0bc7013e550cd756b1da18b08afc95d443f177d8ddcae3aab7"
    },
    "fields": [
      {
        "path": "from.name",
        "format": "raw",
        "label": "Sender",
        "signature": "3044022061102a17459e3eb33ea99f875a6e1a0bf32059752e858b8a714080c667d8adcb02204ed10e590bf7a29a417ca56b9484fc14d0a7c4f0d86e7ce24fb5ccf0556633c1"
      },
      {
        "path": "to.members.[].name",
        "format": "raw",
        "label": "Recipient",
        "signature": "3046022100da0d2991bb43f2f15750c506fe6de293403ac8554abba91a42a17b9bd606d28a022100ff14e23ad1d80e87852868b23d3b94717c8372c5077604e1e4eb91337f59066a"
      },
      {
        "path": "contents",
        "format": "raw",
        "label": "Message",
        "signature": "3046022100b8eb78af1926c0f467a9eaae8bddfc9809142457b274e569c47ba67ea6e36703022100b7b687c896302724877e23de734293183a49023ee62e1960f7d1197f56eaf21a"
      },
      {
        "path": "attach.list.[].name",
        "format": "raw",
        "label": "Attachment",
        "signature": "3045022100b01fb7a24c68490b628a2733399d50325ef77fcd23937c47b621b2d081fbf29f02204194a21dc935f873172928cdd13e30cbdef28c08f1bae37b51d78355b0df5561"
      }
    ]
  },
  "5:0xccccccccccccccccccccccccccccccccccccccc1:f9a315b6c68ed811063e25014e88de5b2739ebc23fae9f15f8e0a0ce": {
    "contractName": {
      "label": "Leia",
      "signature": "3046022100a3a51459d3adf212bf90585d8bbf8c7a9fe105b11ad5fae7ec483e8c8a3add2b022100b90d6ae1f960dc09aead13e2d0e54494ac21ab23b701b195a896c83538ea0ed1"
    },
    "fields": [
      {
        "path": "from.name",
        "format": "raw",
        "label": "Sender",
        "signature": "3046022100eb56bf6529df0c57ebe0e1d926fdf3bf509de432d1271b2e39a4ac6e2aefdeb9022100bba6abd2f8cc05a9a524a7348f61b4f1fe3c885d54d12edf3cb506e0fdae70f0"
      },
      {
        "path": "to.[].name",
        "format": "raw",
        "label": "Should be Alice & Bob",
        "signature": "3046022100d393eba84f5efd48ab37506c6575f92ba63c355357e6ec777e849a2717dc203e022100c6242eb81a63816e43b80696becc239a439053344b9ce3b870707577f8c2a266"
      },
      {
        "path": "contents",
        "format": "raw",
        "label": "Message",
        "signature": "304402200ad6e2706931eeb008069e7ec3a196357fa10aa1efcaa7ef72666ff4b641cfd302204e22897b9eb48e7e02e227bcbc06eeab53c29e2bc09e60895af078a1bd9e1aad"
      }
    ]
  },
  "5:0xcccccccccccccccccccccccccccccccccccccccc:ccbc1c2d282de172d94391dc53bfe1ca9575b5ef44b8374ff08204ee": {
    "contractName": {
      "label": "Han",
      "signature": "3046022100e08201e76ec521f5fd61158f8ea1242c04c5ae8c2a2d9e582fd3012297924778022100b6cd270abfebd2f7f8ff34450364b1e08c9c0467ca2208cb42ca6f930c427ca3"
    },
    "fields": [
      {
        "path": "from.name",
        "format": "raw",
        "label": "Sender",
        "signature": "3044022062ae20dc22d3f89832f97af07ad60bd412052d3440e2cde3ab2c8aed5eb60bec02201a8861de7811cb3180fc6496ae3d2112e70fdbe2d14fae77d7f66d98fb4d2883"
      },
      {
        "path": "to.[].wallets.[]",
        "format": "raw",
        "label": "Recipients",
        "signature": "3044022013bbe281a4e1a5bb273360dca3a2d1428be7985a6a0e2a60f34a2f812451ea7f02202b3d001f7b345d46ff51b3730a3d3325c03adfcd471e610222fe34c2254c6966"
      },
      {
        "path": "contents",
        "format": "raw",
        "label": "Message",
        "signature": "304602210086d556628e13296856d289f45b76ed6197ccb9b35036ae70a0ff439cca2dc25b022100e24e4d3ddfde6db1bad74d71ce8f61b18d14f8c24d61566896ce4686379ab5cf"
      }
    ]
  },
  "5:0xcccccccccccccccccccccccccccccccccccccccc:a6dfffb1ad68d66636f07152a977b48093ca6f0761283b54d3699419": {
    "contractName": {
      "label": "Padme",
      "signature": "3046022100bd6de7636bb63affd2a0e89dae3f7bc89a7f597abf57b8500713a98bdb8b71b0022100989ae054ae7d5697fb474f8d7fb2545876bb948886e2740701b079261a15bff1"
    },
    "fields": [
      {
        "path": "val",
        "format": "raw",
        "label": "Value ma man",
        "signature": "30440220056eed97085e204cbb98ee6550e6dd4601bdbb488715e7a4c467a01516743f8502204d3ce91c60ec345036fd5c61dbfcd3b0cddec5aa9d303e98add16f94f84a2bcc"
      }
    ]
  },
  "1:0xcccccccccccccccccccccccccccccccccccccccc:7e916a5dd34dd8da7436fa22a4b79f250d77275e11273b38cdf5387c": {
    "contractName": {
      "label": "Darth Vador",
      "signature": "3046022100e07b22754b0a822a1985c9a3435aff753beffb5adf4157356c4f8b35a57fd7d4022100f578383b33515484cd4aa96fed230e97fa87a4c55952ab44f49de72aa6f2ef9f"
    },
    "fields": [
      {
        "path": "from.name",
        "format": "raw",
        "label": "Sender",
        "signature": "3046022100de57b2e02bf337b5892d9a2c088ca4155538c81f439e372966b962c6c93492ad022100b90221968c5c2815b2a2bce5128c4bddbde322cab8c0a2d35bcec8fb2be2dee7"
      },
      {
        "path": "to.members.[].name",
        "format": "raw",
        "label": "Recipient",
        "signature": "3046022100e417d5ad99d507a14e48077f4210bd217f5dbd25afdb14d318cd9f4e3c68789f022100c23009ccd7d92cb514e204d1f9b2370fd2ab2998cad72afb84eaa42d3cd32b4f"
      },
      {
        "path": "contents",
        "format": "raw",
        "label": "Message",
        "signature": "304402206393b2dd0bed33d4e9e19b6f1089c1ca269df6746df9bdc04d0d1e05239ae281022003177fd79ce85556a3b900a35dadae29bb9212eaa64c90428698e49be3695e86"
      },
      {
        "path": "attach.list.[].name",
        "format": "raw",
        "label": "Attachment",
        "signature": "3046022100e7e1454fb07ff84e8d768597e6ff7c01191d58e18ea6a691b5019fa24f9cc41c022100b6653fbfa6f727b2683199eae7a3cd4e55a9b8a8cfd86138e4c97e9b58617d61"
      }
    ]
  },
  "0:0x0000000000000000000000000000000000000000:1b035bb23481b565164f6266cddba7d0a1de7819b7867218761e8a7d": {
    "contractName": {
      "label": "Palpatine",
      "signature": "304602210091f9ebbc812a20f1a575f64ade029f49e0442f6a88def31c7cf74a9ad7d9fd40022100ed1defae90fe371ed43e58c37b4caedf5473ce9dd78984e880bd757f1dc3e655"
    },
    "fields": [
      {
        "path": "curDate",
        "format": "raw",
        "label": "Timestamp",
        "signature": "3044022079158841df478fe788b50fe38ea80bac2903f862734b07285f69a92278ece9f9022065fe071875c34897f3c896e278c64eda264b72fac95937400bd40499491f52e3"
      },
      {
        "path": "id",
        "format": "raw",
        "label": "Identifier",
        "signature": "304502201f96f470b926b453cdb43bd6638807ab0e2691f639f68ea3caf7e84810fe7219022100a80151716ab5bf1792497397cdb54bffe2c840dd1f531cde1a8e9c5a3913b675"
      }
    ]
  },
  "1:0xcccccccccccccccccccccccccccccccccccccccc:0270aaaa8983a8ba018832814fadeb88ea930d63b4cc7acfa241cbff": {
    "contractName": {
      "label": "Dark Maul",
      "signature": "3045022100d9f6612aa98300474292182491148326e8e377b5584ca47f8f766b974bfce124022068409e7ef96e2312694e081449ae703a9b26bdd3eec2332f18156a5326a7b9f2"
    },
    "fields": [
      {
        "path": "max",
        "format": "raw",
        "label": "Max UInt256",
        "signature": "304502202338f93fac8fe95ce7fac892fffe6e99d5ed3453b82429893bbddf68cede1abc0221008ed113c9b3a18c307eb8bacf2157b7c8d474e7212268b113c3581ba70f96dd2d"
      },
      {
        "path": "neg256",
        "format": "raw",
        "label": "Min Int256",
        "signature": "3046022100b4a931fcfab181c760817ec86262336033c9d296f8f68aed04766fd8e7a506c8022100eb54089e8139a6b6838a6eb5c1911ec2475816c101ca61d7a560d68df737ec3f"
      },
      {
        "path": "pos256",
        "format": "raw",
        "label": "Max Int256",
        "signature": "3046022100de1ea9d3db73089a8e9885b94652ff0a84fee2991352ed6711be82a410593aaf022100d0fb389abfc8dda0457474434d2b4132b19471afc428fcc7e91ada40ab6239ba"
      },
      {
        "path": "neg128",
        "format": "raw",
        "label": "Min Int128",
        "signature": "3045022035616f2cf0eaac3a0d075ba69a85362b9f7348c051904466a4bf65f88a6d36d5022100f363a8c90b7ff451ae76f288de01acb1412a69f08fc505c0677a09c28ffbf625"
      },
      {
        "path": "pos128",
        "format": "raw",
        "label": "Max Int128",
        "signature": "3045022100fac114b732aa682525ca014b2e8cb36a23ea882c55a7173c4fbf2657cfeb094702203a1fb3460878c5a775977555718fb9d16a3b972a441fee23a000a90a0b81fea2"
      },
      {
        "path": "neg64",
        "format": "raw",
        "label": "Min Int64",
        "signature": "304402203771ba95ab8b4f673b31c0ad63495f40acb95df743707ccdda32a7fa32ec59d30220340e906465992877840a4e179c41cfaa78f352767c9acae55eb585eab99de28b"
      },
      {
        "path": "pos64",
        "format": "raw",
        "label": "Max Int64",
        "signature": "3045022068c50782a96e92e85e8027a892383395c183c797a410da981a89f761ceed16f7022100831e54bb59eda0f0e2e906b51ae9a508f3a88e99f13f50638f03a2ea20b92287"
      },
      {
        "path": "neg32",
        "format": "raw",
        "label": "Min Int32",
        "signature": "304502202dbe56656795e5a3732186851ad56675d46c053233610f3dbfbdd1287d9f7dbc022100995c691efbaf6ed2fc6ee23ab1bb86065e3a9539d5c186941274432e102f7086"
      },
      {
        "path": "pos32",
        "format": "raw",
        "label": "Max Int32",
        "signature": "304402200c3f65b45e88fd78d45a66ac4a7db9837eb9c8f1d7165e6c48623291218f7373022049f6c49c7bac26b82de50392f0354380da7c9aeb26660fd34227415374f9cd85"
      },
      {
        "path": "neg16",
        "format": "raw",
        "label": "Min Int16",
        "signature": "30450220304c255c31b96173db32434550e2c9e580f2e66036cbdba6352a2c0f02dc92ec022100f28adb8c477eafd393fdb332048adcf78d0866454fd0dea496a1ffa120362e20"
      },
      {
        "path": "pos16",
        "format": "raw",
        "label": "Max Int16",
        "signature": "3044022019d155f12a3d4e4bf463954227c4978fad9bfa4c36c2b28eca459133d0c40136022028e6c4f0f223f9a74c15d3fb98baffa10aa2aec850ed42813301cbfb751ffbe0"
      },
      {
        "path": "neg8",
        "format": "raw",
        "label": "Min Int8",
        "signature": "304402204cd508c120bba2708c00c947711b106944e014d3322b6d018fca849219ff641f0220296c4c72b1a9d6f40f1c4c768d3dae3c4dd49d3b3dae95b64561f33d48793246"
      },
      {
        "path": "pos8",
        "format": "raw",
        "label": "Max Int8",
        "signature": "30440220606bab0c711597bc314b28b1395b88cf4008f686d4a52f743485837e61f2adf602203f5f452a06ef1a3acf66542473745165a7a9e6310db827038d02a23a50c84bdf"
      }
    ]
  },
  "0:0x0000000000000000000000000000000000000000:cf5a5f8e4ae5baff4e1dd4d767b839464ba1bc26c84228d89955de54": {
    "contractName": {
      "label": "Warrick",
      "signature": "3046022100f1af490dc8b60d080fe2488ea720f2d305d60fcce71bf73609d432be64cbfc0f022100b9197005fdfbe4798808c56dd2d5f88689958234a8ce685efdb0c02e3717462d"
    },
    "fields": [
      {
        "path": "newThreshold",
        "format": "raw",
        "label": "New Threshold",
        "signature": "3045022026d6cdb4b241594798d40203d787eb948f6513f665178de17a6044b8e4b084d3022100a8a254886d77f85947f5f2f18d4ba3cad5ad3813c97f06408c0dbbe06926a2e5"
      }
    ]
  },
  "1:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48:d4dd8410bdcf861c48d353f8e3a9b738282a0fd9ba7239f59baa9099": {
    "contractName": {
      "label": "Permit USDC transfers",
      "signature": "3045022100a79de252776cf2fe2758823fb523414e483420c9645466dd18189bd05376c527022076222d6e261689e5b25214562a75cd173dba49b20b923084dcd60ced2b0719ff"
    },
    "fields": [
      {
        "path": "owner",
        "format": "raw",
        "label": "From",
        "signature": "30440220785a896fb5465f02c9e5dfb3d94e4d9455e2beb788be5ab7f6cdb7f30f2c6bd8022017ee7bf88e02635841692eac82e40cb1642264e83af05bdf490eeed3c9e7c8d7"
      },
      {
        "path": "spender",
        "format": "raw",
        "label": "Approve to spender",
        "signature": "3045022100cd3d674ab32ea5ce0755a0447df2d4216367e4a53b9132743e3c5a34a79240920220363230a8e765d42c7b60ff265297f865e7548fe34afc5a03294800a54ca885f1"
      },
      {
        "path": "value",
        "format": "amount",
        "coin_ref": 255,
        "label": "Amount allowance",
        "signature": "3045022100ddb1f28019136896db0901806ded2a372500bb83c153dafdc28f214292cdda3802201b562d0a01a5c6dc905766b760231c71f7b53df0aaa2773e8c0c6da1a3176e61"
      },
      {
        "path": "deadline",
        "format": "datetime",
        "label": "Approval expire",
        "signature": "3046022100ca28b0acda246fbd00c79250a4c0146197b63f7695269b2fd053af71fa243138022100c423bbdf2514f70d95a5be885161e1abb358ae8971748f761e8af76d735c7b04"
      }
    ]
  },
  "137:0x000000000022d473030f116ddee9f6b43ac78ba3:4d593149e876e739220f3b5ede1b38a0213d76c4705b1547c4323df3": {
    "contractName": {
      "label": "Permit2",
      "signature": "304502207b4555721d2144f142052d1f323429d542961573e0a0f3c5e87aa5aeded6b3f7022100ab96fc24d0f9cc3d0c93ac6711253fd048ed52339d4f894e24a9e6177d51a49e"
    },
    "fields": [
      {
        "path": "details.token",
        "format": "token",
        "coin_ref": 0,
        "label": "Amount allowance",
        "signature": "3046022100f443a122573bc88adb3a774cfcf7c7772d9ab11ee8d04c1b4aaa1f169b63211c0221008bd2eb156deca718888263ac9995799d313262771b42c507478d57545c77aea5"
      },
      {
        "path": "details.amount",
        "format": "amount",
        "coin_ref": 0,
        "label": "Amount allowance",
        "signature": "3045022100a25bcfd5a5a3df6d873874eeb417ff9fc451f3002aee73cee9b8b0bc1e8ef68d02201836220f0d030d953d44d9141b38c050517bc29967c31941c9bd7eb485d5e694"
      },
      {
        "path": "details.expiration",
        "format": "datetime",
        "label": "Approval expire",
        "signature": "3045022100dfeb0c1b415264ad40024f0c11a9d9a491d252bb99a6a257ac9db36d4214e87402207d0a838e62ad6f8148b04849d7a2dc5c75491ac445371498a5971c8ec2b6d7ac"
      },
      {
        "path": "spender",
        "format": "raw",
        "label": "Approve to spender",
        "signature": "3045022100a4f400735e562a75688eb30ff2535c73ba91505bc0b70004e3118ef186789918022030db9543fcf5bea2866649757de7f007a87e7e292780ec2a5d585b9b326c84fb"
      }
    ]
  },
  "1:0x000000000022d473030f116ddee9f6b43ac78ba3:a35a03a79619e46c3773d8880c952f7caeea45674557cfd2470e8fc5": {
    "contractName": {
      "label": "UniswapX Exclusive Dutch Order",
      "signature": "30450220133222a33ac1797d287d213d9af3292534915e481edbc9002d4f1ec91452ad49022100cddc2a84ad7b2156b68d794133a51109734de16c4a978022a872c093c0f57d43"
    },
    "fields": [
      {
        "path": "permitted.token",
        "format": "token",
        "coin_ref": 0,
        "label": "Amount allowance",
        "signature": "30450220087564cbfcaa383760331291b08e940b137d5ab7e6585fd21460ff8a2bc962a2022100dfc62361756e8a5382c68d9709ff1b3285d673c166600c901cbcb64e1982caf2"
      },
      {
        "path": "permitted.amount",
        "format": "amount",
        "coin_ref": 0,
        "label": "Amount allowance",
        "signature": "3045022100f81546f3be85c23f4f4583b225ee650cf183aa463236c43305a93090a2472ccd02201b6ff2a84877caee2f49a694ab8f3b163d055f28e0789496300fb01c7fda6157"
      },
      {
        "path": "spender",
        "format": "raw",
        "label": "Approve to spender",
        "signature": "304502203a66cd6d84b6b24faeba9a5049dce8f43591e028214bd133de39f73c6fc5ce890221008d56e006b3ad551266490f6567dae494950bdb7152b281b3be2ac4466f0c5302"
      },
      {
        "path": "deadline",
        "format": "datetime",
        "label": "Approval expire",
        "signature": "304402206f7d715a5486e518edca9ada72137cbbb52192e4be80b5b34c8345485b5cfd470220304e412971df7c7fb62f4b33435bbed359abc760c16eab35c82dce6ce59f6ab1"
      },
      {
        "path": "witness.inputToken",
        "format": "token",
        "coin_ref": 1,
        "label": "To swap",
        "signature": "3044022001b973eae56269f1973398aa53db8e2bba657d81bda9f772bd1103884fb63b950220073ca0844bf7d613b51a96e01a22f5b34f3a5fe4f45ed98d2c45314e5f2eea71"
      },
      {
        "path": "witness.inputStartAmount",
        "format": "amount",
        "coin_ref": 1,
        "label": "To swap",
        "signature": "3045022100dfd4251280d6c2f5cedd28eecd270d6140a9642456c8de317d288493d478e87f02201cfd53b321b426eb0d28e879af1ce9dd59259b9f5bfe3d7e165efa7a5f200b88"
      },
      {
        "path": "witness.outputs.[].token",
        "format": "raw",
        "label": "Tokens to receive",
        "signature": "304402200518911aed49f8972b543fa71c3ccf0d3029800fff13ce27bb2981f19d3bdc4902200a7cb06951e60c69e4c7c41717687e47f2a1d49f04f82eb4bb19de2abc9d8ee8"
      },
      {
        "path": "witness.outputs.[].endAmount",
        "format": "raw",
        "label": "Minimum amounts to receive",
        "signature": "30450220095fc59a5c1b65fb19886025eff26d4627d574489a2d41e1050105c1579da4e102210093c0f711db3bb37814f1aec3bd009a4472392eb0ab50ab1764c7b89475a9d67f"
      },
      {
        "path": "witness.outputs.[].recipient",
        "format": "raw",
        "label": "On Addresses",
        "signature": "3046022100f5787e5fc18bc219b57473e67254c174f39343a27ee990b19b23dc675cc2b4f3022100e9e1159e5a7a2799624947d38f8bfe19b4cc8a051cc9c553fbde0bb812e9e49a"
      }
    ]
  },
  "137:0x111111125421ca6dc452d289314280a0f8842a65:c4d135e3a126166bdee4e4859b77383074c8f046fb9b83e9cef7138c": {
    "contractName": {
      "label": "1inch Order",
      "signature": "304402206cfe6a9208d04c77b8791386f5fcbb70756bdcdde0a0c20e7339bf571fcffec1022060361f073a31b833dc2f4c4064e2a2bb060f52a58db0e966b2e87a02bf01ea50"
    },
    "fields": [
      {
        "path": "maker",
        "format": "raw",
        "label": "From",
        "signature": "304502200b8b50b3b13c63d2cc6242ad5644dc5f20bc919f57e266293824d0f555a20ae202210099d940fd2b780bb6938bdc89f31b12f0d29e20d4c128234cf71bf120a24e81a4"
      },
      {
        "path": "receiver",
        "format": "raw",
        "label": "To",
        "signature": "3045022020eb170b9844e3c6c3b61d34887bb3a3acb4ea9f8ac01600927f8e83916020cf0221009fc344206e5ab7759c98ccbcd86fcf32b5ea64fa44f3142aeb81e21b1b5c08c0"
      },
      {
        "path": "makerAsset",
        "format": "token",
        "coin_ref": 0,
        "label": "Send",
        "signature": "304402204c2f225cf542e142dede6da5e51216053023e093748b457be37168ed87d63d4d022018cf762c9f6fe16d30899decb58037abb7c11f115f8b550c08b1f4005d444461"
      },
      {
        "path": "takerAsset",
        "format": "token",
        "coin_ref": 1,
        "label": "Receive minimum",
        "signature": "304402204d6075e9943d3a692612d07658a28361f389c1fc2d82ac2515526789e26d562b022015b1b2df1d1add3c686459ab0956559b77ffd2e3d0dc0a7178bc6ee185c6d5cc"
      },
      {
        "path": "makingAmount",
        "format": "amount",
        "coin_ref": 0,
        "label": "Send",
        "signature": "304602210091612542ceb9c385829f068e290f24c3375ebe0a990fbc67bd1543410c01497a022100e34da13655ff03cd82f7054476b93eacdaf347fa217933f306c5280eb8456956"
      },
      {
        "path": "takingAmount",
        "format": "amount",
        "coin_ref": 1,
        "label": "Receive minimum",
        "signature": "3045022100f00a9be55f05be21fc8206b025683f32558827ba42b3fea4ab09b2a9a5fb3b68022066ec1859e1ecee756a1f1b02d9056b68cd5cc5dd2390f5f4a4e7c1f0564dd7f0"
      }
    ]
  }
};
