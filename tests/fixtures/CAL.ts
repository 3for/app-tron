export const v2 = {
  "1151668124:0xcccccccccccccccccccccccccccccccccccccccc:1fd77fb96a82b9c1de173fa836e20da791158ea832a3d07c6725f47c": {
    "contractName": {
      "label": "Anakin",
      "signature": "3045022048a915c315bf7919b16b82fd43602c98f6cd021a816a70a736ff7f07733775cc022100f6df11683706b6b477e6b4e59630c578780d3682639e8db42bd169758fdc278f"
    },
    "fields": [
      {
        "path": "from.name",
        "format": "raw",
        "label": "From",
        "signature": "30450220278fd51149636f6d617722fee579a4b702c7a4d9c67ffb6813671c8e44009c27022100e0c226c1b6e5a3b04b48d23ffea70f18479b84059cbc770c25cd65cbdb39ff76"
      },
      {
        "path": "to.name",
        "format": "raw",
        "label": "To",
        "signature": "304502203d81e565a23d8305088e1b98ae4d146d3f0717151d392173f0cfd14cd400fdd9022100fc912e888e623bffa42084f08099a65f6f3adfdf90a1b3cc1776592a3e9fc127"
      }
    ]
  },
  "1151668124:0xcccccccccccccccccccccccccccccccccccccccc:f9a315b6c68ed811063e25014e88de5b2739ebc23fae9f15f8e0a0ce": {
    "contractName": {
      "label": "Chewie",
      "signature": "3045022100d4d3d12ff9444d927e9742f0ba9cd642d48ac72195c92d7592162521c2e236ff02200595b60a88464c8798c3e8e6833d0ca4744765ea068635262a185bf4adc72e44"
    },
    "fields": [
      {
        "path": "from.name",
        "format": "raw",
        "label": "Sender",
        "signature": "304402207203c701c45af4965a5469389e2cb9de661eba3cb4e5e070aeb79e020eb449bc02203b8f352e612c3d2ac5d24a405005b1188d53571a4ca563606e3feddab19f0e10"
      },
      {
        "path": "to.[].wallets.[]",
        "format": "raw",
        "label": "Recipients",
        "signature": "3045022100b9d43e2e741f7b6307ecd8fda2ca757a4479239aa8d2b13279453cf8b902e8d702207c717ce66dde0731e3fca08822e15d012f0c9fc7facdb05f25ab42b0b246ebd7"
      },
      {
        "path": "contents",
        "format": "raw",
        "label": "Message",
        "signature": "30450220724ad7899ceeecf11a6699d0a7a9876b3943641a195d5bc90b2c0846c010c052022100b5cbe33e1f486645d0b594bff66889be7759d8a8c985c06127ede1dd5fe97e06"
      }
    ]
  },
  "1151668124:0x7f268357a8c2552623316e2562d90e642bb538e5:d8e4f2bd77f7562e99ea5df4adb127291a2bfbc225ae55450038f27f": {
    "contractName": {
      "label": "Mace Windu",
      "signature": "304502201d417c21ef86d0e5b97edb43ff3e92d326c55d1728f7e06ee1d7bd743310545f022100b32189ad3f95eb4b1c57dfe628d7944e25f290ffadd73736498028111480eb17"
    },
    "fields": [
      {
        "path": "maker",
        "format": "raw",
        "label": "Maker",
        "signature": "304402205597cb7d1c0bd84aedac8192a4b858ac7a39cac20c277dee45399365de93dd3602205ac1e4cff8a4acceb9fa3221935051ff3bef71b8e1ee459cace7ac791eef12bb"
      },
      {
        "path": "taker",
        "format": "raw",
        "label": "Taker",
        "signature": "3045022023d24ef08827d493ca834b805c7fd5c7fc08db31f88b26dd7a692717fbf74f930221008ada0de037410d444328a77f77be6712b379220797d36f16d53de8b58f7fbdca"
      },
      {
        "path": "basePrice",
        "format": "raw",
        "label": "Base Price",
        "signature": "3045022100d84ddfcdcdc101b7227559f9ee20cb90032d0c585894f4b21e04ad39470a0b3202200fa8b27d8d3a1a2d5095fdf28ea549671406b75d47839f1aac2bdf46ad8d0c71"
      },
      {
        "path": "expirationTime",
        "format": "raw",
        "label": "Expiration Time",
        "signature": "3046022100893eec41c3b29b3eab44f05171d7d065dead8607206505b765e0e6f75861c6f1022100893c275e6212b179ab3dbd3f3de3a2b7a71f8a61a73e8f356f27ecbabf31d7b9"
      }
    ]
  },
  "1151668124:0xcccccccccccccccccccccccccccccccccccccccc:087da43b1d5a46a4acfe9437df4197f443a524ec658fbd0e8d305798": {
    "contractName": {
      "label": "Yoda",
      "signature": "3044022035037ec7950c3110fb9290577a187a72938961c23ca2c24db28220e5b9fc198b02206b4d7fad24e938a7a33fce235b98c22e44c6cb3d937d50bda4d0383c367fe943"
    },
    "fields": [
      {
        "path": "from",
        "format": "raw",
        "label": "Sender",
        "signature": "304502210085d62428731647e545b6f585c118fd94a62c9515543b3d48e7db0aae1abe0719022016b8fb90486f19144fd33b449b298def008dd001564c71540a1c74c1e479f5f0"
      },
      {
        "path": "to.[]",
        "format": "raw",
        "label": "Recipients",
        "signature": "3045022100d202424078850a3738764d881f4f6a8e17ba556fddf067612f74ee1e7ac1240202202e74e21d51eb528fef5f132177e380dee63a2cce222ee9bd151eeb8c2efa595f"
      },
      {
        "path": "contents",
        "format": "raw",
        "label": "Message",
        "signature": "304602210086effe947756c3b3ee632fa7f83e02cb88f8ccfa1e12df9c7ee0044ecca309c1022100b34069b4c5107ae84db9c5bd02b78260185d89eb39ea6d17e3e89dbea1f41c1f"
      },
      {
        "path": "id",
        "format": "raw",
        "label": "Hello this is ID",
        "signature": "3045022100b2937621f2eaa592d0152c703a28bf99b26ed5dbb8f779518e2f0ec35744c08c0220540f231c5ce00ef34f2f1672e5c79dd5cd560e388687ff1ec4f1d5d7a6f7be26"
      }
    ]
  },
  "1151668124:0x9757f2d2b135150bbeb65308d4a91804107cd8d6:139c059f886c2b9b41f05a6c4ec2578a048d18aaadbc095609e5df4b": {
    "contractName": {
      "label": "Boba",
      "signature": "3046022100b134530552eca6a648f3735d7763509874dd1a980220042d2973cf0c63605490022100a2fc81c7d37283d5e7941563619e685b90c357391503827b3cb1b5f4e16aa05f"
    },
    "fields": [
      {
        "path": "maker",
        "format": "raw",
        "label": "Maker",
        "signature": "3045022100949f1373a2fa49037bb38e3988254fc4a4fb7eb25a2fd739075efd6dbd747c66022040705c039bb92c71d9b4d2e28ba6f2255ebfbda7108077cfbaba1bab718dde79"
      },
      {
        "path": "taker",
        "format": "raw",
        "label": "Taker",
        "signature": "3046022100bb34d9da7d090d088ebe0801a742158ae1b82fe8156f04fb5fd60f27549f02cb0221009206156aa8e7db733ca48a3ed3ba79332d6484dfedc0ca2c996aba1eaa4b1e46"
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
  "1151668124:0xcccccccccccccccccccccccccccccccccccccccc:7e916a5dd34dd8da7436fa22a4b79f250d77275e11273b38cdf5387c": {
    "contractName": {
      "label": "C3P0",
      "signature": "3045022100a85e75a71170b75fbb3906c5df986ad49e698947fbc91554b663aed9ed2aed5d0220607026dbd8b46e284d03432112508f446c1e12f7044d100f617a00d25298388d"
    },
    "fields": [
      {
        "path": "from.name",
        "format": "raw",
        "label": "Sender",
        "signature": "3046022100889e7fa70305f4f5d813339d5d112bf6d2faea7158d0b08ad7446240538e8fb8022100dadcb922bc040582fe95fa3e5186b84cab0e7c591de3bc6f2722cd63b9f06e34"
      },
      {
        "path": "to.members.[].name",
        "format": "raw",
        "label": "Recipient",
        "signature": "3046022100d50e60ec7a71fd1ae6c64c54fe5ef61f087bbea382b108863de8e251a7bacd1c02210090f3824436a07ab8888a582d0c3ad9d5586b3d96e4e5115eae5c51c3983947b8"
      },
      {
        "path": "contents",
        "format": "raw",
        "label": "Message",
        "signature": "3045022100ebd72a990b34098980f8de378aaccfda6a1b447adaa21d4a926de0f8fa51168802206c0662bd51613fb9434275fbc46e5b13bac103af8eae584a3febf553a7da6146"
      },
      {
        "path": "attach.list.[].name",
        "format": "raw",
        "label": "Attachment",
        "signature": "3045022100dca5c2a3af5df0d5875e660099a0c07359885a369c7bac1c31c88f1e8f091bb90220501a8790f663e1e0b76db502fd2aef626b01ff94d0b2315dc69f1376d266891e"
      }
    ]
  },
  "1151668124:0xccccccccccccccccccccccccccccccccccccccc2:7e916a5dd34dd8da7436fa22a4b79f250d77275e11273b38cdf5387c": {
    "contractName": {
      "label": "Darth Vador",
      "signature": "3046022100eac08e224c8dff36e5df82a853b2aa4b80486b8bbf3e71cb4177b3225dd8a8fd0221009505f722c0e0d2897b5a647d0b5bee303581c4c068d51f5bf629888ac31bf32d"
    },
    "fields": [
      {
        "path": "from.name",
        "format": "raw",
        "label": "Sender",
        "signature": "3045022100b24c863ea2f1230195e4afc57d8ddf4496f4a471e57abb2a4d3c8cae16230f4f02200dd0c4460d884a694b64e6cce378e70d53ead44a9ec18068d1aa1dfbb30165d9"
      },
      {
        "path": "to.members.[].name",
        "format": "raw",
        "label": "Recipient",
        "signature": "3046022100d03eee49db0dd24ca70c3d9a90fd149bebcf8e37e6fe2aae3ad491e274bad3c2022100c8f8b7ce494ae220d46192a4cff84deac8af8fcefa82d5ac0ba2eddb6cb4f213"
      },
      {
        "path": "contents",
        "format": "raw",
        "label": "Message",
        "signature": "304402207ae0b7f5e4437f15c24e09ec42909012e95b2d6859a8491c608205cbe0f41e0e02200fe06016e13fe8f5748a37d7f4014310a7eec8f1632fda6e7e5a4e047cb36bee"
      },
      {
        "path": "attach.list.[].name",
        "format": "raw",
        "label": "Attachment",
        "signature": "3044022030e9c68f721445d664da38ce4e5c65f53ea08f5c2203ffc62a54d797c61316cc02206225e35617725e6d61d58dedf656a1e68f17d440a4da58e4e47f70c6ccaf3e12"
      }
    ]
  },
  "1151668124:0xccccccccccccccccccccccccccccccccccccccc1:f9a315b6c68ed811063e25014e88de5b2739ebc23fae9f15f8e0a0ce": {
    "contractName": {
      "label": "Leia",
      "signature": "3046022100d03c771190b150d2e175daac12885a0000353a3457d4bd95f905eda1abf2810e0221009ef2c82fce486b4be2baa71812e2651d32e2389c16a4128a19c5cf79ca7c3195"
    },
    "fields": [
      {
        "path": "from.name",
        "format": "raw",
        "label": "Sender",
        "signature": "3046022100a7d3e5720a705f08d8eede6e11e39ed03ac1db4af2c03b40a2e2928c7ec9161b02210098e05c14be7c8c93ec7a64818041185fc88997c9a0edbf1d13e6e5cf270f663b"
      },
      {
        "path": "to.[].name",
        "format": "raw",
        "label": "Should be Alice & Bob",
        "signature": "304402205a71b0f59e79c169c736eeb0dbecf4c3a1bb715de2a3dfcf55e8535b655c2627022056c713923e3a439581365e71af27416f218fe52056698c7f1cd27e5dae7e904f"
      },
      {
        "path": "contents",
        "format": "raw",
        "label": "Message",
        "signature": "3046022100810507d63bb54f784bba358dca7cbe6ed34861a2f79da306d945d786c8226b82022100ac47c28baf68450314f4ba33c717ff657fd680644d815ef01c3558113cbbef12"
      }
    ]
  },
  "1151668124:0xcccccccccccccccccccccccccccccccccccccccc:ccbc1c2d282de172d94391dc53bfe1ca9575b5ef44b8374ff08204ee": {
    "contractName": {
      "label": "Han",
      "signature": "3045022100de0b8c7fac4912b0cdae544cc3502c1e7ad48d128b995077358bc810258dbb32022052364f4ea0dec0a4e69f1da360217623abe27552566778a90a6f3f55493fe64a"
    },
    "fields": [
      {
        "path": "from.name",
        "format": "raw",
        "label": "Sender",
        "signature": "3045022100e665f88673c97eef38f321dfb2b30f647b7821df766e4a4716454bf6badcea67022062bba24171f927437c96067c30d9ccb08f31e1b79e8e49429a2850824e13bcc1"
      },
      {
        "path": "to.[].wallets.[]",
        "format": "raw",
        "label": "Recipients",
        "signature": "3045022074c3a38969120338561ddd4c2ac7382c75f7ef1dab348adb92dc9f2860aacb3e022100b441f374e5df8afaf3541acbb494a616d93eb50f8c894d3b10147eb7178cf0af"
      },
      {
        "path": "contents",
        "format": "raw",
        "label": "Message",
        "signature": "3045022100b7f9aad52cda6543bbb91992c1acc9d10436ecf523b9570706aa1e578a259650022045cac18bda41b48ac17551bc4ee3700a380086c357d9eb16d03aa543380d2896"
      }
    ]
  },
  "1151668124:0xcccccccccccccccccccccccccccccccccccccccc:a6dfffb1ad68d66636f07152a977b48093ca6f0761283b54d3699419": {
    "contractName": {
      "label": "Padme",
      "signature": "3046022100bde9cedd300e0de123da5b4c11971e6e067ab4723ef1f01321d0ff998b2e0af40221009c1d29f870fd664660b731a9a53d670a548e0a424ccff8bd7f6e70f7d6d975a1"
    },
    "fields": [
      {
        "path": "val",
        "format": "raw",
        "label": "Value ma man",
        "signature": "3045022100f2c9ed0b341ced5e4f41a70d3329b4f872e8ec6481f2477108c0c66654cc61d702205ff7557616ca5bb80149333106e4043ca8afc62e8b9dce237de582e22ffc8b18"
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
  "1151668124:0xcccccccccccccccccccccccccccccccccccccccc:0270aaaa8983a8ba018832814fadeb88ea930d63b4cc7acfa241cbff": {
    "contractName": {
      "label": "Dark Maul",
      "signature": "3045022046646263f4dac8aa3ab53c6803c4a34905c2c43c365df02a71538c5883f00042022100802c5846321d590af90f6d70d01af06926c095bfca17ea1c89868d3d89dfcdfb"
    },
    "fields": [
      {
        "path": "max",
        "format": "raw",
        "label": "Max UInt256",
        "signature": "304402205f6cb8fef5fcd2d32228edd6fc5bbea8a66b8898b9f4e595fd5c0b1d3d2b3e5c0220296606c6e0821ce77887edef81460c4caf9943450fe9f90741b7a94f39b61e7e"
      },
      {
        "path": "neg256",
        "format": "raw",
        "label": "Min Int256",
        "signature": "3045022100cb9e61264d53a2773380c5ce31f3b8ae9ce086fec610881af314f71d40b3041802206ecfdeaf6a08ed1bffbf101624b76f8be55eae5b8f624263fa62c0770a3dabf8"
      },
      {
        "path": "pos256",
        "format": "raw",
        "label": "Max Int256",
        "signature": "30460221008bf659d2fbf2bbdef06007b2b1851faa339617e62e4408e3b3e01fbd59a15128022100c2b0473577139aa26ae687d317b7096b0a7e04d7b0c9d68c5b27ad5cd1f031e8"
      },
      {
        "path": "neg128",
        "format": "raw",
        "label": "Min Int128",
        "signature": "3045022062783299527f0ed85fe3fb5fe50426fae23d0beaa9006b48b39b4ddfc7aa834e022100fad974c2fc46614923eec5945fd2ff54867daff44e21bf7f72587c0f8945f3e1"
      },
      {
        "path": "pos128",
        "format": "raw",
        "label": "Max Int128",
        "signature": "30450220092ceb6d571d2f8fbf086b9c3a4ae8abb2b875ecab4a1ef6a6f79f6c61a29d06022100950f7d6468641112ee6530e466fbef14801f68f9b1b0ff34f0d6e1ecd71c3756"
      },
      {
        "path": "neg64",
        "format": "raw",
        "label": "Min Int64",
        "signature": "304602210092abbbf41e0a21bf875dce745550c57f72aeb07b0c794dc8a511dc1d96a4bb6f022100e00a6f575e96a32b8584d8f93da152f385116f0f3b4f2e0a4ea41f52f3ee70d2"
      },
      {
        "path": "pos64",
        "format": "raw",
        "label": "Max Int64",
        "signature": "30450220646fb0a129e3f3c05e5e8ba7373e75d940fb5b054730b0982973b943b0fac8f0022100a8e2798db8bd9d32a7be42f60e3e88f72bf7fae17a89ab442e266c3fea7d3e98"
      },
      {
        "path": "neg32",
        "format": "raw",
        "label": "Min Int32",
        "signature": "304402203b585ec1fad7c157e35578596937ebe577c2b3cf15e59be73e35404acbfbb2e9022071ea586c761ae539fb639c942f764b6eb8cf95d7e5b3b5b5a6697c92abd505ae"
      },
      {
        "path": "pos32",
        "format": "raw",
        "label": "Max Int32",
        "signature": "3046022100b796c6b9cab8a07027eebfa983823259b2b4e32db2d7f57ea435fabc98bb0255022100fe8ff7acf539f13427005997a4647101f8590ceb62d29a4a6bbce3cbbc73a955"
      },
      {
        "path": "neg16",
        "format": "raw",
        "label": "Min Int16",
        "signature": "304502200679f0f68cfc89b1c02e36cb52e448204f8c85d747a98bea99433efa6a3572c5022100b405bf79d846af05b4f7396eb759668a28e289fffc29d15cd288a72585fa057b"
      },
      {
        "path": "pos16",
        "format": "raw",
        "label": "Max Int16",
        "signature": "304502202ee1c49c4f64c2b49725e41b09d7f061bcb67faaa85129ed1400a1ff842de2d00221009d626631fee68591f3fa230e49b16286f36d87c48642a4bd5bba3677ab19336f"
      },
      {
        "path": "neg8",
        "format": "raw",
        "label": "Min Int8",
        "signature": "3045022057b06a8bf654a35a0226d6873fafdd9d70e3a833768a364c57d029939c33115f022100e5397d8f592f8ba368ba984f8c63094596f457848dd83481a6a6f33be05f06fd"
      },
      {
        "path": "pos8",
        "format": "raw",
        "label": "Max Int8",
        "signature": "304402206c912a815403f1fc981589889b21c655f09fd8d31677ccb0d2fd8ba539d8b29002207f5404bbc7f9001ef68b6d25750b37ddda8dbf14bc4672b24af349d2f763c219"
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
  "1151668124:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48:d4dd8410bdcf861c48d353f8e3a9b738282a0fd9ba7239f59baa9099": {
    "contractName": {
      "label": "Permit USDC transfers",
      "signature": "3046022100b737f38cb08cf35259ea3d251ea2aa46104cd6b44bb41696028c70e939c67e1e0221009344ecb2877728b596e9d3bfa13e9cf86a1dd3ddc3f96a0962dc21122e77a474"
    },
    "fields": [
      {
        "path": "owner",
        "format": "raw",
        "label": "From",
        "signature": "3045022100b32bc9d4acec602b2e7b21e2e50e97c10e23472eda9a5915b298f9912c2e099a02204ba513e3f4729afb7868564efac0996b10318c855dcd4cf0f9016ceff71cfb70"
      },
      {
        "path": "spender",
        "format": "raw",
        "label": "Approve to spender",
        "signature": "3046022100f753c77eec5b9b50afbd66a8900c26bf61f808e12106ff385cad4a0bc75542810221008718080666d6f9d1100fee310b1eb58070a44e3caf36a3342809f64580ce7440"
      },
      {
        "path": "value",
        "format": "amount",
        "coin_ref": 255,
        "label": "Amount allowance",
        "signature": "3046022100f2893cda28e4b51d087e1912b234039d365836ebb8019317ca61fd3f4c360739022100df7eece8d0d74cc73d6ce4cd7d1dd6b5ff2f14d21fe648603e35120999c4d2d1"
      },
      {
        "path": "deadline",
        "format": "datetime",
        "label": "Approval expire",
        "signature": "3046022100f3c459b0f0ac316187826c97fd0a6321282304cd84f85ca3b2414e4e3d83b172022100ce543eaa4215bd20054be0ac8268652d360635f59d100973471f624d7b8a2b8b"
      }
    ]
  },
  "1151668124:0x000000000022d473030f116ddee9f6b43ac78ba3:4d593149e876e739220f3b5ede1b38a0213d76c4705b1547c4323df3": {
    "contractName": {
      "label": "Permit2",
      "signature": "3046022100b27d76064032c7a86460d2cfcd6d613146c22545aa6f14c7ba0916769ba31f49022100f4c1c0190d9ebb9488d7acdab6df009cec8e68e60f3f7e306b4ae15318abc0a7"
    },
    "fields": [
      {
        "path": "details.token",
        "format": "token",
        "coin_ref": 0,
        "label": "Amount allowance",
        "signature": "30460221009fd853bdf5b0acdca0b8886d230262e15f7008075c3cfd6aa7d0c018634341510221008591f2171ef10ce51e8e10fb9f8168153fee705861c8a59738ab20991be7f043"
      },
      {
        "path": "details.amount",
        "format": "amount",
        "coin_ref": 0,
        "label": "Amount allowance",
        "signature": "3045022018ec3965be7ec323ac4f9cea9a7e692791ede317e89b8d24af6497fa9ab0ac36022100f51fda6ba33b9566434db9238600d4b6d50c2d015f2266f1a27fcfead0423a43"
      },
      {
        "path": "details.expiration",
        "format": "datetime",
        "label": "Approval expire",
        "signature": "304402203eaf1f5426a00be308f518ff8e5b7d9da114f9c054a11ab7becb17159466206002201670d9f6c4012a921b0a5d38b571fb86b35c71aebc10bafbb1210c924283e63b"
      },
      {
        "path": "spender",
        "format": "raw",
        "label": "Approve to spender",
        "signature": "3045022100f3b3d15f7efc4bbbabc927a8b96643b8e9de8ec408d5b9cd6cbb78bd7ad5bedf02207f1becab9b57f6fb1f16c0803ddd5a7c6b886a29c1be4f835caecffbe6833c01"
      }
    ]
  },
  "1151668124:0x000000000022d473030f116ddee9f6b43ac78ba3:a35a03a79619e46c3773d8880c952f7caeea45674557cfd2470e8fc5": {
    "contractName": {
      "label": "UniswapX Exclusive Dutch Order",
      "signature": "304402202b69ee74af3dd80bc4dbcf1ad27a5764bd99e753ad0b08eea8a2fb7a322601090220692a57c171b0ff43e103dbefb359d38660976ceebc8ca43ae7fcb05849c290b8"
    },
    "fields": [
      {
        "path": "permitted.token",
        "format": "token",
        "coin_ref": 0,
        "label": "Amount allowance",
        "signature": "3044022034952a97c712a2cfc850be952e7d0ff868cbdc4419621cc2830376024003d27a0220372690df3c5c9f407a576efe9068c24bfed9b016bcfd5c579d6091f2729f5766"
      },
      {
        "path": "permitted.amount",
        "format": "amount",
        "coin_ref": 0,
        "label": "Amount allowance",
        "signature": "3045022100fbed6022e7eff71b12570d8a57d1ebe5257e385db9464425665953790cb1f1e302200cecd36a498e84752707460afb000b06c3d8fe42a2bc748a5e5ec46d2a5683ea"
      },
      {
        "path": "spender",
        "format": "raw",
        "label": "Approve to spender",
        "signature": "3045022100d2794f81cbbe1055ce53e2fb30202c7395a5fe7f186a1a211e4cba3b91fa86b1022036584d53746ad075f0a6dc49f05fca225e46184ca4b001e122ee0daf8a8d7cc8"
      },
      {
        "path": "deadline",
        "format": "datetime",
        "label": "Approval expire",
        "signature": "3045022100c618ca6e4199bf7ef3039b5a84937ad7668eaba993861c2edcc465fa78563ed4022077a97f9afe193df3a0ea3840f2642f0d0444999c616fb1d5daed1392c11e7243"
      },
      {
        "path": "witness.inputToken",
        "format": "token",
        "coin_ref": 1,
        "label": "To swap",
        "signature": "3045022100d2ad93e7617ae852a57fd08624e09e20cbedaa5de9b36416b6608866f1ca7c2702203538befaf8231096167cde6822e73f13c17388feac8d64362a181b3f541244a4"
      },
      {
        "path": "witness.inputStartAmount",
        "format": "amount",
        "coin_ref": 1,
        "label": "To swap",
        "signature": "304502203470a690161b86385cdc96ea8997d69435d2509f3765330787dc38f55da65d4a02210081076b4e7a3b192868bc584610f16e7aee333ef4a3f888dde4bfe883caf1b0a4"
      },
      {
        "path": "witness.outputs.[].token",
        "format": "raw",
        "label": "Tokens to receive",
        "signature": "3046022100d78915955c32112ce95bb0ef291ae12edec4ec7832cd6b7c166877bf13d4f46102210092b6dc4c96023528f182f65c9b4c0633494f0ff787825937466fa0ad2e1ebdad"
      },
      {
        "path": "witness.outputs.[].endAmount",
        "format": "raw",
        "label": "Minimum amounts to receive",
        "signature": "3046022100aff8bce292b66167356e6aaed503effb12086109873a1b804301e30b8e8e690902210093478e8d68972f105223d9491cc1b9fe5be03dabca7ec249fb2f0ca7c8f66ee1"
      },
      {
        "path": "witness.outputs.[].recipient",
        "format": "raw",
        "label": "On Addresses",
        "signature": "30440220485b7efb96738fb4b7a04e57a54a51973a5866eeabcd8195c9b5189e7e73514d022070fd9199cbe1a7b51dd8bcdb48fd874b522d0ca0f3012cddd7eb4353d0ea54ea"
      }
    ]
  },
  "1151668124:0x111111125421ca6dc452d289314280a0f8842a65:c4d135e3a126166bdee4e4859b77383074c8f046fb9b83e9cef7138c": {
    "contractName": {
      "label": "1inch Order",
      "signature": "3046022100c15356040e9f6032642ec7dcc773ce867a3d3bb9327dfd35ee452be053e671bc02210086ef02d46cbe0d2cc59f98e3265c87d6881cf4b146edcfe4b59b69a1aac5803b"
    },
    "fields": [
      {
        "path": "maker",
        "format": "raw",
        "label": "From",
        "signature": "30450220767257189c8bbbb8192f70bfef26e2f66931bfd80b07aff9ec8a06893800bc9c022100a7f9023d1dbed8fef216e93e3819f73a38971e7d7105ce2ad6ad417c6da348db"
      },
      {
        "path": "receiver",
        "format": "raw",
        "label": "To",
        "signature": "304502207a02c3bd942e7771edfe082bc0b03dffd82ac2428ead602013f5426b64a8acdd022100a7fb516776d172dcd41aef30188a58889271073454c91f2752c732169c6b1a76"
      },
      {
        "path": "makerAsset",
        "format": "token",
        "coin_ref": 0,
        "label": "Send",
        "signature": "304402200f4c92b450021f8dba8b77214f26c2f3013e056f8cf19408fc09abd8460c24ba02202cb6c0632abdb542335364c39982daab0380c816edd6135a086ef7ddb478a3f9"
      },
      {
        "path": "takerAsset",
        "format": "token",
        "coin_ref": 1,
        "label": "Receive minimum",
        "signature": "3044022068fc2a0d56d2264a81a370311311bd4c193cea9728c3437134020d0e163a194a02202f23c9b7a0c0bbcc1056eee27bea21e832fd57747f9e1ed0c7085f9f946e4a94"
      },
      {
        "path": "makingAmount",
        "format": "amount",
        "coin_ref": 0,
        "label": "Send",
        "signature": "304502202d417ea03f391251f4753c9096c5f957feb990a2e206b3388ead7d38d8933492022100aaf0d93a7b2ceadbb0550426e22c021513ff25b7c6356e4699b6e432263a35fd"
      },
      {
        "path": "takingAmount",
        "format": "amount",
        "coin_ref": 1,
        "label": "Receive minimum",
        "signature": "304502204a41f723683885e61277104a471ba372bbde8a8f1c43196d85830d70370c98cc0221009c08373b7fc399008d023385484d09985aa35ce53584478fda0ba623db140f7b"
      }
    ]
  }
};
