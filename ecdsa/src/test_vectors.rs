use hex_literal::hex;

#[derive(Debug)]
pub struct TestVector {
    pub message: Vec<u8>,
    pub priv_key: String,
    pub qx: String,
    pub qy: String,
    pub k: String,
    pub r: String,
    pub s: String,
}

/// ECDSA/P-256 test vectors.
///
/// Adapted from the FIPS 186-4 ECDSA test vectors
/// (P-256, SHA-256, from `SigGen.txt` in `186-4ecdsatestvectors.zip`)
/// <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures>
pub fn get_test_vectors_p256() -> Vec<TestVector> {
    vec![
        TestVector {
            message: hex!("5905238877c77421f73e43ee3da6f2d9e2ccad5fc942dcec0cbd25482935faaf416983fe165b1a045ee2bcd2e6dca3bdf46c4310a7461f9a37960ca672d3feb5473e253605fb1ddfd28065b53cb5858a8ad28175bf9bd386a5e471ea7a65c17cc934a9d791e91491eb3754d03799790fe2d308d16146d5c9b0d0debd97d79ce8").to_vec(),
            priv_key: "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464".to_string(),
            qx: "1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83".to_string(),
            qy: "ce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9".to_string(),
            k: "94a1bbb14b906a61a280f245f9e93c7f3b4a6247824f5d33b9670787642a68de".to_string(),
            r: "f3ac8061b514795b8843e3d6629527ed2afd6b1f6a555a7acabb5e6f79c8c2ac".to_string(),
            s: "8bf77819ca05a6b2786c76262bf7371cef97b218e96f175a3ccdda2acc058903".to_string(),
        },
        TestVector {
          message: hex!("c35e2f092553c55772926bdbe87c9796827d17024dbb9233a545366e2e5987dd344deb72df987144b8c6c43bc41b654b94cc856e16b96d7a821c8ec039b503e3d86728c494a967d83011a0e090b5d54cd47f4e366c0912bc808fbb2ea96efac88fb3ebec9342738e225f7c7c2b011ce375b56621a20642b4d36e060db4524af1").to_vec(),
          priv_key: "0f56db78ca460b055c500064824bed999a25aaf48ebb519ac201537b85479813".to_string(),
          qx: "e266ddfdc12668db30d4ca3e8f7749432c416044f2d2b8c10bf3d4012aeffa8a".to_string(),
          qy: "bfa86404a2e9ffe67d47c587ef7a97a7f456b863b4d02cfc6928973ab5b1cb39".to_string(),
          k: "6d3e71882c3b83b156bb14e0ab184aa9fb728068d3ae9fac421187ae0b2f34c6".to_string(),
          r: "976d3a4e9d23326dc0baa9fa560b7c4e53f42864f508483a6473b6a11079b2db".to_string(),
          s: "1b766e9ceb71ba6c01dcd46e0af462cd4cfa652ae5017d4555b8eeefe36e1932".to_string(),
      },
      TestVector {
        message: hex!("3c054e333a94259c36af09ab5b4ff9beb3492f8d5b4282d16801daccb29f70fe61a0b37ffef5c04cd1b70e85b1f549a1c4dc672985e50f43ea037efa9964f096b5f62f7ffdf8d6bfb2cc859558f5a393cb949dbd48f269343b5263dcdb9c556eca074f2e98e6d94c2c29a677afaf806edf79b15a3fcd46e7067b7669f83188ee").to_vec(),
        priv_key: "e283871239837e13b95f789e6e1af63bf61c918c992e62bca040d64cad1fc2ef".to_string(),
        qx: "74ccd8a62fba0e667c50929a53f78c21b8ff0c3c737b0b40b1750b2302b0bde8".to_string(),
        qy: "29074e21f3a0ef88b9efdf10d06aa4c295cc1671f758ca0e4cd108803d0f2614".to_string(),
        k: "ad5e887eb2b380b8d8280ad6e5ff8a60f4d26243e0124c2f31a297b5d0835de2".to_string(),
        r: "35fb60f5ca0f3ca08542fb3cc641c8263a2cab7a90ee6a5e1583fac2bb6f6bd1".to_string(),
        s: "ee59d81bc9db1055cc0ed97b159d8784af04e98511d0a9a407b99bb292572e96".to_string(),
      },
      TestVector {
        message: hex!("0989122410d522af64ceb07da2c865219046b4c3d9d99b01278c07ff63eaf1039cb787ae9e2dd46436cc0415f280c562bebb83a23e639e476a02ec8cff7ea06cd12c86dcc3adefbf1a9e9a9b6646c7599ec631b0da9a60debeb9b3e19324977f3b4f36892c8a38671c8e1cc8e50fcd50f9e51deaf98272f9266fc702e4e57c30").to_vec(),
        priv_key: "a3d2d3b7596f6592ce98b4bfe10d41837f10027a90d7bb75349490018cf72d07".to_string(),
        qx: "322f80371bf6e044bc49391d97c1714ab87f990b949bc178cb7c43b7c22d89e1".to_string(),
        qy: "3c15d54a5cc6b9f09de8457e873eb3deb1fceb54b0b295da6050294fae7fd999".to_string(),
        k: "24fc90e1da13f17ef9fe84cc96b9471ed1aaac17e3a4bae33a115df4e5834f18".to_string(),
        r: "d7c562370af617b581c84a2468cc8bd50bb1cbf322de41b7887ce07c0e5884ca".to_string(),
        s: "b46d9f2d8c4bf83546ff178f1d78937c008d64e8ecc5cbb825cb21d94d670d89".to_string(),
      },
      TestVector {
        message: hex!("dc66e39f9bbfd9865318531ffe9207f934fa615a5b285708a5e9c46b7775150e818d7f24d2a123df3672fff2094e3fd3df6fbe259e3989dd5edfcccbe7d45e26a775a5c4329a084f057c42c13f3248e3fd6f0c76678f890f513c32292dd306eaa84a59abe34b16cb5e38d0e885525d10336ca443e1682aa04a7af832b0eee4e7").to_vec(),
        priv_key: "53a0e8a8fe93db01e7ae94e1a9882a102ebd079b3a535827d583626c272d280d".to_string(),
        qx: "1bcec4570e1ec2436596b8ded58f60c3b1ebc6a403bc5543040ba82963057244".to_string(),
        qy: "8af62a4c683f096b28558320737bf83b9959a46ad2521004ef74cf85e67494e1".to_string(),
        k: "5d833e8d24cc7a402d7ee7ec852a3587cddeb48358cea71b0bedb8fabe84e0c4".to_string(),
        r: "18caaf7b663507a8bcd992b836dec9dc5703c080af5e51dfa3a9a7c387182604".to_string(),
        s: "77c68928ac3b88d985fb43fb615fb7ff45c18ba5c81af796c613dfa98352d29c".to_string(),
      },
      TestVector {
        message: hex!("600974e7d8c5508e2c1aab0783ad0d7c4494ab2b4da265c2fe496421c4df238b0be25f25659157c8a225fb03953607f7df996acfd402f147e37aee2f1693e3bf1c35eab3ae360a2bd91d04622ea47f83d863d2dfecb618e8b8bdc39e17d15d672eee03bb4ce2cc5cf6b217e5faf3f336fdd87d972d3a8b8a593ba85955cc9d71").to_vec(),
        priv_key: "4af107e8e2194c830ffb712a65511bc9186a133007855b49ab4b3833aefc4a1d".to_string(),
        qx: "a32e50be3dae2c8ba3f5e4bdae14cf7645420d425ead94036c22dd6c4fc59e00".to_string(),
        qy: "d623bf641160c289d6742c6257ae6ba574446dd1d0e74db3aaa80900b78d4ae9".to_string(),
        k: "e18f96f84dfa2fd3cdfaec9159d4c338cd54ad314134f0b31e20591fc238d0ab".to_string(),
        r: "8524c5024e2d9a73bde8c72d9129f57873bbad0ed05215a372a84fdbc78f2e68".to_string(),
        s: "d18c2caf3b1072f87064ec5e8953f51301cada03469c640244760328eb5a05cb".to_string(),
      },
      TestVector {
        message: hex!("dfa6cb9b39adda6c74cc8b2a8b53a12c499ab9dee01b4123642b4f11af336a91a5c9ce0520eb2395a6190ecbf6169c4cba81941de8e76c9c908eb843b98ce95e0da29c5d4388040264e05e07030a577cc5d176387154eabae2af52a83e85c61c7c61da930c9b19e45d7e34c8516dc3c238fddd6e450a77455d534c48a152010b").to_vec(),
        priv_key: "78dfaa09f1076850b3e206e477494cddcfb822aaa0128475053592c48ebaf4ab".to_string(),
        qx: "8bcfe2a721ca6d753968f564ec4315be4857e28bef1908f61a366b1f03c97479".to_string(),
        qy: "0f67576a30b8e20d4232d8530b52fb4c89cbc589ede291e499ddd15fe870ab96".to_string(),
        k: "295544dbb2da3da170741c9b2c6551d40af7ed4e891445f11a02b66a5c258a77".to_string(),
        r: "c5a186d72df452015480f7f338970bfe825087f05c0088d95305f87aacc9b254".to_string(),
        s: "84a58f9e9d9e735344b316b1aa1ab5185665b85147dc82d92e969d7bee31ca30".to_string(),
      },
      TestVector {
        message: hex!("51d2547cbff92431174aa7fc7302139519d98071c755ff1c92e4694b58587ea560f72f32fc6dd4dee7d22bb7387381d0256e2862d0644cdf2c277c5d740fa089830eb52bf79d1e75b8596ecf0ea58a0b9df61e0c9754bfcd62efab6ea1bd216bf181c5593da79f10135a9bc6e164f1854bc8859734341aad237ba29a81a3fc8b").to_vec(),
        priv_key: "80e692e3eb9fcd8c7d44e7de9f7a5952686407f90025a1d87e52c7096a62618a".to_string(),
        qx: "a88bc8430279c8c0400a77d751f26c0abc93e5de4ad9a4166357952fe041e767".to_string(),
        qy: "2d365a1eef25ead579cc9a069b6abc1b16b81c35f18785ce26a10ba6d1381185".to_string(),
        k: "7c80fd66d62cc076cef2d030c17c0a69c99611549cb32c4ff662475adbe84b22".to_string(),
        r: "9d0c6afb6df3bced455b459cc21387e14929392664bb8741a3693a1795ca6902".to_string(),
        s: "d7f9ddd191f1f412869429209ee3814c75c72fa46a9cccf804a2f5cc0b7e739f".to_string(),
      },
      TestVector {
        message: hex!("558c2ac13026402bad4a0a83ebc9468e50f7ffab06d6f981e5db1d082098065bcff6f21a7a74558b1e8612914b8b5a0aa28ed5b574c36ac4ea5868432a62bb8ef0695d27c1e3ceaf75c7b251c65ddb268696f07c16d2767973d85beb443f211e6445e7fe5d46f0dce70d58a4cd9fe70688c035688ea8c6baec65a5fc7e2c93e8").to_vec(),
        priv_key: "5e666c0db0214c3b627a8e48541cc84a8b6fd15f300da4dff5d18aec6c55b881".to_string(),
        qx: "1bc487570f040dc94196c9befe8ab2b6de77208b1f38bdaae28f9645c4d2bc3a".to_string(),
        qy: "ec81602abd8345e71867c8210313737865b8aa186851e1b48eaca140320f5d8f".to_string(),
        k: "2e7625a48874d86c9e467f890aaa7cd6ebdf71c0102bfdcfa24565d6af3fdce9".to_string(),
        r: "2f9e2b4e9f747c657f705bffd124ee178bbc5391c86d056717b140c153570fd9".to_string(),
        s: "f5413bfd85949da8d83de83ab0d19b2986613e224d1901d76919de23ccd03199".to_string(),
      },
      TestVector {
        message: hex!("4d55c99ef6bd54621662c3d110c3cb627c03d6311393b264ab97b90a4b15214a5593ba2510a53d63fb34be251facb697c973e11b665cb7920f1684b0031b4dd370cb927ca7168b0bf8ad285e05e9e31e34bc24024739fdc10b78586f29eff94412034e3b606ed850ec2c1900e8e68151fc4aee5adebb066eb6da4eaa5681378e").to_vec(),
        priv_key: "f73f455271c877c4d5334627e37c278f68d143014b0a05aa62f308b2101c5308".to_string(),
        qx: "b8188bd68701fc396dab53125d4d28ea33a91daf6d21485f4770f6ea8c565dde".to_string(),
        qy: "423f058810f277f8fe076f6db56e9285a1bf2c2a1dae145095edd9c04970bc4a".to_string(),
        k: "62f8665fd6e26b3fa069e85281777a9b1f0dfd2c0b9f54a086d0c109ff9fd615".to_string(),
        r: "1cc628533d0004b2b20e7f4baad0b8bb5e0673db159bbccf92491aef61fc9620".to_string(),
        s: "880e0bbf82a8cf818ed46ba03cf0fc6c898e36fca36cc7fdb1d2db7503634430".to_string(),
      },
      TestVector {
        message: hex!("f8248ad47d97c18c984f1f5c10950dc1404713c56b6ea397e01e6dd925e903b4fadfe2c9e877169e71ce3c7fe5ce70ee4255d9cdc26f6943bf48687874de64f6cf30a012512e787b88059bbf561162bdcc23a3742c835ac144cc14167b1bd6727e940540a9c99f3cbb41fb1dcb00d76dda04995847c657f4c19d303eb09eb48a").to_vec(),
        priv_key: "b20d705d9bd7c2b8dc60393a5357f632990e599a0975573ac67fd89b49187906".to_string(),
        qx: "51f99d2d52d4a6e734484a018b7ca2f895c2929b6754a3a03224d07ae61166ce".to_string(),
        qy: "4737da963c6ef7247fb88d19f9b0c667cac7fe12837fdab88c66f10d3c14cad1".to_string(),
        k: "72b656f6b35b9ccbc712c9f1f3b1a14cbbebaec41c4bca8da18f492a062d6f6f".to_string(),
        r: "9886ae46c1415c3bc959e82b760ad760aab66885a84e620aa339fdf102465c42".to_string(),
        s: "2bf3a80bc04faa35ebecc0f4864ac02d349f6f126e0f988501b8d3075409a26c".to_string(),
      },
      TestVector {
        message: hex!("3b6ee2425940b3d240d35b97b6dcd61ed3423d8e71a0ada35d47b322d17b35ea0472f35edd1d252f87b8b65ef4b716669fc9ac28b00d34a9d66ad118c9d94e7f46d0b4f6c2b2d339fd6bcd351241a387cc82609057048c12c4ec3d85c661975c45b300cb96930d89370a327c98b67defaa89497aa8ef994c77f1130f752f94a4").to_vec(),
        priv_key: "d4234bebfbc821050341a37e1240efe5e33763cbbb2ef76a1c79e24724e5a5e7".to_string(),
        qx: "8fb287f0202ad57ae841aea35f29b2e1d53e196d0ddd9aec24813d64c0922fb7".to_string(),
        qy: "1f6daff1aa2dd2d6d3741623eecb5e7b612997a1039aab2e5cf2de969cfea573".to_string(),
        k: "d926fe10f1bfd9855610f4f5a3d666b1a149344057e35537373372ead8b1a778".to_string(),
        r: "490efd106be11fc365c7467eb89b8d39e15d65175356775deab211163c2504cb".to_string(),
        s: "644300fc0da4d40fb8c6ead510d14f0bd4e1321a469e9c0a581464c7186b7aa7".to_string(),
      },
      TestVector {
        message: hex!("c5204b81ec0a4df5b7e9fda3dc245f98082ae7f4efe81998dcaa286bd4507ca840a53d21b01e904f55e38f78c3757d5a5a4a44b1d5d4e480be3afb5b394a5d2840af42b1b4083d40afbfe22d702f370d32dbfd392e128ea4724d66a3701da41ae2f03bb4d91bb946c7969404cb544f71eb7a49eb4c4ec55799bda1eb545143a7").to_vec(),
        priv_key: "b58f5211dff440626bb56d0ad483193d606cf21f36d9830543327292f4d25d8c".to_string(),
        qx: "68229b48c2fe19d3db034e4c15077eb7471a66031f28a980821873915298ba76".to_string(),
        qy: "303e8ee3742a893f78b810991da697083dd8f11128c47651c27a56740a80c24c".to_string(),
        k: "e158bf4a2d19a99149d9cdb879294ccb7aaeae03d75ddd616ef8ae51a6dc1071".to_string(),
        r: "e67a9717ccf96841489d6541f4f6adb12d17b59a6bef847b6183b8fcf16a32eb".to_string(),
        s: "9ae6ba6d637706849a6a9fc388cf0232d85c26ea0d1fe7437adb48de58364333".to_string(),
      },
      TestVector {
        message: hex!("72e81fe221fb402148d8b7ab03549f1180bcc03d41ca59d7653801f0ba853add1f6d29edd7f9abc621b2d548f8dbf8979bd16608d2d8fc3260b4ebc0dd42482481d548c7075711b5759649c41f439fad69954956c9326841ea6492956829f9e0dc789f73633b40f6ac77bcae6dfc7930cfe89e526d1684365c5b0be2437fdb01").to_vec(),
        priv_key: "54c066711cdb061eda07e5275f7e95a9962c6764b84f6f1f3ab5a588e0a2afb1".to_string(),
        qx: "0a7dbb8bf50cb605eb2268b081f26d6b08e012f952c4b70a5a1e6e7d46af98bb".to_string(),
        qy: "f26dd7d799930062480849962ccf5004edcfd307c044f4e8f667c9baa834eeae".to_string(),
        k: "646fe933e96c3b8f9f507498e907fdd201f08478d0202c752a7c2cfebf4d061a".to_string(),
        r: "b53ce4da1aa7c0dc77a1896ab716b921499aed78df725b1504aba1597ba0c64b".to_string(),
        s: "d7c246dc7ad0e67700c373edcfdd1c0a0495fc954549ad579df6ed1438840851".to_string(),
      },
      TestVector {
        message: hex!("21188c3edd5de088dacc1076b9e1bcecd79de1003c2414c3866173054dc82dde85169baa77993adb20c269f60a5226111828578bcc7c29e6e8d2dae81806152c8ba0c6ada1986a1983ebeec1473a73a04795b6319d48662d40881c1723a706f516fe75300f92408aa1dc6ae4288d2046f23c1aa2e54b7fb6448a0da922bd7f34").to_vec(),
        priv_key: "34fa4682bf6cb5b16783adcd18f0e6879b92185f76d7c920409f904f522db4b1".to_string(),
        qx: "105d22d9c626520faca13e7ced382dcbe93498315f00cc0ac39c4821d0d73737".to_string(),
        qy: "6c47f3cbbfa97dfcebe16270b8c7d5d3a5900b888c42520d751e8faf3b401ef4".to_string(),
        k: "a6f463ee72c9492bc792fe98163112837aebd07bab7a84aaed05be64db3086f4".to_string(),
        r: "542c40a18140a6266d6f0286e24e9a7bad7650e72ef0e2131e629c076d962663".to_string(),
        s: "4f7f65305e24a6bbb5cff714ba8f5a2cee5bdc89ba8d75dcbf21966ce38eb66f".to_string(),
      },
    ]
}

pub fn get_test_vectors_k256() -> Vec<TestVector> {
    vec![TestVector {
        message: hex!("4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a").to_vec(),
        priv_key: "ebb2c082fd7727890a28ac82f6bdf97bad8de9f5d7c9028692de1a255cad3e0f".to_string(),
        qx: "779dd197a5df977ed2cf6cb31d82d43328b790dc6b3b7d4437a427bd5847dfcd".to_string(),
        qy: "e94b724a555b6d017bb7607c3e3281daf5b1699d6ef4124975c9237b917d426f".to_string(),
        k: "49a0d7b786ec9cde0d0721d72804befd06571c974b191efb42ecf322ba9ddd9a".to_string(),
        r: "241097efbf8b63bf145c8961dbdf10c310efbb3b2676bbc0f8b08505c9e2f795".to_string(),
        s: "021006b7838609339e8b415a7f9acb1b661828131aef1ecbc7955dfb01f3ca0e".to_string(),
    }]
}
