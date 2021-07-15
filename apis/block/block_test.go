package block

import (
	"testing"

	"github.com/cryptogarageinc/cfd-go/config"
	types "github.com/cryptogarageinc/cfd-go/types"
	"github.com/stretchr/testify/assert"
)

func TestBlock(t *testing.T) {
	blockHex := "00000020d987e1f7cc030f4272beda5a081f8f8969f044ef72a3b2c2e544afc8230b9642d8b5de43b746fa65aaab7cfa0b521b41e4eb0d7c0e2fb834380259df581daf03157eb360ffff7f200100000015020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff050277020101ffffffff02246aa01200000000160014aef2e2877c45ada6b9eaef2bdb9131630ae12dca0000000000000000266a24aa21a9ed2af9d1c54b61988d37ce9bcde367fba7f3c5910cecaf8be1b6b443e937e39cec0120000000000000000000000000000000000000000000000000000000000000000000000000020000000001013d067178968e8e7469a61a82c365508ee3615bed93ed421ddefe19da412171080000000000feffffff02a0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee13373f2500000000160014a9b62806472c7b70c9f753bf41573e1506534dc40247304402205de2d7b0acf8e6027fcb1e197745ca8d23c1a4a7f4dc449762265e2aab2022f202204d35e5866f31595616b44f77e218fbddbfed702b830eb4c2aac087c5c1ad0648012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d476020000020000000001019421ca1de8781f070262511333197ab44f1629dbb704bd923f48bae4fa67a9f90000000000feffffff0213373f250000000016001455d6fbae5d95d2b03e5210abbe5a15ddbdb62c47a0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee0247304402206f590ce48f6f7a93821c116c3a4a9659d9739d8a9bc62fcae12e34cf0e4b26500220361867ad6dcd30af0bec09a9571a8888452d2812275201f4878de296a78e8627012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d476020000020000000001018e4212da7a883762b80efdf512263fd8d412771515b8b81cf992c01314fc93210000000000feffffff0213373f2500000000160014563423d5881cddbb72a1d6fea1af5c56bbea6a3fa0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee024730440220185d48c45b2e83f56249bfda4e2f0e1a211165c3c1175bd358cc7e4024e4764202201835811415ee2e5efbf42445b0113f54ae87b99e77e59252a69960759fdd8cf7012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d46302000002000000000101f0d8cef892eb52f81ac0e86bce4df8eeb9d0c1336cb62a069626c173e65321f80000000000feffffff02a0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee13373f2500000000160014e53cad733f173a80f1402d16123321535454048e0247304402207bbea0204f17fb98370ada2158666b4554d1354409efbd326835413041cd24410220323a16ee7b50f298446db61cd197cc44dd27fd90d45adb1a4fd780574300be7b012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d47602000002000000000101106a9ee2f6bbc4e58cbff2b1c99a53cdddec1a153f8a699350c00969500097210000000000feffffff02a0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee13373f2500000000160014f0321c988998afdb2b8788ce862402110792be8c0247304402207f6e3931036bb80b127b3d25ecf92bf5507cf057ec5af7c3a70b37e0c74575eb02205da9e647d92c86b2e17533050edd95e7eb887981e6145ade05728e0447a357bf012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d47602000002000000000101ea826992d745371bd6d762692369b94b2ac047df92d8b83cf9f46f6c9dbb13450000000000feffffff02a0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee13373f2500000000160014008e9141e1a0fd29384d41585598d2d1dc90ad380247304402202aeae79aa171eb28d21ee22fff4b58794d77e1ceda4c0bdd02fe87b4b6260c17022067184229e67f0ac2729e30206700fb50f0691e248690b6b103788552ebfb8b37012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d476020000020000000001011723ce44d3f606a6fbd3de7e5204ad22f6b48154e19e0e37fdb547c84e57bdfe0000000000feffffff0213373f2500000000160014b30e6003f0a61a3c594678af24bfe170894c15cca0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee0247304402202876093a9dec94f9ce1fb3b7c487a8cf38b09a9f3e438c2a1e56d2ff8e2287df02204bba8b7936cccad0302d4f0e39da4b27779a2e8a5ba5a506fe00907544224633012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d476020000020000000001016de1c5853fd550cb2fdd67f25b32496bb182404e2f127b5e82e48c587622eabc0000000000feffffff0213373f250000000016001496864cef7241cc0c24e8914f4ec75e34da0a70a6a0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee0247304402207dde78431c3e5ede2a90af0b3e3d32fadb5712e5ec04e3fac2dc6137d747187902202fc5603f63ce4498ad9062ed35b37ca5fc9a19fc90a9ef40ddec55b30820862c012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d476020000020000000001013e22c22ad4afedfac4642f54ebc1fb93f94f3af1c7cedd78fb17242975e00e650000000000feffffff02a0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee13373f250000000016001485fe6084fcec5323e4647ccb6781f2975ce78a690247304402202d4676c01c0f5f39d98f3e0435101c283baff3f2168bb20fccc99ef514abc77c02205703439a4ca4c289f9ab36e31ba88b81d5503ad705a30b036b628e505ef2b07f012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d476020000020000000001018e637219b2c53a395f6b61b85ff720e7380161b31473556d470878ccc9077fe80000000000feffffff02a0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee13373f2500000000160014d9a72d531686342f1f81a447f9643d22ec7bd0ab02473044022010df9caa2ae04bf2b04cce039d859e8fe9f04add799ce02ce4f5848a48eebb9802204e11ae33d32a7c99af8dcc85797b5dc0b7a864c5f9848be41604740fac2bdb89012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d4760200000200000000010124c74f712076cb581a3ee4ae502e094487139ca3da724edb9c0acfd905bd8d340000000000feffffff0213373f250000000016001465eab055d88f1ac853fe1f790740ce24c8623e4ea0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee02473044022053373da5b4b0583d7ef8e743b0fad5688d5a81c82dd33fb6a614a0cf7234431a0220192e5802c1bf8d2e05bca416e3e42b1fb7947169333c40a33bfda2bf1170237d012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d4760200000200000000010145df9bc5da442ff71110c0872dc58939138aba50f2e12bdf13ef7e75ab2f893c0000000000feffffff0213373f250000000016001427880ac035c111a8e8f71e4ae6a5bb4df79518c4a0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee0247304402200a13fd5ae3a2dd9bb210316fea853cc8ad9ada202a58c91f53c61a0741b63833022012a15e4bb30938b31da9606d03e2692e12ce87afe816df19ca20934dfadb7641012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d4760200000200000000010140b280318583b4e346fab2a2a126201799ddaffa169d3ac375b9434b3937a0750000000000feffffff0213373f2500000000160014e11569e65a6a7bbe75ca0322070eb0745201b99ca0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee024730440220655e813dcd37ee11f44d82eddc1540225866e3cc730b768c6c5f9b80cd1c447502200e538e03ed2a3c4f5da9396e884890556e42bf5d25ae49eb1b6c8a0101096fb0012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d476020000020000000001012fb0c024a0ae79e6217dc8889c6af40853b2b230a0e9f79d765c8b5525e0e2320000000000feffffff0213373f25000000001600147f44238db9775e0e738fb949724a7ffb66f4ac47a0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee02473044022032778f2c844abedb675ef947bdc7a11271800b5a11c98be5c0c9fdc6b2037f7302206acf28de27d327dc5a9d93998edad27f7509aa8479a1a2be1cb28f0eee28bf6a012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d47602000002000000000101892c26005096da187a5de107320c08a02e458be0184af915edbacaf5ad898c160000000000feffffff02a0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee13373f250000000016001460524bb60b4dc68abe9ba195376d572dd6cc20fa0247304402206b43d3fcceff2ee92380f6e112b99907b94df56c9ed2ab7df4fa750fd5010ed70220526807188cb56ff1944e19db3910b06d944c8772a76fd91b83cca791c740da14012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d4760200000200000000010128877cbe42170fca382e506d745a333a1e1eed9ed5c3597cf904cd441f7fef050000000000feffffff02a0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee13373f250000000016001462bf5d506758c4075c1484ed199c12b1d070dcc9024730440220514defa364f4cf78355fb64a79f0be487a0515f2c383cca2c7572b862f389b8b022040fb39e0cef457968c22c7a778b3225bf6d95e661c6bfaeea40dc6c9ae7fd9d5012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d476020000020000000001019b34c725b2b7de36389cec07b79109d482dab48e1641c2ba143fe1e0ab80f86d0000000000feffffff02a0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee13373f250000000016001437586a889710f537d70d511e41f45ade16ae96b80247304402205e1560130977bf5584e1938c34daa77e3dd0393eff6cfb18fa3d485a622a9f1d02200d55678c7c274442b0aa99d0a047094051b125ff74e8582be20d52dbb1825889012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d476020000020000000001017883189114213697b8adc8069c8bafc80d9972c9fc1949a478c57bde58daacbb0000000000feffffff02a0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee13373f25000000001600144b69012485912f125d6121323d1b2c55e24b3a8f0247304402203bf784686661951078c64dce1410677127d92015d018a1233a9be6351f26ad2302203b6287e552aed0abcf8740cc464d5843dbd3712e58b33dfa2be6947ba88e7b8f012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d4760200000200000000010180143a2ecddd4d3b32eb7c1e6378a054a2a02b278811a5ffbddf4db4e17f0ad70000000000feffffff0213373f2500000000160014fe956a004e01b6cbe82bf6a351f9370a60917abba0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee024730440220769b4f0bc75725b686fcc131af5b31722eeb0e7835bdeb812e16982183045d66022070a2f04e7619e75a9abd62170a1dbffceb11e398119c559bdb66cf49d91d7b43012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d47602000002000000000101f33b3ce193ef8a4450c6b4db2184538c0e5c5c5406e549478d8afe10b3d7e1760000000000feffffff02a0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee13373f25000000001600147235fdc337715c994998751dbfb0f3a38e87594e02473044022071323b810bed75c508337a442268503d70ac598f8db2fd0af57fb7ff6b913450022075157811bc930b2a7e2dc2cf5d6b075ca99e3e81bef2992111e43b8aebe9a0ac012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d434020000"

	network := types.Mainnet
	block := types.Block{Hex: blockHex}
	blockUtil := NewBlockApi(config.NetworkOpt(network))
	for _, errItem := range blockUtil.InitializeError.GetErrors() {
		assert.NoError(t, errItem)
	}
	hash, header, err := blockUtil.GetHeaderData(&block)
	assert.NoError(t, err)
	assert.Equal(t, "0ae1754425645e84cf354366150db602bd1ca38a5b64b6d7949ffc7f5480ab41", hash)
	assert.NotNil(t, header)
	if header != nil {
		assert.Equal(t, uint32(536870912), header.Version)
		assert.Equal(t, "42960b23c8af44e5c2b2a372ef44f069898f1f085adabe72420f03ccf7e187d9", header.PrevBlockHash)
		assert.Equal(t, "03af1d58df59023834b82f0e7c0debe4411b520bfa7cabaa65fa46b743deb5d8", header.MerkleRoot)
		assert.Equal(t, uint32(1622375957), header.Time)
		assert.Equal(t, uint32(0x207fffff), header.Bits)
		assert.Equal(t, uint32(1), header.Nonce)
	}

	count, err := blockUtil.GetTxCount(&block)
	assert.NoError(t, err)
	assert.Equal(t, uint32(21), count)

	txid := "cb3f209415bd73c709740fa0742ba960679cf22e86f691d11eb08e4a85cef95f"
	txidList, err := blockUtil.GetTxidList(&block)
	assert.NoError(t, err)
	assert.Equal(t, 21, len(txidList))
	if len(txidList) == 21 {
		expTxidList := []string{
			"7f5fb624f5cdce391362aa6befea307c4e778e008e799b40ca7119046f26ab31",
			"b4bcb584d0ee9c1e687c69ad0497b2686f7d47529affc0f1df8210b2a074c40c",
			"7af0cb6d0a0ded748790daa5e20b079e30cc82d90a267cad982328ed11409c17",
			"8d0b1863957eaa5b9c82a07c4e8b78801e496a8af4ed11450186fb1e7bdbfa29",
			"b42e9550b5129b34152950843ca09b0674a51ef4d273688366b216db7da16442",
			"d4ebf5a67e891b059c6aa67dd06c0ac3e129bf959919e2077c6519d6d460b347",
			"5edd72b9fef5225167c11862063c8cd955e648e01470b9784693d3868eaadf49",
			"d6f11f1fa8efb17911c1918ec1f2964d20b6bd5ddcefc60acc751094344f2b5e",
			"cb3f209415bd73c709740fa0742ba960679cf22e86f691d11eb08e4a85cef95f",
			"f4be3e47478145959d2d0978bf1900db2521be4d4f2964b277c35b754133bc7d",
			"9c9a3d9783dd9ac6c14c0ee487fa94f2e53053a7c96d10c37f0289edcdeb2b7e",
			"a5ab7f31660deb709d4ab2a70f4ce16a7cb02a16b03e843a39aba43115d3217f",
			"dc11069c2643ff09717a290e7dc0e38863316ec68b24fbb7d47d4e670f74777f",
			"4b244572aaec7a7b92431f7371b42547aca705b7ede430081be6374e8a672282",
			"4ae603bfb1689c29b1e5feb2cbd2f1ebb950df3ed4b25b6ad98f2f56da8cac93",
			"18b54774739e59b7bb0ec6a7196000c0f8fe42b441502636bdb5adde40f9e8a8",
			"587b9d5224a54fb3427cd99dc276b8acab4d4322c1b5681408d74a2927cd62ac",
			"98bdb3d84051b02a8bb147bb34d2e34c5b32339aebcccff696429c04538a45df",
			"695eddd38e01b5f67f93d3dcbdca033e1d8fd3feaefbdbcc2a2bd1326a6b7be4",
			"2bc841beb4de23e39e9674f96afc7a8b3c6db60c6d3c645c06a747eeb5135ae8",
			"be37763a766b5aa48d31a44a2c34ff1355e55e7f0efae58de9594d4eae3ca8ed",
		}
		for index := 0; index < len(txidList); index++ {
			assert.Equal(t, expTxidList[index], txidList[index])
		}
	}

	tx, proof, err := blockUtil.GetTransactionData(&block, txid)
	assert.NoError(t, err)
	assert.Equal(t, "020000000001016de1c5853fd550cb2fdd67f25b32496bb182404e2f127b5e82e48c587622eabc0000000000feffffff0213373f250000000016001496864cef7241cc0c24e8914f4ec75e34da0a70a6a0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee0247304402207dde78431c3e5ede2a90af0b3e3d32fadb5712e5ec04e3fac2dc6137d747187902202fc5603f63ce4498ad9062ed35b37ca5fc9a19fc90a9ef40ddec55b30820862c012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d476020000", tx.Hex)
	assert.Equal(t, "00000020d987e1f7cc030f4272beda5a081f8f8969f044ef72a3b2c2e544afc8230b9642d8b5de43b746fa65aaab7cfa0b521b41e4eb0d7c0e2fb834380259df581daf03157eb360ffff7f20010000001500000006774b1a7f9e060f94a1c7bd9d8109e233014e4e74a09a5b85a42add1837c18de15ff9ce854a8eb01ed191f6862ef29c6760a92b74a00f7409c773bd1594203fcb7dbc3341755bc377b264294f4dbe2125db0019bf78092d9d95458147473ebef40b484381159b8168441d718d2855f98b076d7f319e08fc129fc6684a10364d6cab62141fa7cf9455e1db2b83d9746dcb4151f71cbde29b8074d9c280cf2329858c705d27704a43f47e3a3066b9253a3d7380cb20874e67178450d2ab376f06ee027b00", proof.ToHex())

	exist, err := blockUtil.ExistTxid(&block, txid)
	assert.NoError(t, err)
	assert.True(t, exist)

	exist, err = blockUtil.ExistTxid(&block, "f5ce9417846b075c82da9368ed6bf40b59721662b64e4dd506fbdc50911f39fe")
	assert.NoError(t, err)
	assert.False(t, exist)
}
