//
//  BRPeerManager.m
//  BreadWallet
//
//  Created by Aaron Voisine on 10/6/13.
//  Copyright (c) 2013 Aaron Voisine <voisine@gmail.com>
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.

#import "BRPeerManager.h"
#import "BRPeer.h"
#import "BRPeerEntity.h"
#import "BRBloomFilter.h"
#import "BRKeySequence.h"
#import "BRTransaction.h"
#import "BRMerkleBlock.h"
#import "BRMerkleBlockEntity.h"
#import "BRWalletManager.h"
#import "BRWallet.h"
#import "NSString+Base58.h"
#import "NSData+Hash.h"
#import "NSManagedObject+Sugar.h"
#import <netdb.h>

#define FIXED_PEERS          @"FixedPeers"
#define MAX_CONNECTIONS      3
#define NODE_NETWORK         1  // services value indicating a node offers full blocks, not just headers
#define PROTOCOL_TIMEOUT     30.0
#define MAX_CONNECT_FAILURES 20 // notify user of network problems after this many connect failures in a row

#if BITCOIN_TESTNET

#define GENESIS_BLOCK_HASH @"000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943".hexToData.reverse

// The testnet genesis block uses the mainnet genesis block's merkle root. The hash is wrong using its own root.
#define GENESIS_BLOCK [[BRMerkleBlock alloc] initWithBlockHash:GENESIS_BLOCK_HASH version:1\
    prevBlock:@"0000000000000000000000000000000000000000000000000000000000000000".hexToData\
    merkleRoot:@"3ba3edfd7a7b12b27ac72c3e67768f617fC81bc3888a51323a9fb8aa4b1e5e4a".hexToData\
    timestamp:1296688602.0 - NSTimeIntervalSince1970 target:0x1d00ffffu nonce:414098458u totalTransactions:1\
    hashes:@"3ba3edfd7a7b12b27ac72c3e67768f617fC81bc3888a51323a9fb8aa4b1e5e4a".hexToData flags:@"00".hexToData height:0
    parentBlock:nil]

static const struct { uint32_t height; char *hash; time_t timestamp; uint32_t target; } checkpoint_array[] = {
    {  20160, "000000001cf5440e7c9ae69f655759b17a32aad141896defd55bb895b7cfc44e", 1345001466, 0x1c4d1756u },
    {  40320, "000000008011f56b8c92ff27fb502df5723171c5374673670ef0eee3696aee6d", 1355980158, 0x1d00ffffu },
    {  60480, "00000000130f90cda6a43048a58788c0a5c75fa3c32d38f788458eb8f6952cee", 1363746033, 0x1c1eca8au },
    {  80640, "00000000002d0a8b51a9c028918db3068f976e3373d586f08201a4449619731c", 1369042673, 0x1c011c48u },
    { 100800, "0000000000a33112f86f3f7b0aa590cb4949b84c2d9c673e9e303257b3be9000", 1376543922, 0x1c00d907u },
    { 120960, "00000000003367e56e7f08fdd13b85bbb31c5bace2f8ca2b0000904d84960d0c", 1382025703, 0x1c00df4cu },
    { 141120, "0000000007da2f551c3acd00e34cc389a4c6b6b3fad0e4e67907ad4c7ed6ab9f", 1384495076, 0x1c0ffff0u },
    { 161280, "0000000001d1b79a1aec5702aaa39bad593980dfe26799697085206ef9513486", 1388980370, 0x1c03fffcu },
    { 181440, "00000000002bb4563a0ec21dc4136b37dcd1b9d577a75a695c8dd0b861e1307e", 1392304311, 0x1b336ce6u },
    { 201600, "0000000000376bb71314321c45de3015fe958543afcbada242a3b1b072498e38", 1393813869, 0x1b602ac0u }
};

static const char *dns_seeds[] = {
    "testnets.chain.so",
    "suchdig.com",
    "testdoge.lionservers.de",
    "senatorwhiskers.com",
};

#else // main net

#define GENESIS_BLOCK_HASH @"1a91e3dace36e2be3bf030a65679fe821aa1d6ef92e7c9902eb318182c355691".hexToData.reverse

#define GENESIS_BLOCK [[BRMerkleBlock alloc] initWithBlockHash:GENESIS_BLOCK_HASH version:1\
    prevBlock:@"0000000000000000000000000000000000000000000000000000000000000000".hexToData\
    merkleRoot:@"5b2a3f53f605d62c53e62932dac6925e3d74afa5a4b459745c36d42d0ed26a69".hexToData\
    timestamp:1386325540.0 - NSTimeIntervalSince1970 target:0x1e0ffff0L nonce:99943u totalTransactions:1\
    hashes:@"5b2a3f53f605d62c53e62932dac6925e3d74afa5a4b459745c36d42d0ed26a69".hexToData flags:@"00".hexToData height:0\
    parentBlock:nil]

// blockchain checkpoints, these are also used as starting points for partial chain downloads, so they need to be at
// difficulty transition boundaries in order to verify the block difficulty at the immediately following transition
static const struct { uint32_t height; char *hash; time_t timestamp; uint32_t target; } checkpoint_array[] = {
    { 2016, "729c9b1c5ca6c5b3dd2acbb68ad413492c69827e20cb400f97476751257a9429", 1386526585, 0x01010000u },
    { 4032, "b9f70503731e52fab40da63697e26087d9dda8e83f5132675c3cf2fb5e2fb370", 1386635242, 0x01020000u },
    { 6048, "bbce917f7fcf2348de68eb03849bec099d48aa1947591133de99898d3fed5d22", 1386749842, 0x01050000u },
    { 8064, "299f4224a9b153a7b1600a00d16ffb6116ad1bd99c18c1e671d097411d32f66b", 1386866372, 0x01070000u },
    { 10080, "61236cb9883b3d8bdd4c97ef6bd29ff88576ea45428929bd551627eeb8e95925", 1386980096, 0x010e0000u },
    { 12096, "c7094268aadf7113842ca1936db91330f742bba5120958ccdea573de7357c516", 1387092085, 0x011a0000u },
    { 14112, "e23295950c9a72542f92b8d32874b254e3951f1e8a4b685bed5f0bd6269e2ebf", 1387197495, 0x01570000u },
    { 16128, "969ad11dadc437f74209d6a96573a1e235d59024e835f1d74f6682ce372874d0", 1387317316, 0x01650000u },
    { 18144, "428a450984ac9fd1449d3faf567dafee9725e31a9e9f5a71c50c81114798dfd1", 1387430223, 0x0200cb00u },
    { 20160, "fedf3bebfe6fac06275b133a86fd80a5b2ab257f28867d894439e0df7d5ee41f", 1387542614, 0x02018300u },
    { 22176, "f3537c37876c3c3be0c55954173682343d3a721378b81e0a7f991b4d138a6234", 1387666157, 0x02015300u },
    { 24192, "f26e1022bb48cc470a294d72273169592505afed9e5e62986e50b0c060ffa180", 1387788614, 0x02012b00u },
    { 26208, "fe1d123972512fc30137f8b2d411f331c2f6cab6705bd76c18781a2d14eb76bb", 1387905026, 0x0201b100u },
    { 28224, "e53dab5c829cf284df184ef70e142b0e202ab3ca353ff5ea4362a77f5c4be56b", 1388025549, 0x0201c700u },
    { 30240, "614529237cdb363357c5a631d8e12ffed36d4314f9f805a0ffcb86f17b0e7e4c", 1388149872, 0x0201b100u },
    { 32256, "d0b82fc8b9ff7359573cf51ca96dfdf118d5102e922bc56d92ef6c1b5d403616", 1388272671, 0x02018000u },
    { 34272, "801f254dbcbc3eb1ca1941fd6bac36ba25021d234e985c53dd31aecead7dcaf1", 1388395440, 0x02017e00u },
    { 36288, "e4eba9bf2433b757dc9da9af93988618527a2e8c8b37a20176a78ddd15b2a797", 1388516435, 0x02016800u },
    { 38304, "cf211fabcc69235bb58154ffef2ba509f686da86be909913b029a5887e88f034", 1388637646, 0x02016400u },
    { 40320, "a3f5b50455ff15b149c790bf09a7d65e9d3711cd340e9710e40696fd40a8c368", 1388763252, 0x02012700u },
    { 42336, "6427f3e8650d8df6a2742e853cd2aa7a099f6d98d23c10b24b2a0b1ae56e8dd3", 1388886232, 0x02014000u },
    { 44352, "1a3e9b9057894d38730bf4370fa8c40476b56748996a6b67bbb37b572d896747", 1389008746, 0x02011c00u },
    { 46368, "911275dfb7921387556d021d37b8a46f9a449b2f8be2d6cc27175bddc4add0d3", 1389132523, 0x0200fb00u },
    { 48384, "566210448d0f02a8d03199fdf31153a3b57b825af6ceb7ee18e9cfc00eeb0bff", 1389255315, 0x02010800u },
    { 50400, "862036fe389912e71ee1f76641e60851e64a1edf70f4db2e588219873e66b255", 1389372914, 0x02015600u },
    { 52416, "6a8b9271b3dd4277b9d4156739fee1bfe970a375c3854c4a4d9f7efe0c87c15b", 1389491604, 0x02018700u },
    { 54432, "62b9369fc98b5920e80155b1139ba7ae171fe12f5b2a8f97fb072d60419b4cb1", 1389616674, 0x02016100u },
    { 56448, "28a168841d9fd3c04b4d43b6b6aebcefd1d4e12dbf30805de94ad60f20920cdf", 1389738120, 0x0201a900u },
    { 58464, "d24599b8cb8d0a1ace201d0fae6ad531fcd3d6d2ada4fecd27b098ee51093fac", 1389859012, 0x0201a000u },
    { 60480, "7d2e4ee3371b030d87cea237e3dd950d8f02334c2f69d682cf403b9a8ad193ee", 1389976419, 0x02023400u },
    { 62496, "75b688971a8b9d03d8b6ae80057980e290494c8de064ccef1d63b7cdfa992afc", 1390096744, 0x02026500u },
    { 64512, "6107b5915ea67ff32e6fb5cc40e027588d707839a078f541314f4fb3ec9a5375", 1390214554, 0x0202ee00u },
    { 66528, "431e1efbe7868084f84f1f6f788aeb3f0cd4df73359fc66a2a530cc43044c8a1", 1390329679, 0x02047000u },
    { 68544, "9c8bcdc423d303ee557942709cd24cd188ab802c34e86aa9a4f6f9f691567c71", 1390450782, 0x02048900u },
    { 70560, "1cf5ec36aca6e44a0e370b7ee390a264109ced07414b409de2dfa0bfb0be5f8c", 1390571169, 0x0204f000u },
    { 72576, "61ede8dcdbab0fc664132adf3db7e926fb39dadc570ba48e647af1d1ad5857bd", 1390693881, 0x02046f00u },
    { 74592, "005a5222f8731fbf01f06a7d9910d8d1b1854cc2409df28fe8abe4baf27ee145", 1390817058, 0x0204bd00u },
    { 76608, "7cdb0763abc88302ca192695ac45aee3bafc7bc6da11d329a3f88bf2f7a7d099", 1390941640, 0x02040500u },
    { 78624, "e7cc09d41ab51f122cc302c7cee6b6e1a9f685d44cf2889fb7ad1bd8775f81bc", 1391063832, 0x02045400u },
    { 80640, "e7961b94f744997a5302d17ea9db0d745968ba39ba36388135c5176600adddc4", 1391183316, 0x0204ea00u },
    { 82656, "6c77f83c6b5f124b6921ad9c1df4fefe76807abafa21a2799be33cf01fae3167", 1391303525, 0x0205e200u },
    { 84672, "774bdddcf387e33ccfcd13a939f71ee1f64f932a9c365ef8546a25cb4863f530", 1391426167, 0x02052f00u },
    { 86688, "b573ee731971085b8908eb98b940f9559f961371beedd93eef4faf95d3adb0e7", 1391550603, 0x02044900u },
    { 88704, "07825bfe9ed7d90ade4cbd3ec9bef5b622f9362de800aa89eb321eae49e392d9", 1391670301, 0x0204fd00u },
    { 90720, "e4e566ac0ceda1735eed16e5be0ac050de8ba8b488cf41a740fa39fa1988ad93", 1391789130, 0x02060400u },
    { 92736, "3f4e47e20a5fbf0a0fa6d60e7a633951644ee65b3bdfb7ac0b4717d05131245b", 1391912197, 0x02058a00u },
    { 94752, "bd7568b49421eae149ccb35f848df7748d15e8ed1d38925002b08eed117e8049", 1392031480, 0x0205bd00u },
    { 96768, "b867ec0c844062756a4cc5e690cd2e56cb4ad7dd528d7e1d0fcb3953621328c7", 1392152524, 0x02067500u },
    { 98784, "67ad9e4cf91a2ad6a109659451f7d417eea68755066fc6c2eec21f24429b1f13", 1392272935, 0x02076e00u },
    { 100800, "7fe46a0dfafd9529768a7c6958a207286bdfafcd5d77ae02d62e9411c57e393e", 1392401107, 0x0204a800u },
    { 102816, "5b9e1c2b9a9ea913dd669ce1366cb4c714bf1c338cb0df6d97175b4c31828963", 1392524019, 0x02041800u },
    { 104832, "888cd562fad9eaa6b3b387d6e76bf31a417419bcaebab2d7e8eb58132d64ec54", 1392651439, 0x0203ea00u },
    { 106848, "0d69d545841739e5e6d2bd5308a4c32e4b7a3984d5301748a2cd9923651fb6e1", 1392766991, 0x0204c300u },
    { 108864, "8c4f8aabd19980e9abe6661ad18f42e630eb51d0be2b8bf6a83b0865bb893943", 1392889786, 0x02048000u },
    { 110880, "12b5784285e93eddf7a520a48f5f01cea20a45800b9c293ca6e6580cecbf1c52", 1393012157, 0x02044500u },
    { 112896, "e766aa18723338b2a34a02908a53c2a1e9f76edd6fe5469f93e7007651928000", 1393133358, 0x0204bc00u },
    { 114912, "43e9db5007ca97949fa267d71daa2dec1e56cabb34b1f34e7e8a860285df057c", 1393257044, 0x0203de00u },
    { 116928, "4698e02c4c7a5861780637bdf0c4d84237c6cbf1b9f35370090cff8be3855c5d", 1393380069, 0x02036500u },
    { 118944, "569f1a4e6a9b811818366897e4c84601c0d3a3237d8ff51dbf70d627eb288a72", 1393500434, 0x02042000u },
    { 120960, "bcff901618355372e3b1fc1ed654e7553b70edd552ddcaf966e28bdbb64b5a82", 1393620670, 0x02049500u },
    { 122976, "4693406b7e43fe976999634a6b2e60fd497a886e20b7159e6af152cef789f6ea", 1393744093, 0x02045300u },
    { 124992, "d90ad871ad7f3efa9c8b04fc9d05843efa95c9a23167eac046aa4dd862a0fde3", 1393863872, 0x02042e00u },
    { 127008, "808d1ba084aa16e229d72ba36ba23442f2bf7549df09c57f003c4a6cd8bd0aec", 1393987942, 0x02041f00u },
    { 129024, "a8dd7e228283bf4348b021895159d92f5b135e97d3a845ed647b7f9f9132b701", 1394108963, 0x02042800u },
    { 131040, "139b9e29a981de1c0724b58c2fe6a6092cee63dc25a209a5eed89e9a775483f7", 1394235374, 0x0203d600u },
    { 133056, "7dbf96a342f4921c1a7d0de8255ce94cb9fd652bb596960483362017fe128bbf", 1394359431, 0x0204f200u },
    { 135072, "7e2dc3fe256cc304e1c705c9cdb08154f11dc5564460e1effbbb7736ac985445", 1394486151, 0x02037800u },
    { 137088, "3f839f875376c832706797702f2d6d4ff124fbd988b68ba078ff4e8aa81d6828", 1394608841, 0x02049d00u },
    { 139104, "5badc551de55cab2bb072e049bd84053b981a96bd29a00e97b63d70d7b04e921", 1394729666, 0x02045500u },
    { 141120, "1f58bd2779f508ccd0f4127d4018ba968b8c6d9f1a80cda4b8a975583ef5b526", 1394857300, 0x02040000u },
    { 143136, "81d8da0601edf75d5b879584e7cea4d86001df8fb1de24ffae32d77df1b0a7ee", 1394978003, 0x02048b00u },
    { 145152, "b0dd42b8e05423125cdcc60c2609d0b0a5319adf6c208879257364943a4c0e45", 1395104329, 0x0202ab00u },
    { 147168, "d62079d930a643136cf1c61592d53d18fdd7836c8cdd9d99b60240147c3f218d", 1395234348, 0x02046400u },
    { 149184, "0e7693236e35489a92dc269f495240cf6d70ec5099cfb0f057af79ab0a54b312", 1395364077, 0x0203ec00u },
    { 151200, "af325f9e21f8fdf68eb701dc4e235765d637c194ecea4dbe06574382187768b7", 1395494773, 0x0204fc00u },
    { 153216, "0ecd072de0fed40776327596834fc4d0fd715297e5c8afc0f3e610a48aba9be7", 1395626071, 0x02037000u },
    { 155232, "5a85f4ab123365ee0e52bc0c1300f84b5aab0d03fe347683fc4ae86eb7694c69", 1395756317, 0x0202f600u },
    { 157248, "a431f48c45681178f9099af6d6ddd1979e0d850d57a90882a96fdad6c27b4f0f", 1395887027, 0x0203a300u },
    { 159264, "423809be60c51aca782c9bafe58680de9c6700a71cfecea641a4ce8c1c147d8f", 1396021359, 0x02033a00u },
    { 161280, "1a0f06917f3c5879082c40e8e2c9181bbedb2555944cd278575546cd5a282ed8", 1396151478, 0x0204e000u },
    { 163296, "67f1b950548637161820005422a5245fe044d25d303a80f3c968fe5843a6f808", 1396282420, 0x02045f00u },
    { 165312, "eb18744af5d18f32a82a184222eea95657e349e863c096fb7de7232b13c9c16a", 1396416881, 0x02038800u },
    { 167328, "41e4a001a81130ecc4de269a238ade17d166103283e42787ae42ae51d1ecffc5", 1396547586, 0x0202c100u },
    { 169344, "8f87d3c7ccfe4b6fb99d27aa0d5de48d13e607e75fa1c1122cb67774a99500f3", 1396683287, 0x0203f800u },
    { 171360, "9a376ed3809c270d36fdb2248769a332104833dc0ea0014133f66f1846b30c5c", 1396818299, 0x02039800u },
    { 173376, "32f01b6bba695ef111efd333708d89aaedfdfc117d1c3acc994315036dbede43", 1396954044, 0x02059f00u },
    { 175392, "c013896b42fe22c8af38c1f427983ad42f3d34843938446a2c1cbe491e74c264", 1397088663, 0x02049000u },
    { 177408, "26858dcd11535cc3c8f8ce3082ff0e711f1bf6688778378faa7c9e2c21db546d", 1397222024, 0x0203d300u },
    { 179424, "2b195fe4abe6f3bbe7c49552261b0a5af6c194ca827ded60be3e552016408a48", 1397357624, 0x0203ea00u },
    { 181440, "e6b21e580eecfff37ddbed66be367a07176d8096bddcb80fed9cc5d2905cd437", 1397490952, 0x0204f400u },
    { 183456, "aa64b2d09ea21f2b922a2b8ae0fdaeacfd49e4696df2ab79b97412cca214bb3e", 1397624144, 0x02050a00u },
    { 185472, "486e5d8c544a02fa38f63f7cd9b83b3746cbd5a0031a0ce6af0ba913cfde167f", 1397756237, 0x0204fd00u },
    { 187488, "8299023467baf76489ff595165d6297792922742f3978c62d62abee4e01751c8", 1397887154, 0x0203f200u },
    { 189504, "e4a8e60e1fd66c29616015d1996e4bff8ef2eb8494c52fe1d276ff9d7a3bf893", 1398016106, 0x02039700u },
    { 191520, "c9e3fc8cbf32b7647859dddb976478e2625749ed3c8b0992ff36c60a823363e9", 1398145038, 0x02040900u },
    { 193536, "55b34ddec4e1687d84e3d4b442989fbc01bab83487c67d962539833f9590850e", 1398274626, 0x02051700u },
    { 195552, "5d5adb01be40e3c61b5eb642cd589de4f959bcc4a66776cd8cee74d27737304c", 1398405815, 0x02038100u },
    { 197568, "c1566d3f3e436900d18748b76e31ff7e0a6b6886f2ed95e082d4fd828747352b", 1398535806, 0x0204c400u },
    { 199584, "4b2dafb8847cfd57cd407efd91306ea8eebd23c3d7d6188709028f8043067ef8", 1398668636, 0x02045000u },
    { 201600, "4294ba1673480f1f6db42deeff7ac3cafdfd864e94715e876a5dd251ccc9bdd5", 1398797573, 0x02035500u },
    { 203616, "f52876204ffd62842f417823895c79e396f164c5fe6a9e86dc7d614f13d48734", 1398926061, 0x02030400u },
    { 205632, "aa341bf2943c50154e4a0b095e71a668c684695b291035db239bd4fb2f1688ec", 1399058763, 0x0202f400u },
    { 207648, "f573debc94972f9915cea1d969e4a66cc018671eabbb8e455fdd4c8e5a67f5eb", 1399189742, 0x0202d200u },
    { 209664, "812262f37f44b9084cfadab96ce8dd5fa665517f4a910a528bea38b15c86a12f", 1399322874, 0x02033800u },
    { 211680, "0e1d9fc17add85c1698acd0e35691c329f7101fe77aeb4edfbf9ba6c299faabf", 1399450740, 0x02028b00u },
    { 213696, "34924983a17ad3fe0049b2272284447d0c36f90c12b382bc3bf9e9d36b563003", 1399582744, 0x02032c00u },
    { 215712, "edad110cd56c4b2fa492652fdc115a55ac429e43be526f900594b6a327514e45", 1399714416, 0x02035f00u },
    { 217728, "fa0d9171764a01e10d0e24d2cfa08bb4ccddf70efb44849e9582195b8ddc8127", 1399846692, 0x02031400u },
    { 219744, "a45bea7df154116124078ff6db06134c0e1167fb856dc828e8e6abd1d23f793d", 1399978378, 0x02028c00u },
    { 221760, "1bd7a053d632197280ec38243c1ff9843aca69b64dc3f1ddda7e19436ce3ad05", 1400111033, 0x02029600u },
    { 223776, "bc816585b3816e686d935592235005ad72f4a6d261fbd87a2ed6a27bc2fcaa41", 1400245025, 0x02031000u },
    { 225792, "d00aa7c065b94093c29b5c395e2b0e25852e67e6fa7d843a065c5471584c7bda", 1400376708, 0x0202d200u },
    { 227808, "ffa7e7710cb0cbbfd9dddbb3877b30d9d98d240b4dff92a511537ee6aa178d0e", 1400511240, 0x02037500u },
    { 229824, "da67031cefd32e87a854732b5a467e434a7367abe63d818869a80e5cbe824420", 1400652357, 0x02034500u },
    { 231840, "cbaa053369e87699404f34c3c552cec6fff32d5359e5d607982aa24f61276cdf", 1400789705, 0x0202e200u },
    { 233856, "d3569d305ef1a6cabf49c28d9eb354ac2bd7b4faeb4005d0233c346a28bb6184", 1400927413, 0x02024000u },
    { 235872, "97312620d66dedf6c4dae6148e94b7d7e9e43808ce5fec4b40ba326fc46ed64b", 1401068215, 0x02029c00u },
    { 237888, "07379a18cc6ffc25d26b9eb315232a46b41b256b168e9e08ec458d5f5edafa10", 1401204874, 0x02021f00u },
    { 239904, "552b3fca776a97e2bc7e48ec81ba68760f2362d07efc36dc7ee098f70d86a28a", 1401346981, 0x02032a00u },
    { 241920, "433a467734c61e29e6d764a60fd7ff3b5afecc160b6bf981adabc6405d122bb8", 1401484237, 0x02037d00u },
    { 243936, "9177407e22d3a11914aed08efe2175dd7b3ef2d14a396aa032b89fa9cc3fc3a9", 1401625280, 0x02032600u },
    { 245952, "b4441e97ccf0ccc264bd168d410f307b701e42c07a462bdb601fab719d2992b0", 1401762618, 0x02026800u },
    { 247968, "b24c49347dc316a3924ff2759873c7c66483f5de1ed938a400d218ee20800719", 1401901380, 0x0202e600u },
    { 249984, "e8d4d71a0f98bb641224cb00b09ca86fbce2c20fa5e2ff3ce0069eb08d081985", 1402040291, 0x02029200u },
    { 252000, "490fe3e1d784e703ba77bd5ed9ce303d88947841c1f73b94c7584dd0a473dff0", 1402177284, 0x02033100u },
    { 254016, "a9e774e8d592984c6811852fca69413b8c2610a003405c69373745cf2145e538", 1402319882, 0x02027200u },
    { 256032, "a15e84fb657c1d57ee7c54d148abe1f2d5c12f1c106c7882022012c3624f1434", 1402456535, 0x02027a00u },
    { 258048, "05480c10c99e2ebf01d9c4b64584c269696d8dc45ab26aea6bb652eb9fdb7b44", 1402593628, 0x02032500u },
    { 260064, "ebdbce2fc870a7c0bf6d9c2f270c3d5cb64974b75d34e596e422016f525d838d", 1402733538, 0x0202a900u },
    { 262080, "7d0852f76ee97cf395166c7ba6fa841f05240f3e96e1ef8511aea030806a6c65", 1402871023, 0x02038600u },
    { 264096, "e01bd666092f994898719cd66d298317046ac5198ef92c433d2a48b5a5691a05", 1403008126, 0x02037300u },
    { 266112, "6b234d6ce62249a7400cbac5664519fbbe9e974ff1ff3ab51cbd5c1f2f197705", 1403143871, 0x0203ab00u },
    { 268128, "668912865675017509b18ef5f8f27d27bb35f98a92826b9cb76feb2560bc8bd4", 1403277338, 0x02036700u },
    { 270144, "1a79bd672c8db9bb7087133ceee6d0df0a11285951824b812f09240f62c445fd", 1403413131, 0x02032800u },
    { 272160, "f2bd4da1260b61136db368c3805e7f7694732211340af228c0a8aa939517d214", 1403547885, 0x02040c00u },
    { 274176, "defdcea584f9f6de300049ee74c0ca155d4249753a16a2d893956bc0dde86401", 1403681200, 0x02048300u },
    { 276192, "ec0f5f2cb9db922f665a9e7c886d097d027ba55fca238e2e3bcb842d2b98d717", 1403814694, 0x02038000u },
    { 278208, "0733713315a3b22f3e6da3d6cc8d8a02757025082696857f81efe43656b6b495", 1403950437, 0x02034600u },
    { 280224, "30ab0dbe841e9ce4f262fc62ff08be50e8e2d52b16f11023217db22735cb4307", 1404087681, 0x02048700u },
    { 282240, "b9e1ce8466dbe907b3b75c630bed3c51cc2eba5ab0034ba720294e2beb1af60d", 1404222140, 0x02047900u },
    { 284256, "797d2c73fc9080c38cf29d5cbc62178b28e6d605c7a2f55df9e8a5b26ef3f58d", 1404355536, 0x02030300u },
    { 286272, "3df9eecba4234b26d686ac463d6f782c273aa006a0d69e28fcd310be2e451ec4", 1404491363, 0x02041700u },
    { 288288, "4fca3b67f33823d9923522d4e82fd109bcc0e94e954c50b896d6fbdb4f210d72", 1404627745, 0x02061b00u },
    { 290304, "e22b66ff5632600c67a2562c8bc1fe4933df739a2f064b3a13f0425804c96a4c", 1404763984, 0x02044a00u },
    { 292320, "dc781b51a3da57dc6d6fc0d4dee1d3b7f87a3c7d59dda7b1c52c7c615ce6666e", 1404903390, 0x0206b600u },
    { 294336, "06d3ca7519feb0a6b2eea92da8ae22acea19315952b68c72771f2b8f07bb2842", 1405044529, 0x02060500u },
    { 296352, "45139efe67d6a27c74e02d1033a47780c1edf3dfbdc9ea021d1041c6afc39a33", 1405185374, 0x0206a600u },
    { 298368, "5642d5f212571fbb26d2b725d14314fe509f41b3673f67e8cba90b96656107f2", 1405330677, 0x0205ca00u },
    { 300384, "415c5ca137bb1423e7757d3c5577a2ef4126fea525d293256d09a2e9c5251b9e", 1405467773, 0x02027400u },
    { 302400, "02010996bfaca49b8f13fc8d2954589e1c0b6e97bc670838b9be031ad93cc2e8", 1405604574, 0x0202b000u },
    { 304416, "46854d035efe694b65a6c2eb8a051db660bef5c10048870772cb82895629abfb", 1405740770, 0x0202c400u },
    { 306432, "4948ae9896f53d2cb5f3c4bbbb201118fee894125109d00d86a8b0576030f39b", 1405877243, 0x0202a000u },
    { 308448, "71c242164856e8ef169e1a5d4480d504ea4ede2a45c0a03fc981497aab208643", 1406013872, 0x02036f00u },
    { 310464, "ade21e55d5f057fc970413f4335ed521937f699895ed64963dd294d054b910c6", 1406153611, 0x0202b900u },
    { 312480, "b71e3cffff8a2dabda50638fbbaf0b8e9affae62a2395b3fc82e05dc04a776b0", 1406287345, 0x02027500u },
    { 314496, "744630d3a490333ae68de7d046b0246eea61df93021877a9b0dd6b725b9ba596", 1406428014, 0x02029f00u },
    { 316512, "24fadaf59e24086300588d9b21d0f4acd3bd6fb043a53aae6fd74ecac747db4e", 1406569054, 0x0202c200u },
    { 318528, "1def8698d8b0924fd762434e25c5f4e72b417eb25649035fed869f8a8cb5c0d4", 1406713780, 0x02037b00u },
    { 320544, "b4cd740e2d0738b1e8caf7ec81303de3f86f1dd83b8e2bee00a1a44d075afe37", 1406862898, 0x0203a200u },
    { 322560, "e8ca47c71c2ffd7def6b07d114fc7e79bea377c895bcdbd958c88b2fde21b2ae", 1407009627, 0x0202e500u },
    { 324576, "e6b125367483f262b34c5e0587f35f4b3cce1b0dbc63e13579ff4f43934b668e", 1407156784, 0x02039300u },
    { 326592, "ebf0d640ed016a727d974fdea5ffd83f43664f21b09e68c483a977105fdd1fd5", 1407296300, 0x02028e00u },
    { 328608, "3783089a6a56eb78b5e8fe0ceac3d027dc46960ac24919e1cf958df0a7843247", 1407437597, 0x02025600u },
    { 330624, "22ebac6c342960362f918bde7d95a572491058df61e6d70926e68256fd730f12", 1407579581, 0x02028d00u },
    { 332640, "3ccce3aeac1277b9b5069769bb874cab86ef071a816cc7350fbc9a4620b25d45", 1407724773, 0x0202bc00u },
    { 334656, "b5baf4c6f2752a927ad2ff899f68a2a25063a0b13e9c1565192fc36b782985cf", 1407869229, 0x02032400u },
    { 336672, "3087d526a64aa72a13e325e6fc39851e0d961a64f66634ff55736f59a031e8b0", 1408013881, 0x02034e00u },
    { 338688, "42b576af327b6ade35683dfa26c890bd142295b777bcebb9a976848b63278a88", 1408156222, 0x02039200u },
    { 340704, "6b460bf36b7f258c43646da7a25a1bc1c746e9ac32491423ac19d89b426b6f9a", 1408299730, 0x0202e100u },
    { 342720, "49181ea0c279ecea67862aa812cc9f1717d1ea5f9ba2a8a008324917575e1d5c", 1408444593, 0x02042a00u },
    { 344736, "742e0fc7f7b637fa044c801cca15d98eabfeb62e105dd0c6ba9b0a5330c171cd", 1408590253, 0x02027f00u },
    { 346752, "9a7c64f52d5dd2f6ffed42496900c8c001b711cb6b987d9f88a2031b9a4c0a93", 1408729765, 0x0202ae00u },
    { 348768, "33a8c6041c2df538ef0afdff043d30a72e4058bdf75afaeedb2754828ce9f4bd", 1408867126, 0x0203e500u },
    { 350784, "b4da0e99af78a3e40b8bee274287f41364e9f806f9e5e356b93640ebb934f70d", 1409006719, 0x02035c00u },
    { 352800, "88fab11bcb3f4ec9f7e81f5ea98730f851dbe924cbe9ddfc7f81b2990fd80497", 1409148619, 0x0203d200u },
    { 354816, "3e9e3eeac005a3d46093c0fa47358a59348c010921fafd8ecf2d9d041e66cd4a", 1409285416, 0x02032200u },
    { 356832, "5b6d08aadeac8bff251d9327365406193aa41c52e883430658b1928b4f310f41", 1409426808, 0x0202e000u },
    { 358848, "972706b00765d558441da3c9c32501ca3859812e880741a7ec07f6b2fd79a9a1", 1409569850, 0x0202d900u },
    { 360864, "44682330c7753a9673a1e448c91b55ca395b476e4c836ee07287eae836b4ad4d", 1409710285, 0x0202db00u },
    { 362880, "9a9c8d075a1c356eb43611ef2c24d42a10c3d1bd37ea7048d75ecfc6bdacf7a8", 1409853429, 0x02043800u },
    { 364896, "7214415bb60f45e495cc35f89284146f60d69f2d1301a9ecc5f032fd300327f2", 1409997735, 0x02065c00u },
    { 366912, "579a80b66e6a3e58c88de3ac00e4fdd8e6a30efbd72ea45c8ecbb500dc57df47", 1410142713, 0x02050600u },
    { 368928, "d20f1ad9e57fc59545b8194e4b3b031e266de4db675d7b40191c6f8ec845446a", 1410290769, 0x02052100u },
    { 370944, "5efd13df7ae14b3a36a1cedebff399395d0e8b5734555b3cf9d3287fdc7e1d12", 1410437478, 0x0204db00u },
    { 372960, "629d9fe9a87b762a4ebd92f1ccf48dd64fb54b31dda3d26a0acfeaca19b8b25c", 1410564445, 0x02110d00u },
    { 374976, "980e317ebcd39a00c8650ca2abe79228bf20fa0ecada3ef3ece357a13c6da15c", 1410689524, 0x021fb400u },
    { 376992, "af72ba062f2ef583119a163755554988c0d879ee127310349cfb9b1e4b5accb5", 1410815342, 0x0224ca00u },
    { 379008, "b64ed2a2cea55d79435addd332684f7f5c68fff8fd547d2cbaeb76a70b9dff0a", 1410943111, 0x0232e800u },
    { 381024, "dea3c46965ba937e5cc04388ffbacd2af984bb3dfef9aa55eee58686aa4695c6", 1411068528, 0x021fd200u },
    { 383040, "fda7054eb894665e5b038564c5e940f3ec11511eac8f77b4396d2a825b453e57", 1411194748, 0x0235cc00u },
    { 385056, "b032ed9796f3fd81974a1c5a87ee7260aab2c19b57356f5ed27c72710f99000f", 1411321793, 0x0233c500u },
    { 387072, "c2136d5602d42e6652e5fb7dac67f8c813b4b80e4bb2956f5f2404da5ea040b3", 1411448693, 0x021d3800u },
    { 389088, "e58d2ca990f6311bd806f65a17e4f0a53f2df7052af1e877c9c76e4faa65919d", 1411574755, 0x0229e000u },
    { 391104, "e736fa056a93d4eecbe564e091aeb98a403b20ddc6e34b58e87040d4ed4b1baa", 1411700787, 0x0224ea00u },
    { 393120, "dfc17fefd97ccdcabe155af79c0fa39c853d908ae96b0aa2017edc8bbb7371a8", 1411825860, 0x0230c300u },
    { 395136, "320acaeb80de928a066dffc9a5d52cd77b072274a097212ae8cd73ac46b84449", 1411952671, 0x02255c00u },
    { 397152, "1cd35fceeb66a3ab560f41c9745b00e1b7fb36274a95a740a18ae7524c0c5a0f", 1412078823, 0x024b8400u },
    { 399168, "3f75215f2fc8ac716e1fb985c8ce724bd6ec399bea408c9b03881d2b06c1897c", 1412205961, 0x02493400u },
    { 401184, "e6ca5e523205207703c1670e30072f84722448c37eef571046edc8939ab4c491", 1412333544, 0x02302600u },
    { 403200, "c165ef7f0600b1a53248f2397b50193ac5ca4da084c8d207298401f24aec4788", 1412460609, 0x023d2800u },
    { 405216, "9df7cdd7e2c9ab57d6242d3c539c5e8c16930821deda642c301e54730671f96e", 1412587500, 0x02366600u },
    { 407232, "b0a324718b87fa4b1c845e1aaf36cd2f5d8c175fb31111b9d07daf2c8c7ccf3a", 1412714774, 0x022b9900u },
    { 409248, "69f8967a07ee3134686a1829f7ed4e25c6868d402e960b5184eec9398ffa6b21", 1412841245, 0x0221b500u },
    { 411264, "20f7e0e6303e2f6247e22e01fb012e94e8a91eca3b7107296ce5febbfb89a441", 1412966724, 0x0242e500u },
    { 413280, "fa81acf04748375e611336a35625a1c95d99ade9a3b83b2c2a33ef523e271bd5", 1413093853, 0x02412600u },
    { 415296, "30477379f3de5ab2e1cf621f0fcfa01ae58a782ff50b3a206070700ae9a3c6f0", 1413222709, 0x022dad00u },
    { 417312, "9f33f14e1d9c87768c3616d05b719824d7cd040f34da745b51ffa0ecbb23dd7d", 1413350091, 0x024a6b00u },
    { 419328, "78833e075854d4472363d4aa0c8de4ac334c7caa59c7f6df3fee01157f9a4532", 1413477482, 0x0230d600u },
    { 421344, "0b1416bd225ab0e68eb929a4ba321f6277919043a2349285ec752d30c50c8177", 1413604638, 0x02301300u },
    { 423360, "95f14dd2ec3a75a36a47e7662ef08261e64762766caf7f3e5a747a9204159d63", 1413730696, 0x023a0e00u },
    { 425376, "203114fa71b3435d37bc7ab6ff40e842bf3e35dc5ab3aeba6958b38ad4b97649", 1413857696, 0x02495400u },
    { 427392, "a7db3eccce080d144cc2f29dffd02b53be70b8048ddf7d74742b255d0acd8d21", 1413987668, 0x02342000u },
    { 429408, "4596da8ac5af1953895ea0fd411bc4af05b7379523b87acc9d49861f267474fb", 1414116078, 0x02255b00u },
    { 431424, "6a1e2902e0db3e61a2c7bce438dce155d9b1691727738cb8d96a1d17b1ff30e8", 1414243281, 0x022e4e00u },
    { 433440, "a23f0798ea1c63b971509f5e017688e814fd96c6f4e895867ff0e004b03b2281", 1414369654, 0x02331600u },
    { 435456, "34f8c0772075926e0595ee7bae5feb97c1bc7fd566d7c9723e66142081463a34", 1414498284, 0x02398100u },
    { 437472, "fe07671db2a057f5985d919f78765a200d063c1e00e7abe31061e1ed108a4a9c", 1414625217, 0x023f6900u },
    { 439488, "eec12a006519ecaa42e52d1d7b52d139816987e09a93b611cf3dc846142c7bd0", 1414751495, 0x024aa900u },
    { 441504, "3418aeab151c714eda674de849ea94ac01fdf35397c58d42731500e40844ebd9", 1414878646, 0x02418300u },
    { 443520, "ad563011733f7853b8d8714eebeb715eb67fbb2e5838189b1055a8605f8ecfda", 1415004943, 0x023fdf00u },
    { 445536, "1e64d951c84f9859da6b2ce3205d9b2c16bd243c4ffc938f2ad68f6cf747de1e", 1415132058, 0x02375200u },
    { 447552, "caf500dc22601914a6912bcbf9ebb321c9e27326275c30f75a881a914c8a972e", 1415259064, 0x02279400u },
    { 449568, "b93b5c14fb77233ac4d90d4c1b27494e7c734c58d9724374c16af41747642d9d", 1415385611, 0x02534200u },
    { 451584, "c03ebc35c7d5ca2a4f2fa6e99b2ff53ce2566c63f2cb09cd390ce4bc65f1e01c", 1415513492, 0x022b8000u },
    { 453600, "dcbc7c07667816dc5fb5c43616b17e2fe047906e733b9ee1d56ef9e935f6d76c", 1415641062, 0x023dbe00u },
    { 455616, "ab67400ca96c3ffcf3abfb32464eb3a2067619d9f5b32516317d607bd647f921", 1415768562, 0x0227d900u },
    { 457632, "23540c912cc25a91a961a63c0f1e7a726c2d4cd547a971b51fafaa76f9fb48a1", 1415894690, 0x023e4400u },
    { 459648, "fe383225badfa471a04de2a2906f63ee304b2977fe123dc0dce9b67fde9293af", 1416021092, 0x024a7b00u },
    { 461664, "34ffbf3f2bb2cdb161c600eee5c22430958c16690a31b9e4a3be7fe83012d834", 1416147131, 0x024a4d00u },
    { 463680, "e23b0b6bce00197ee9856edf1014b89e7578993c0678cb8cf16673f2614fb1d1", 1416274432, 0x022dec00u },
    { 465696, "8b626a8f73570e05133884121691f60545a5a492af167967180fedd3ac4bbe59", 1416401233, 0x023a5d00u },
    { 467712, "f2ea926c319ee2d68f9c7a070dce99d670068635a3d5f9b58b6b70f0cfb96981", 1416528546, 0x023dc200u },
    { 469728, "255f0d3131020ee0d9dc5eb3b1fe701e6ec6b3f006cd1fe5cd06109f6b2003aa", 1416656932, 0x024ce100u },
    { 471744, "56bd86c9a59426a0a16edd5e01e051685ad2bc25458fda749bc6b68d7b6ba7da", 1416783970, 0x023ada00u },
    { 473760, "91724024710a2292d4025d0aad98f323f5e8d5a74baf8326cf4d711b676c4e0e", 1416910430, 0x024ecb00u },
    { 475776, "95caed85ccdc1291137fddb66994cf9c8a2a4a76efd53c786ed4a190c664f866", 1417037487, 0x0238c700u },
    { 477792, "b5329b5b824df4ebce579a224c5887190c724ff26e5d84ce23e00373d316548f", 1417164186, 0x023cb200u },
    { 479808, "25a1e6e83d5314a9d576cecb4bf91a366e61792ea6bd7129f167b3b3d0022d69", 1417291332, 0x0244ff00u },
    { 481824, "57225a3c50136c0d3c3c44d7b5d6c4bacaf18c7ac10420803a0c490a7f8b372f", 1417419430, 0x0246d500u },
    { 483840, "ab4964d217f874874e5626b2030a2ac1a9febfb466568da7fcbd16016d4ed4db", 1417548226, 0x0265ce00u },
    { 485856, "4b9bc2f17f121ecdda55d2ea89e06ad1b1717d0563b81b73f153907c6081f958", 1417677594, 0x0231aa00u },
    { 487872, "ead72e51b98cdd53f25fb6c8dfaaee09c625281c733b62905c43c4a935fa1324", 1417805622, 0x02424000u },
    { 489888, "7b106a563ab18b07b80a7ac7cfbe0f4417ae181d2a0e794b9d352b2196ea98a1", 1417931874, 0x026df400u },
    { 491904, "e8f359c91724c380a59c94a6c711069cdbc910c825ca650bd8cd69b2bf33fdc8", 1418058954, 0x023cf900u },
    { 493920, "50ae27b27aa50263bb9eb07a9b0744512ac14dda00f9a7a37e7454e7d10d6e59", 1418187414, 0x022ec400u },
    { 495936, "172b0ccbd1b3843346fc368a90d1288b832f3bcbdc9948447b9f4fc4f06451a1", 1418313611, 0x023c1400u },
    { 497952, "6dba46139ebb158d410f635ccfe4d33e13f10544ae1388ebfc1b3ec5c05f24b3", 1418440525, 0x027f9600u },
    { 499968, "758f2e9580a7fe98541472dd36169ed068c80b22cfb41723527c4288729ce7da", 1418567958, 0x026cba00u },
    { 501984, "26beb4f1a409875e57e6ccefa0994bd72dd62833eceb71c6a164662bb59eff72", 1418696200, 0x02351a00u },
    { 504000, "ab1a0a2fa1ba8fab2e9c05b5028a6268fe28c387b8246e332d6ac64b6976ca7f", 1418824139, 0x025bda00u },
    { 506016, "f6c1b41b385f04002509471a472ca619bdf5fd0a55bc2c3fcde5c89dd054f733", 1418951734, 0x0247c000u },
    { 508032, "cd88b5f8f27bc457ea02233242dc26b86fcb11c3e9c18466f64860f1c73c8e5b", 1419077853, 0x024c5900u },
    { 510048, "db13f5d3b450721189bb0b963580c1b49d1021657f749a231164440559ac9a61", 1419205286, 0x02432c00u },
    { 512064, "0d8bdb1de4d92d75210f57acdff227ab1b23121053d26a3d28be0ffbf8bb3519", 1419333475, 0x025efd00u },
    { 514080, "14b6292c09654c254eff9a4f1056ce38ef1e2166a19bb71f9e2a6204e988675d", 1419460770, 0x02590300u },
    { 516096, "ebf306c6c59f3f4cd4c05861feec12c2f2ca39f17a03181074884eeba304b79c", 1419587930, 0x027d2400u },
    { 518112, "ebef268d157247029af386b0ae07f4157ff6691d425ecf43d72e00391e7ff928", 1419714973, 0x026edd00u },
    { 520128, "e7f351912a2e1c33324eea702a9033410f9ed2b436ba8ce05831e32e009fb1fa", 1419843461, 0x02751800u },
    { 522144, "efbe4dc7921cc6e1e8c0a7e1747511855fdfb0808c641a96d508b0c0ab600db8", 1419971486, 0x02547200u },
    { 524160, "0ecb6bd9129ba766190b6bba6ac9c416594866402a74eceb249827a0dd035968", 1420098891, 0x02432400u },
    { 526176, "2c8564466a88de70c30c744fad5c457cd0c622db0677f6f7ba78915b8c3594fa", 1420226730, 0x0230ec00u },
    { 528192, "3dd633cf5250643c1f28f665d4b04256522ca5a81c28c7b82a425c94cc018cbc", 1420353630, 0x0240fa00u },
    { 530208, "84fba87684d970f0f7eea9ec333c5879297581d4132059d5de761d992c9d4a49", 1420480767, 0x0239ff00u },
    { 532224, "aeae45cd6689228c211157a82caed05fa896e7ec94504f8e49105eada33d1dc5", 1420609083, 0x022b2200u },
};

static const char *dns_seeds[] = {
    "seed.dogecoin.com",
    "seed.mophides.com",
    "seed.dogechain.info",
};

#endif

@interface BRPeerManager ()

@property (nonatomic, strong) NSMutableOrderedSet *peers;
@property (nonatomic, strong) NSMutableSet *connectedPeers, *misbehavinPeers;
@property (nonatomic, strong) BRPeer *downloadPeer;
@property (nonatomic, assign) uint32_t tweak, syncStartHeight, filterUpdateHeight;
@property (nonatomic, strong) BRBloomFilter *bloomFilter;
@property (nonatomic, assign) double filterFpRate;
@property (nonatomic, assign) NSUInteger taskId, connectFailures;
@property (nonatomic, assign) NSTimeInterval earliestKeyTime, lastRelayTime;
@property (nonatomic, strong) NSMutableDictionary *blocks, *orphans, *checkpoints, *txRelays, *txRejections;
@property (nonatomic, strong) NSMutableDictionary *publishedTx, *publishedCallback;
@property (nonatomic, strong) BRMerkleBlock *lastBlock, *lastOrphan;
@property (nonatomic, strong) dispatch_queue_t q;
@property (nonatomic, strong) id resignActiveObserver, seedObserver;

@end

@implementation BRPeerManager

+ (instancetype)sharedInstance
{
    static id singleton = nil;
    static dispatch_once_t onceToken = 0;
    
    dispatch_once(&onceToken, ^{
        srand48(time(NULL)); // seed psudo random number generator (for non-cryptographic use only!)
        singleton = [self new];
    });
    
    return singleton;
}

- (instancetype)init
{
    if (! (self = [super init])) return nil;

    self.earliestKeyTime = [[BRWalletManager sharedInstance] seedCreationTime];
    self.connectedPeers = [NSMutableSet set];
    self.misbehavinPeers = [NSMutableSet set];
    self.tweak = (uint32_t)mrand48();
    self.taskId = UIBackgroundTaskInvalid;
    self.q = dispatch_queue_create("peermanager", NULL);
    self.orphans = [NSMutableDictionary dictionary];
    self.txRelays = [NSMutableDictionary dictionary];
    self.txRejections = [NSMutableDictionary dictionary];
    self.publishedTx = [NSMutableDictionary dictionary];
    self.publishedCallback = [NSMutableDictionary dictionary];

    for (BRTransaction *tx in [[[BRWalletManager sharedInstance] wallet] recentTransactions]) {
        if (tx.blockHeight != TX_UNCONFIRMED) break;
        self.publishedTx[tx.txHash] = tx; // add unconfirmed tx to mempool
    }

    self.resignActiveObserver =
        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationWillResignActiveNotification object:nil
        queue:nil usingBlock:^(NSNotification *note) {
            [self savePeers];
            [self saveBlocks];
            [BRMerkleBlockEntity saveContext];
            if (self.syncProgress >= 1.0) [self.connectedPeers makeObjectsPerformSelector:@selector(disconnect)];
        }];

    self.seedObserver =
        [[NSNotificationCenter defaultCenter] addObserverForName:BRWalletManagerSeedChangedNotification object:nil
        queue:nil usingBlock:^(NSNotification *note) {
            self.earliestKeyTime = [[BRWalletManager sharedInstance] seedCreationTime];
            self.syncStartHeight = 0;
            [self.orphans removeAllObjects];
            [self.txRelays removeAllObjects];
            [self.txRejections removeAllObjects];
            [self.publishedTx removeAllObjects];
            [self.publishedCallback removeAllObjects];
            [BRMerkleBlockEntity deleteObjects:[BRMerkleBlockEntity allObjects]];
            [BRMerkleBlockEntity saveContext];
            _blocks = nil;
            _bloomFilter = nil;
            _lastBlock = nil;
            _lastOrphan = nil;
            [self.connectedPeers makeObjectsPerformSelector:@selector(disconnect)];
        }];

    return self;
}

- (void)dealloc
{
    [NSObject cancelPreviousPerformRequestsWithTarget:self];
    if (self.resignActiveObserver) [[NSNotificationCenter defaultCenter] removeObserver:self.resignActiveObserver];
    if (self.seedObserver) [[NSNotificationCenter defaultCenter] removeObserver:self.seedObserver];
}

- (NSMutableOrderedSet *)peers
{
    if (_peers.count >= MAX_CONNECTIONS) return _peers;

    @synchronized(self) {
        if (_peers.count >= MAX_CONNECTIONS) return _peers;
        _peers = [NSMutableOrderedSet orderedSet];

        NSTimeInterval now = [NSDate timeIntervalSinceReferenceDate];

        [[BRPeerEntity context] performBlockAndWait:^{
            for (BRPeerEntity *e in [BRPeerEntity allObjects]) {
                if (e.misbehavin == 0) [_peers addObject:[e peer]];
                else [self.misbehavinPeers addObject:[e peer]];
            }
        }];

        if (_peers.count < MAX_CONNECTIONS) {
            for (int i = 0; i < sizeof(dns_seeds)/sizeof(*dns_seeds); i++) { // DNS peer discovery
                struct hostent *h = gethostbyname(dns_seeds[i]);

                for (int j = 0; h != NULL && h->h_addr_list[j] != NULL; j++) {
                    uint32_t addr = CFSwapInt32BigToHost(((struct in_addr *)h->h_addr_list[j])->s_addr);

                    // give dns peers a timestamp between 3 and 7 days ago
                    [_peers addObject:[[BRPeer alloc] initWithAddress:addr port:BITCOIN_STANDARD_PORT
                                       timestamp:now - 24*60*60*(3 + drand48()*4) services:NODE_NETWORK]];
                }
            }

#if BITCOIN_TESTNET
            [self sortPeers];
            return _peers;
#endif
            if (_peers.count < MAX_CONNECTIONS) {
                // if DNS peer discovery fails, fall back on a hard coded list of peers
                // hard coded list is taken from the satoshi client, values need to be byte swapped to be host native
                for (NSNumber *address in [NSArray arrayWithContentsOfFile:[[NSBundle mainBundle]
                                           pathForResource:FIXED_PEERS ofType:@"plist"]]) {
                    // give hard coded peers a timestamp between 7 and 14 days ago
                    [_peers addObject:[[BRPeer alloc] initWithAddress:CFSwapInt32(address.intValue)
                                       port:BITCOIN_STANDARD_PORT timestamp:now - 24*60*60*(7 + drand48()*7)
                                       services:NODE_NETWORK]];
                }
            }
        }

        [self sortPeers];
        return _peers;
    }
}

- (NSMutableDictionary *)blocks
{
    if (_blocks.count > 0) return _blocks;

    [[BRMerkleBlockEntity context] performBlockAndWait:^{
        if (_blocks.count > 0) return;
        _blocks = [NSMutableDictionary dictionary];
        self.checkpoints = [NSMutableDictionary dictionary];

        _blocks[GENESIS_BLOCK_HASH] = GENESIS_BLOCK;

        // add checkpoints to the block collection
        for (int i = 0; i < sizeof(checkpoint_array)/sizeof(*checkpoint_array); i++) {
            NSData *hash = [NSString stringWithUTF8String:checkpoint_array[i].hash].hexToData.reverse;

            _blocks[hash] = [[BRMerkleBlock alloc] initWithBlockHash:hash version:1 prevBlock:nil merkleRoot:nil
                             timestamp:checkpoint_array[i].timestamp - NSTimeIntervalSince1970
                             target:checkpoint_array[i].target nonce:0 totalTransactions:0 hashes:nil flags:nil
                             height:checkpoint_array[i].height parentBlock:nil];
            assert([_blocks[hash] isValid]);
            self.checkpoints[@(checkpoint_array[i].height)] = hash;
        }

        for (BRMerkleBlockEntity *e in [BRMerkleBlockEntity allObjects]) {
            _blocks[e.blockHash] = [e merkleBlock];
        };
    }];

    return _blocks;
}

// this is used as part of a getblocks or getheaders request
- (NSArray *)blockLocatorArray
{
    // append 10 most recent block hashes, decending, then continue appending, doubling the step back each time,
    // finishing with the genisis block (top, -1, -2, -3, -4, -5, -6, -7, -8, -9, -11, -15, -23, -39, -71, -135, ..., 0)
    NSMutableArray *locators = [NSMutableArray array];
    int32_t step = 1, start = 0;
    BRMerkleBlock *b = self.lastBlock;

    while (b && b.height > 0) {
        [locators addObject:b.blockHash];
        if (++start >= 10) step *= 2;

        for (int32_t i = 0; b && i < step; i++) {
            b = self.blocks[b.prevBlock];
        }
    }

    [locators addObject:GENESIS_BLOCK_HASH];

    return locators;
}

- (BRMerkleBlock *)lastBlock
{
    if (_lastBlock) return _lastBlock;

    NSFetchRequest *req = [BRMerkleBlockEntity fetchRequest];

    req.sortDescriptors = @[[NSSortDescriptor sortDescriptorWithKey:@"height" ascending:NO]];
    req.predicate = [NSPredicate predicateWithFormat:@"height >= 0 && height != %d", BLOCK_UNKOWN_HEIGHT];
    req.fetchLimit = 1;
    _lastBlock = [[BRMerkleBlockEntity fetchObjects:req].lastObject merkleBlock];

    // if we don't have any blocks yet, use the latest checkpoint that is at least a week older than earliestKeyTime
    for (int i = sizeof(checkpoint_array)/sizeof(*checkpoint_array) - 1; ! _lastBlock && i >= 0; i--) {
        if (checkpoint_array[i].timestamp + 7*24*60*60 - NSTimeIntervalSince1970 >= self.earliestKeyTime) continue;
        _lastBlock = [[BRMerkleBlock alloc]
                      initWithBlockHash:[NSString stringWithUTF8String:checkpoint_array[i].hash].hexToData.reverse
                      version:1 prevBlock:nil merkleRoot:nil
                      timestamp:checkpoint_array[i].timestamp - NSTimeIntervalSince1970
                      target:checkpoint_array[i].target nonce:0 totalTransactions:0 hashes:nil flags:nil
                      height:checkpoint_array[i].height parentBlock:nil];
    }

    if (! _lastBlock) _lastBlock = GENESIS_BLOCK;

    return _lastBlock;
}

- (uint32_t)lastBlockHeight
{
    return self.lastBlock.height;
}

- (uint32_t)estimatedBlockHeight
{
    return (self.downloadPeer.lastblock > self.lastBlockHeight) ? self.downloadPeer.lastblock : self.lastBlockHeight;
}

- (double)syncProgress
{
    if (! self.downloadPeer) return (self.syncStartHeight == self.lastBlockHeight) ? 0.05 : 0.0;
    if (self.lastBlockHeight >= self.downloadPeer.lastblock) return 1.0;
    return 0.1 + 0.9*(self.lastBlockHeight - self.syncStartHeight)/(self.downloadPeer.lastblock - self.syncStartHeight);
}

// number of connected peers
- (NSUInteger)peerCount
{
    NSUInteger count = 0;

    for (BRPeer *peer in self.connectedPeers) {
        if (peer.status == BRPeerStatusConnected) count++;
    }

    return count;
}

- (BRBloomFilter *)bloomFilter
{
    if (_bloomFilter) return _bloomFilter;

    self.filterUpdateHeight = self.lastBlockHeight;
    self.filterFpRate = BLOOM_DEFAULT_FALSEPOSITIVE_RATE;

    if (self.lastBlockHeight + BLOCK_DIFFICULTY_INTERVAL < self.downloadPeer.lastblock) {
        self.filterFpRate = BLOOM_REDUCED_FALSEPOSITIVE_RATE; // lower false positive rate during chain sync
    }
    else if (self.lastBlockHeight < self.downloadPeer.lastblock) { // partially lower fp rate if we're nearly synced
        self.filterFpRate -= (BLOOM_DEFAULT_FALSEPOSITIVE_RATE - BLOOM_REDUCED_FALSEPOSITIVE_RATE)*
                             (self.downloadPeer.lastblock - self.lastBlockHeight)/BLOCK_DIFFICULTY_INTERVAL;
    }

    BRWallet *w = [[BRWalletManager sharedInstance] wallet];
    NSUInteger elemCount = w.addresses.count + w.unspentOutputs.count;
    BRBloomFilter *filter = [[BRBloomFilter alloc] initWithFalsePositiveRate:self.filterFpRate
                             forElementCount:(elemCount < 200) ? elemCount*1.5 : elemCount + 100
                             tweak:self.tweak flags:BLOOM_UPDATE_ALL];

    for (NSString *address in w.addresses) { // add addresses to watch for any tx receiveing money to the wallet
        NSData *hash = address.addressToHash160;

        if (hash && ! [filter containsData:hash]) [filter insertData:hash];
    }

    for (NSData *utxo in w.unspentOutputs) { // add unspent outputs to watch for any tx sending money from the wallet
        if (! [filter containsData:utxo]) [filter insertData:utxo];
    }

    _bloomFilter = filter;
    return _bloomFilter;
}

- (void)connect
{
    if (! [[BRWalletManager sharedInstance] wallet]) return; // check to make sure the wallet has been created
    if (self.connectFailures >= MAX_CONNECT_FAILURES) self.connectFailures = 0; // this attempt is a manual retry
    
    if (self.syncProgress < 1.0) {
        if (self.syncStartHeight == 0) self.syncStartHeight = self.lastBlockHeight;

        dispatch_async(dispatch_get_main_queue(), ^{
            [[NSNotificationCenter defaultCenter] postNotificationName:BRPeerManagerSyncStartedNotification object:nil];
        });
    }

    dispatch_async(self.q, ^{
        [self.connectedPeers minusSet:[self.connectedPeers objectsPassingTest:^BOOL(id obj, BOOL *stop) {
            return ([obj status] == BRPeerStatusDisconnected) ? YES : NO;
        }]];

        if (self.connectedPeers.count >= MAX_CONNECTIONS) return; // we're already connected to MAX_CONNECTIONS peers

        NSMutableOrderedSet *peers = [NSMutableOrderedSet orderedSetWithOrderedSet:self.peers];

        if (peers.count > 100) [peers removeObjectsInRange:NSMakeRange(100, peers.count - 100)];

        while (peers.count > 0 && self.connectedPeers.count < MAX_CONNECTIONS) {
            // pick a random peer biased towards peers with more recent timestamps
            BRPeer *p = peers[(NSUInteger)(pow(lrand48() % peers.count, 2)/peers.count)];

            if (p && ! [self.connectedPeers containsObject:p]) {
                [p setDelegate:self queue:self.q];
                p.earliestKeyTime = self.earliestKeyTime;
                [self.connectedPeers addObject:p];
                [p connect];
            }

            [peers removeObject:p];
        }

        if (self.connectedPeers.count == 0) {
            [self syncStopped];
            self.syncStartHeight = 0;

            dispatch_async(dispatch_get_main_queue(), ^{
                NSError *error = [NSError errorWithDomain:@"DoughWallet" code:1 userInfo:@{NSLocalizedDescriptionKey:
                                  NSLocalizedString(@"no peers found", nil)}];

                [[NSNotificationCenter defaultCenter] postNotificationName:BRPeerManagerSyncFailedNotification
                 object:nil userInfo:@{@"error":error}];
            });
        }
    });
}

// rescans blocks and transactions after earliestKeyTime, a new random download peer is also selected due to the
// possibility that a malicious node might lie by omitting transactions that match the bloom filter
- (void)rescan
{
    if (! self.connected) return;

    _lastBlock = nil;

    // start the chain download from the most recent checkpoint that's at least a week older than earliestKeyTime
    for (int i = sizeof(checkpoint_array)/sizeof(*checkpoint_array) - 1; ! _lastBlock && i >= 0; i--) {
        if (checkpoint_array[i].timestamp + 7*24*60*60 - NSTimeIntervalSince1970 >= self.earliestKeyTime) continue;
        self.lastBlock = self.blocks[[NSString stringWithUTF8String:checkpoint_array[i].hash].hexToData.reverse];
    }

    if (! _lastBlock) _lastBlock = self.blocks[GENESIS_BLOCK_HASH];

    if (self.downloadPeer) { // disconnect the current download peer so a new random one will be selected
        [self.peers removeObject:self.downloadPeer];
        [self.downloadPeer disconnect];
    }

    self.syncStartHeight = self.lastBlockHeight;
    [self connect];
}

- (void)publishTransaction:(BRTransaction *)transaction completion:(void (^)(NSError *error))completion
{
    if (! [transaction isSigned]) {
        if (completion) {
            completion([NSError errorWithDomain:@"DoughWallet" code:401 userInfo:@{NSLocalizedDescriptionKey:
                        NSLocalizedString(@"dogecoin transaction not signed", nil)}]);
        }
        return;
    }

    if (! self.connected) {
        if (completion) {
            completion([NSError errorWithDomain:@"DoughWallet" code:-1009 userInfo:@{NSLocalizedDescriptionKey:
                        NSLocalizedString(@"not connected to the dogecoin network", nil)}]);
        }
        return;
    }

    self.publishedTx[transaction.txHash] = transaction;
    if (completion) self.publishedCallback[transaction.txHash] = completion;

    NSMutableSet *peers = [NSMutableSet setWithSet:self.connectedPeers];

    // instead of publishing to all peers, leave out the download peer to see if the tx propogates and gets relayed back
    // TODO: XXXX connect to a random peer with an empty or fake bloom filter just for publishing
    if (self.peerCount > 1) [peers removeObject:self.downloadPeer];

    dispatch_async(dispatch_get_main_queue(), ^{
        [self performSelector:@selector(txTimeout:) withObject:transaction.txHash afterDelay:PROTOCOL_TIMEOUT];

        for (BRPeer *p in peers) {
            [p sendInvMessageWithTxHash:transaction.txHash];
        }
    });
}

// number of connected peers that have relayed the transaction
- (NSUInteger)relayCountForTransaction:(NSData *)txHash
{
    return [self.txRelays[txHash] count];
}

// seconds since reference date, 00:00:00 01/01/01 GMT
// NOTE: this is only accurate for the last two weeks worth of blocks, other timestamps are estimated from checkpoints
// BUG: this just doesn't work very well... we need to start storing tx metadata
- (NSTimeInterval)timestampForBlockHeight:(uint32_t)blockHeight
{
    if (blockHeight == TX_UNCONFIRMED) return [NSDate timeIntervalSinceReferenceDate] + 30; // average confirm time

    if (blockHeight > self.lastBlockHeight) { // future block, assume 1 minute per block after last block
        return self.lastBlock.timestamp + (blockHeight - self.lastBlockHeight)*1*60;
    }

    if (_blocks.count > 0) {
        if (blockHeight >= self.lastBlockHeight - BLOCK_DIFFICULTY_INTERVAL*2) { // recent block we have the header for
            BRMerkleBlock *block = self.lastBlock;

            while (block && block.height > blockHeight) {
                block = self.blocks[block.prevBlock];
            }

            if (block) return block.timestamp;
        }
    }
    else [[BRMerkleBlockEntity context] performBlock:^{ [self blocks]; }];

    uint32_t h = self.lastBlockHeight;
    NSTimeInterval t = self.lastBlock.timestamp + NSTimeIntervalSince1970;

    for (int i = sizeof(checkpoint_array)/sizeof(*checkpoint_array) - 1; i >= 0; i--) { // estimate from checkpoints
        if (checkpoint_array[i].height <= blockHeight) {
            t = checkpoint_array[i].timestamp + (t - checkpoint_array[i].timestamp)*
                (blockHeight - checkpoint_array[i].height)/(h - checkpoint_array[i].height);
            return t - NSTimeIntervalSince1970;
        }

        h = checkpoint_array[i].height;
        t = checkpoint_array[i].timestamp;
    }

    return GENESIS_BLOCK.timestamp + ((t - NSTimeIntervalSince1970) - GENESIS_BLOCK.timestamp)*blockHeight/h;
}

- (void)setBlockHeight:(int32_t)height forTxHashes:(NSArray *)txHashes
{
    [[[BRWalletManager sharedInstance] wallet] setBlockHeight:height forTxHashes:txHashes];
    
    if (height != TX_UNCONFIRMED) { // remove confirmed tx from publish list and relay counts
        [self.publishedTx removeObjectsForKeys:txHashes];
        [self.publishedCallback removeObjectsForKeys:txHashes];
        [self.txRejections removeObjectsForKeys:txHashes];
        [self.txRelays removeObjectsForKeys:txHashes];
    }
}

- (void)txTimeout:(NSData *)txHash
{
    void (^callback)(NSError *error) = self.publishedCallback[txHash];

    [self.publishedTx removeObjectForKey:txHash];
    [self.publishedCallback removeObjectForKey:txHash];
    [NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(txTimeout:) object:txHash];

    if (callback) {
        callback([NSError errorWithDomain:@"DoughWallet" code:BITCOIN_TIMEOUT_CODE userInfo:@{NSLocalizedDescriptionKey:
                  NSLocalizedString(@"transaction canceled, network timeout", nil)}]);
    }
}

- (void)syncTimeout
{
    //BUG: XXXX sync can stall if download peer continues to relay tx but not blocks
    NSTimeInterval now = [NSDate timeIntervalSinceReferenceDate];

    if (now - self.lastRelayTime < PROTOCOL_TIMEOUT) { // the download peer relayed something in time, so restart timer
        [NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(syncTimeout) object:nil];
        [self performSelector:@selector(syncTimeout) withObject:nil
         afterDelay:PROTOCOL_TIMEOUT - (now - self.lastRelayTime)];
        return;
    }

    NSLog(@"%@:%d chain sync timed out", self.downloadPeer.host, self.downloadPeer.port);

    [self.peers removeObject:self.downloadPeer];
    [self.downloadPeer disconnect];
}

- (void)syncStopped
{
    if ([[UIApplication sharedApplication] applicationState] == UIApplicationStateBackground) {
        [self.connectedPeers makeObjectsPerformSelector:@selector(disconnect)];
        [self.connectedPeers removeAllObjects];
    }

    if (self.taskId != UIBackgroundTaskInvalid) {
        [[UIApplication sharedApplication] endBackgroundTask:self.taskId];
        self.taskId = UIBackgroundTaskInvalid;
        
        for (BRPeer *p in self.connectedPeers) { // after syncing, load filters and get mempools from the other peers
            if (p != self.downloadPeer) [p sendFilterloadMessage:self.bloomFilter.data];
            [p sendMempoolMessage];
            
            //BUG: XXXX sometimes a peer relays thousands of transactions after mempool msg, should detect and
            // disconnect if it's more than BLOOM_DEFAULT_FALSEPOSITIVE_RATE*10*<typical mempool size>*2
        }
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        [NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(syncTimeout) object:nil];
    });
}

// unconfirmed transactions that aren't in the mempools of any of connected peers have likely dropped off the network
- (void)removeUnrelayedTransactions
{
    BRWalletManager *m = [BRWalletManager sharedInstance];

    for (BRTransaction *tx in m.wallet.recentTransactions) {
        if (tx.blockHeight != TX_UNCONFIRMED) break;
        if ([self.txRelays[tx.txHash] count] == 0) [m.wallet removeTransaction:tx.txHash];
    }
}

- (void)peerMisbehavin:(BRPeer *)peer
{
    peer.misbehavin++;
    [self.peers removeObject:peer];
    [self.misbehavinPeers addObject:peer];
    [peer disconnect];
    [self connect];
}

- (void)sortPeers
{
//    [_peers sortUsingComparator:^NSComparisonResult(id obj1, id obj2) {
//        if ([obj1 timestamp] > [obj2 timestamp]) return NSOrderedAscending;
//        if ([obj1 timestamp] < [obj2 timestamp]) return NSOrderedDescending;
//        return NSOrderedSame;
//    }];
}

- (void)savePeers
{
    NSMutableSet *peers = [[self.peers.set setByAddingObjectsFromSet:self.misbehavinPeers] mutableCopy];
    NSMutableSet *addrs = [NSMutableSet set];

    for (BRPeer *p in peers) {
        [addrs addObject:@((int32_t)p.address)];
    }

    [[BRPeerEntity context] performBlock:^{
        [BRPeerEntity deleteObjects:[BRPeerEntity objectsMatching:@"! (address in %@)", addrs]]; // remove deleted peers

        for (BRPeerEntity *e in [BRPeerEntity objectsMatching:@"address in %@", addrs]) { // update existing peers
            BRPeer *p = [peers member:[e peer]];

            if (p) {
                e.timestamp = p.timestamp;
                e.services = p.services;
                e.misbehavin = p.misbehavin;
                [peers removeObject:p];
            }
            else [e deleteObject];
        }

        for (BRPeer *p in peers) { // add new peers
            [[BRPeerEntity managedObject] setAttributesFromPeer:p];
        }
    }];
}

- (void)saveBlocks
{
    NSMutableSet *blockHashes = [NSMutableSet set];
    BRMerkleBlock *b = self.lastBlock;

    while (b) {
        [blockHashes addObject:b.blockHash];
        b = self.blocks[b.prevBlock];
    }

    [[BRMerkleBlockEntity context] performBlock:^{
        [BRMerkleBlockEntity deleteObjects:[BRMerkleBlockEntity objectsMatching:@"! (blockHash in %@)", blockHashes]];

        for (BRMerkleBlockEntity *e in [BRMerkleBlockEntity objectsMatching:@"blockHash in %@", blockHashes]) {
            [e setAttributesFromBlock:self.blocks[e.blockHash]];
            [blockHashes removeObject:e.blockHash];
        }

        for (NSData *hash in blockHashes) {
            [[BRMerkleBlockEntity managedObject] setAttributesFromBlock:self.blocks[hash]];
        }
    }];
}

#pragma mark - BRPeerDelegate

- (void)peerConnected:(BRPeer *)peer
{
    NSLog(@"%@:%d connected with lastblock %d", peer.host, peer.port, peer.lastblock);

    self.connectFailures = 0;
    peer.timestamp = [NSDate timeIntervalSinceReferenceDate]; // set last seen timestamp for peer

    if (peer.lastblock + 10 < self.lastBlock.height) { // drop peers that aren't synced yet, we can't help them
        [peer disconnect];
        return;
    }

    if (self.connected && (self.downloadPeer.lastblock >= peer.lastblock || self.lastBlock.height >= peer.lastblock)) {
        if (self.lastBlock.height < self.downloadPeer.lastblock) return; // don't load bloom filter yet if we're syncing
        [peer sendFilterloadMessage:self.bloomFilter.data];
        [peer sendMempoolMessage];
        return; // we're already connected to a download peer
    }

    // select the peer with the lowest ping time to download the chain from if we're behind
    // BUG: XXXX a malicious peer can report a higher lastblock to make us select them as the download peer, if two
    // peers agree on lastblock, use one of them instead
    for (BRPeer *p in self.connectedPeers) {
        if ((p.pingTime < peer.pingTime && p.lastblock >= peer.lastblock) || p.lastblock > peer.lastblock) peer = p;
    }

    [self.downloadPeer disconnect];
    self.downloadPeer = peer;
    _connected = YES;

    // every time a new wallet address is added, the bloom filter has to be rebuilt, and each address is only used for
    // one transaction, so here we generate some spare addresses to avoid rebuilding the filter each time a wallet
    // transaction is encountered during the blockchain download (generates twice the external gap limit for both
    // address chains)
    [[[BRWalletManager sharedInstance] wallet] addressesWithGapLimit:SEQUENCE_GAP_LIMIT_EXTERNAL*2 internal:NO];
    [[[BRWalletManager sharedInstance] wallet] addressesWithGapLimit:SEQUENCE_GAP_LIMIT_EXTERNAL*2 internal:YES];

    _bloomFilter = nil; // make sure the bloom filter is updated with any newly generated addresses
    [peer sendFilterloadMessage:self.bloomFilter.data];

    if (self.taskId == UIBackgroundTaskInvalid) { // start a background task for the chain sync
        self.taskId = [[UIApplication sharedApplication] beginBackgroundTaskWithExpirationHandler:^{}];
    }
    
    if (self.lastBlock.height < peer.lastblock) { // start blockchain sync
        self.lastRelayTime = 0;

        dispatch_async(dispatch_get_main_queue(), ^{ // setup a timer to detect if the sync stalls
            [NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(syncTimeout) object:nil];
            [self performSelector:@selector(syncTimeout) withObject:nil afterDelay:PROTOCOL_TIMEOUT];

            dispatch_async(self.q, ^{
                // request just block headers up to a week before earliestKeyTime, and then merkleblocks after that
                if (self.lastBlock.timestamp + 7*24*60*60 >= self.earliestKeyTime) {
                    [peer sendGetblocksMessageWithLocators:[self blockLocatorArray] andHashStop:nil];
                }
                else [peer sendGetheadersMessageWithLocators:[self blockLocatorArray] andHashStop:nil];
            });
        });
    }
    else { // we're already synced
        [self syncStopped];
        [peer sendGetaddrMessage]; // request a list of other bitcoin peers
        self.syncStartHeight = 0;

        dispatch_async(dispatch_get_main_queue(), ^{
            [[NSNotificationCenter defaultCenter] postNotificationName:BRPeerManagerSyncFinishedNotification
             object:nil];
        });
    }
}

- (void)peer:(BRPeer *)peer disconnectedWithError:(NSError *)error
{
    NSLog(@"%@:%d disconnected%@%@", peer.host, peer.port, error ? @", " : @"", error ? error : @"");
    
    if ([error.domain isEqual:@"DoughWallet"] && error.code != BITCOIN_TIMEOUT_CODE) {
        [self peerMisbehavin:peer]; // if it's protocol error other than timeout, the peer isn't following the rules
    }
    else if (error) { // timeout or some non-protocol related network error
        [self.peers removeObject:peer];
        self.connectFailures++;
    }

    for (NSData *txHash in self.txRelays.allKeys) {
        [self.txRelays[txHash] removeObject:peer];
        [self.txRejections[txHash] removeObject:peer];
    }

    if ([self.downloadPeer isEqual:peer]) { // download peer disconnected
        _connected = NO;
        self.downloadPeer = nil;
        [self syncStopped];
        if (self.connectFailures > MAX_CONNECT_FAILURES) self.connectFailures = MAX_CONNECT_FAILURES;
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        if (! self.connected && self.connectFailures == MAX_CONNECT_FAILURES) {
            self.syncStartHeight = 0;
        
            // clear out stored peers so we get a fresh list from DNS on next connect attempt
            [self.connectedPeers removeAllObjects];
            [self.misbehavinPeers removeAllObjects];
            [BRPeerEntity deleteObjects:[BRPeerEntity allObjects]];
            _peers = nil;

            [[NSNotificationCenter defaultCenter] postNotificationName:BRPeerManagerSyncFailedNotification
             object:nil userInfo:error ? @{@"error":error} : nil];
        }
        else if (self.connectFailures < MAX_CONNECT_FAILURES) [self connect]; // try connecting to another peer
        
        [[NSNotificationCenter defaultCenter] postNotificationName:BRPeerManagerTxStatusNotification object:nil];
    });
}

- (void)peer:(BRPeer *)peer relayedPeers:(NSArray *)peers
{
    NSLog(@"%@:%d relayed %d peer(s)", peer.host, peer.port, (int)peers.count);
    if (peer == self.downloadPeer) self.lastRelayTime = [NSDate timeIntervalSinceReferenceDate];
    [self.peers addObjectsFromArray:peers];
    [self.peers minusSet:self.misbehavinPeers];
    [self sortPeers];

    // limit total to 2500 peers
    if (self.peers.count > 2500) [self.peers removeObjectsInRange:NSMakeRange(2500, self.peers.count - 2500)];

    NSTimeInterval t = [NSDate timeIntervalSinceReferenceDate] - 3*60*60;

    // remove peers more than 3 hours old, or until there are only 1000 left
//    while (self.peers.count > 1000 && [self.peers.lastObject timestamp] < t) {
//        [self.peers removeObject:self.peers.lastObject];
//    }

    if (peers.count > 1 && peers.count < 1000) { // peer relaying is complete when we receive fewer than 1000
        // this is a good time to remove unconfirmed tx that dropped off the network
        if (self.peerCount == MAX_CONNECTIONS && self.lastBlockHeight >= self.downloadPeer.lastblock) {
            [self removeUnrelayedTransactions];
        }

        [self savePeers];
        [BRPeerEntity saveContext];
    }
}

- (void)peer:(BRPeer *)peer relayedTransaction:(BRTransaction *)transaction
{
    BRWallet *w = [[BRWalletManager sharedInstance] wallet];

    NSLog(@"%@:%d relayed transaction %@", peer.host, peer.port, transaction.txHash);
    if (peer == self.downloadPeer) self.lastRelayTime = [NSDate timeIntervalSinceReferenceDate];

    if ([w registerTransaction:transaction]) {
        self.publishedTx[transaction.txHash] = transaction;

        // keep track of how many peers relay a tx, this indicates how likely it is to be confirmed in future blocks
        if (! self.txRelays[transaction.txHash]) self.txRelays[transaction.txHash] = [NSMutableSet set];

        if (! [self.txRelays[transaction.txHash] containsObject:peer]) {
            [self.txRelays[transaction.txHash] addObject:peer];
        
            dispatch_async(dispatch_get_main_queue(), ^{
                [[NSNotificationCenter defaultCenter] postNotificationName:BRPeerManagerTxStatusNotification
                 object:nil];
            });
        }

        // the transaction likely consumed one or more wallet addresses, so check that at least the next <gap limit>
        // unused addresses are still matched by the bloom filter
        NSArray *external = [w addressesWithGapLimit:SEQUENCE_GAP_LIMIT_EXTERNAL internal:NO],
                *internal = [w addressesWithGapLimit:SEQUENCE_GAP_LIMIT_INTERNAL internal:YES];

        for (NSString *address in [external arrayByAddingObjectsFromArray:internal]) {
            NSData *hash = address.addressToHash160;

            if (! hash || [self.bloomFilter containsData:hash]) continue;

            // generate additional addresses so we don't have to update the filter after each new transaction
            [w addressesWithGapLimit:SEQUENCE_GAP_LIMIT_EXTERNAL*2 internal:NO];
            [w addressesWithGapLimit:SEQUENCE_GAP_LIMIT_EXTERNAL*2 internal:YES];

            _bloomFilter = nil; // reset the filter so a new one will be created with the new wallet addresses

            if (self.lastBlockHeight >= self.downloadPeer.lastblock) { // if we're syncing, only update download peer
                for (BRPeer *p in self.connectedPeers) {
                    [p sendFilterloadMessage:self.bloomFilter.data];
                }
            }
            else [self.downloadPeer sendFilterloadMessage:self.bloomFilter.data];

            // after adding addresses to the filter, re-request upcoming blocks that were requested using the old filter
            [self.downloadPeer rereqeustBlocksFrom:self.lastBlock.blockHash];
            break;
        }
    }
}

- (void)peer:(BRPeer *)peer rejectedTransaction:(NSData *)txHash withCode:(uint8_t)code
{
    if ([self.txRelays[txHash] containsObject:peer]) {
        [self.txRelays[txHash] removeObject:peer];

        dispatch_async(dispatch_get_main_queue(), ^{
            [[NSNotificationCenter defaultCenter] postNotificationName:BRPeerManagerTxStatusNotification object:nil];
        });
    }

    // keep track of possible double spend rejections and notify the user to do a rescan
    // NOTE: lots of checks here to make sure a malicious node can't annoy the user with rescan alerts
    if (code == 0x10 && self.publishedTx[txHash] != nil && ! [self.txRejections[txHash] containsObject:peer] &&
        [self.connectedPeers containsObject:peer]) {
        if (! self.txRejections[txHash]) self.txRejections[txHash] = [NSMutableSet set];
        [self.txRejections[txHash] addObject:peer];

        if ([self.txRejections[txHash] count] > 1 || self.peerCount < 3) {
            [[[UIAlertView alloc] initWithTitle:NSLocalizedString(@"transaction rejected", nil)
              message:NSLocalizedString(@"Your wallet may be out of sync.\n"
                                        "This can often be fixed by rescaning the blockchain.", nil) delegate:self
              cancelButtonTitle:NSLocalizedString(@"cancel", nil)
              otherButtonTitles:NSLocalizedString(@"rescan", nil), nil] show];
        }
    }
}

- (void)peer:(BRPeer *)peer relayedBlock:(BRMerkleBlock *)block
{
    if (peer == self.downloadPeer) self.lastRelayTime = [NSDate timeIntervalSinceReferenceDate];

    // ignore block headers that are newer than one week before earliestKeyTime (headers have 0 totalTransactions)
    if (block.totalTransactions == 0 && block.timestamp + 7*24*60*60 > self.earliestKeyTime) return;

    // track the observed bloom filter false positive rate using a low pass filter to smooth out variance
    if (peer == self.downloadPeer && block.totalTransactions > 0) {
        // 1% low pass filter, also weights each block by total transactions, using 400 tx per block as typical
        self.filterFpRate = self.filterFpRate*(1.0 - 0.01*block.totalTransactions/400) + 0.01*block.txHashes.count/400;

        if (self.filterFpRate > BLOOM_DEFAULT_FALSEPOSITIVE_RATE*10.0) { // false positive rate sanity check
            NSLog(@"%@:%d bloom filter false positive rate too high after %d blocks, disconnecting...", peer.host,
                  peer.port, self.lastBlockHeight - self.filterUpdateHeight);
            [self.downloadPeer disconnect];
        }
    }

    BRMerkleBlock *prev = self.blocks[block.prevBlock];
    NSTimeInterval transitionTime = 0;

    if (! prev) { // block is an orphan
        NSLog(@"%@:%d relayed orphan block %@, previous %@, last block is %@, height %d", peer.host, peer.port,
              block.blockHash, block.prevBlock, self.lastBlock.blockHash, self.lastBlock.height);

        // ignore orphans older than one week ago
        if (block.timestamp < [NSDate timeIntervalSinceReferenceDate] - 7*24*60*60) return;

        // call getblocks, unless we already did with the previous block, or we're still downloading the chain
        if (self.lastBlock.height >= peer.lastblock && ! [self.lastOrphan.blockHash isEqual:block.prevBlock]) {
            NSLog(@"%@:%d calling getblocks", peer.host, peer.port);
            [peer sendGetblocksMessageWithLocators:[self blockLocatorArray] andHashStop:nil];
        }

        self.orphans[block.prevBlock] = block; // orphans are indexed by previous block rather than their own hash
        self.lastOrphan = block;
        return;
    }

    block.height = prev.height + 1;

    if ((block.height % BLOCK_DIFFICULTY_INTERVAL) == 0) { // hit a difficulty transition, find previous transition time
        BRMerkleBlock *b = block;

        for (uint32_t i = 0; b && i < BLOCK_DIFFICULTY_INTERVAL; i++) {
            b = self.blocks[b.prevBlock];
        }

        transitionTime = b.timestamp;

        while (b) { // free up some memory
            b = self.blocks[b.prevBlock];
            if (b) [self.blocks removeObjectForKey:b.blockHash];
        }
    }

    // verify block difficulty
    if (! [block verifyDifficultyFromPreviousBlock:prev andTransitionTime:transitionTime andStoredBlocks:self.blocks]) {
        NSLog(@"%@:%d relayed block with invalid difficulty target %x, blockHash: %@", peer.host, peer.port,
              block.target, block.blockHash);
        [self peerMisbehavin:peer];
        return;
    }

    // verify block chain checkpoints
    if (self.checkpoints[@(block.height)] && ! [block.blockHash isEqual:self.checkpoints[@(block.height)]]) {
        NSLog(@"%@:%d relayed a block that differs from the checkpoint at height %d, blockHash: %@, expected: %@",
              peer.host, peer.port, block.height, block.blockHash, self.checkpoints[@(block.height)]);
        [self peerMisbehavin:peer];
        return;
    }

    if ([block.prevBlock isEqual:self.lastBlock.blockHash]) { // new block extends main chain
        if ((block.height % 500) == 0 || block.txHashes.count > 0 || block.height > peer.lastblock) {
            NSLog(@"adding block at height: %d, false positive rate: %f", block.height, self.filterFpRate);
        }

        self.blocks[block.blockHash] = block;
        self.lastBlock = block;
        [self setBlockHeight:block.height forTxHashes:block.txHashes];
    }
    else if (self.blocks[block.blockHash] != nil) { // we already have the block (or at least the header)
        if ((block.height % 500) == 0 || block.txHashes.count > 0 || block.height > peer.lastblock) {
            NSLog(@"%@:%d relayed existing block at height %d", peer.host, peer.port, block.height);
        }

        self.blocks[block.blockHash] = block;

        BRMerkleBlock *b = self.lastBlock;

        while (b && b.height > block.height) { // check if block is in main chain
            b = self.blocks[b.prevBlock];
        }

        if ([b.blockHash isEqual:block.blockHash]) { // if it's not on a fork, set block heights for its transactions
            [self setBlockHeight:block.height forTxHashes:block.txHashes];
            if (block.height == self.lastBlock.height) self.lastBlock = block;
        }
    }
    else { // new block is on a fork
        if (block.height <= BITCOIN_REFERENCE_BLOCK_HEIGHT) { // fork is older than the most recent checkpoint
            NSLog(@"ignoring block on fork older than most recent checkpoint, fork height: %d, blockHash: %@",
                  block.height, block.blockHash);
            return;
        }

        // special case, if a new block is mined while we're rescaning the chain, mark as orphan til we're caught up
        if (self.lastBlock.height < peer.lastblock && block.height > self.lastBlock.height + 1) {
            NSLog(@"marking new block at height %d as orphan until rescan completes", block.height);
            self.orphans[block.prevBlock] = block;
            self.lastOrphan = block;
            return;
        }

        NSLog(@"chain fork to height %d", block.height);
        self.blocks[block.blockHash] = block;
        if (block.height <= self.lastBlock.height) return; // if fork is shorter than main chain, ingore it for now

        NSMutableArray *txHashes = [NSMutableArray array];
        BRMerkleBlock *b = block, *b2 = self.lastBlock;

        while (b && b2 && ! [b.blockHash isEqual:b2.blockHash]) { // walk back to where the fork joins the main chain
            b = self.blocks[b.prevBlock];
            if (b.height < b2.height) b2 = self.blocks[b2.prevBlock];
        }

        NSLog(@"reorganizing chain from height %d, new height is %d", b.height, block.height);

        // mark transactions after the join point as unconfirmed
        for (BRTransaction *tx in [[[BRWalletManager sharedInstance] wallet] recentTransactions]) {
            if (tx.blockHeight <= b.height) break;
            [txHashes addObject:tx.txHash];
        }

        [self setBlockHeight:TX_UNCONFIRMED forTxHashes:txHashes];
        b = block;

        while (b.height > b2.height) { // set transaction heights for new main chain
            [self setBlockHeight:b.height forTxHashes:b.txHashes];
            b = self.blocks[b.prevBlock];
        }

        self.lastBlock = block;
    }

    if (block.height == peer.lastblock && block == self.lastBlock) { // chain download is complete
        [self saveBlocks];
        [BRMerkleBlockEntity saveContext];
        [self syncStopped];
        [peer sendGetaddrMessage]; // request a list of other bitcoin peers
        self.syncStartHeight = 0;

        dispatch_async(dispatch_get_main_queue(), ^{
            [[NSNotificationCenter defaultCenter] postNotificationName:BRPeerManagerSyncFinishedNotification
             object:nil];
        });
    }

    if (block == self.lastBlock && self.orphans[block.blockHash]) { // check if the next block was received as an orphan
        BRMerkleBlock *b = self.orphans[block.blockHash];

        [self.orphans removeObjectForKey:block.blockHash];
        [self peer:peer relayedBlock:b];
    }

    if (block.height > peer.lastblock) { // notify that transaction confirmations may have changed
        dispatch_async(dispatch_get_main_queue(), ^{
            [[NSNotificationCenter defaultCenter] postNotificationName:BRPeerManagerTxStatusNotification object:nil];
        });
    }
}

- (BRTransaction *)peer:(BRPeer *)peer requestedTransaction:(NSData *)txHash
{
    BRTransaction *tx = self.publishedTx[txHash];
    void (^callback)(NSError *error) = self.publishedCallback[txHash];
    
    if (tx) {
        [[[BRWalletManager sharedInstance] wallet] registerTransaction:tx];

        if (! self.txRelays[txHash]) self.txRelays[txHash] = [NSMutableSet set];
        [self.txRelays[txHash] addObject:peer];

        dispatch_async(dispatch_get_main_queue(), ^{
            [[NSNotificationCenter defaultCenter] postNotificationName:BRPeerManagerTxStatusNotification object:nil];
        });

        [self.publishedCallback removeObjectForKey:txHash];

        dispatch_async(dispatch_get_main_queue(), ^{
            [NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(txTimeout:) object:txHash];
            if (callback) callback(nil);
        });
    }

    return tx;
}

- (NSData *)peerBloomFilter:(BRPeer *)peer
{
    self.filterFpRate = self.bloomFilter.falsePositiveRate;
    self.filterUpdateHeight = self.lastBlockHeight;
    return self.bloomFilter.data;
}

#pragma mark - UIAlertViewDelegate

- (void)alertView:(UIAlertView *)alertView clickedButtonAtIndex:(NSInteger)buttonIndex
{
    if (buttonIndex == alertView.cancelButtonIndex) return;
    [self rescan];
}

@end
