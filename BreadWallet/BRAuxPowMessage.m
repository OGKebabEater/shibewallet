//
//  BRAuxPowMessage.h
//  BreadWallet
//
//  Created by Filip Noetzel on 06/11/14.
//  Copyright (c) 2014 Aaron Voisine. All rights reserved.
//

#import <Foundation/Foundation.h>

#import "BRAuxPowMessage.h"
#import "NSData+Bitcoin.h"
#import "NSMutableData+Bitcoin.h"
#import <CommonCrypto/CommonDigest.h>

@implementation BRAuxPowMessage



// message can be either a merkleblock or header message
+ (instancetype)blockWithMessage:(NSData *)message
{
    return [[self alloc] initWithMessage:message];
}

void advance_offset(NSString *label, NSData *message, NSUInteger* off, NSUInteger size)
{
    *off += size;
}

- (instancetype)initWithMessage:(NSData *)message
{
    if (! (self = [self init])) return nil;

    if (message.length < 80) return nil;

    NSUInteger off = 0, l = 0, len = 0;

    //         header.parentCoinbaseVerion = readUint32();
    _parentCoinbaseVersion = [message UInt32AtOffset:off];
    advance_offset(@"_parentCoinbaseVersion", message, &off, sizeof(uint32_t));

    //        header.parentCoinbaseTxInCount = readVarInt();
    _parentCoinbaseTxInCount = [message varIntAtOffset:off length:&l];
    advance_offset(@"_parentCoinbaseTxInCount", message, &off, l);

    //        header.parentCointbasePrevOut = readBytes(36); // Always the same on coinbase
    _parentCointbasePrevOut = [message subdataWithRange:NSMakeRange(off, 36)];
    advance_offset(@"_parentCointbasePrevOut", message, &off, 36);

    //        header.parentCoinbaseInScriptLength  = readVarInt();
    //        header.parentCoinbaseInScript = readBytes((int) header.parentCoinbaseInScriptLength); // Script length is limited so this cast should be fine.
    _parentCoinbaseInScript = [message dataAtOffset:off length:&l];
    advance_offset(@"_parentCoinbaseInScript", message, &off, l);

    //        header.parentCoinBaseSequenceNumber = readUint32();
    _parentCoinBaseSequenceNumber = [message UInt32AtOffset:off];
    advance_offset(@"_parentCoinBaseSequenceNumber", message, &off, sizeof(uint32_t));

    //        header.parentCoinbaseTxOutCount = readVarInt();
    _parentCoinbaseTxOutCount = [message varIntAtOffset:off length:&l];
    advance_offset(@"_parentCoinbaseOutCount", message, &off, l);

    //        header.parentCoinbaseOuts = new ArrayList<AuxCoinbaseOut>();
    int ll = 0;
    NSUInteger scriptlength;

    //        for (int i = 0; i < header.parentCoinbaseTxOutCount; i++) {
    for (uint64_t i = 0; i < _parentCoinbaseTxOutCount; i++) {
        //            AuxCoinbaseOut out = new AuxCoinbaseOut();
        //            out.amount = readInt64();
        ll += sizeof(uint64_t);
        //            out.scriptLength = readVarInt();
        scriptlength = [message varIntAtOffset:(off+ll) length:&l];
        //            out.script = readBytes((int) out.scriptLength); // Script length is limited so this cast should be fine.
        ll += l;
        //            header.parentCoinbaseOuts.add(out);
        ll += scriptlength;
    }

    _parentCoinbaseOuts = [message subdataWithRange:NSMakeRange(off, ll)];
    advance_offset(@"_parentCoinbaseOuts", message, &off, ll);

    //        header.parentCoinbaseLockTime = readUint32();
    _parentCoinbaseLockTime = [message UInt32AtOffset:off];
    advance_offset(@"_parentCoinbaseLockTime", message, &off, sizeof(uint32_t));

    //        header.parentBlockHeaderHash = readHash();
    _parentBlockHeaderHash = [message hashAtOffset:off];
    advance_offset(@"_parentBlockHeaderHash", message, &off, CC_SHA256_DIGEST_LENGTH);

    //        header.numOfCoinbaseLinks = readVarInt();
    _numOfCoinbaseLinks = (NSUInteger)[message varIntAtOffset:off length:&l];
    advance_offset(@"_numOfCoinbaseLinks", message, &off, l);

    //        header.coinbaseLinks = new ArrayList<Sha256Hash>();
    //        for (int i = 0; i < header.numOfCoinbaseLinks; i++) {
    //            header.coinbaseLinks.add(readHash());
    //        }
    len = _numOfCoinbaseLinks*CC_SHA256_DIGEST_LENGTH;

    _coinbaseLinks = [message subdataWithRange:NSMakeRange(off, len)];
    advance_offset(@"_coinbaseLinks", message, &off, len);

    //        header.coinbaseBranchBitmask = readUint32();
    _coinbaseBranchBitmask = [message UInt32AtOffset:off];
    off += sizeof(uint32_t);

    //        header.numOfAuxChainLinks = readVarInt();
    _numOfAuxChainLinks = (NSUInteger)[message varIntAtOffset:off length:&l];
    off += l;

    //        header.auxChainLinks = new ArrayList<Sha256Hash>();
    //        for (int i = 0; i < header.numOfAuxChainLinks; i++) {
    //            header.auxChainLinks.add(readHash());
    //        }
    len = _numOfAuxChainLinks*CC_SHA256_DIGEST_LENGTH;

    _auxChainLinks = [message subdataWithRange:NSMakeRange(off, len)];
    off += len;

    //        header.auxChainBranchBitmask = readUint32();
    _auxChainBranchBitmask = [message UInt32AtOffset:off];
    advance_offset(@"_auxChainBranchBitmask", message, &off, sizeof(uint32_t));

    //        header.parentBlockVersion = readUint32();
    _parentBlockVersion = [message UInt32AtOffset:off];
    advance_offset(@"_parentBlockVersion", message, &off, sizeof(uint32_t));

    //        header.parentBlockPrev = readHash();
    _parentBlockPrev = [message hashAtOffset:off];
    advance_offset(@"_parentBlockPrev", message, &off, CC_SHA256_DIGEST_LENGTH);

    //        header.parentBlockMerkleRoot = readHash();
    _parentBlockMerkleRoot = [message hashAtOffset:off];
    advance_offset(@"_parentBlockMerkleRoot", message, &off, CC_SHA256_DIGEST_LENGTH);

    //        header.parentBlockTime = readUint32();
    _parentBlockTime = [message UInt32AtOffset:off] - NSTimeIntervalSince1970;
    advance_offset(@"_parentBlockTime", message, &off, sizeof(uint32_t));


    //        header.parentBlockBits = readUint32();
    _parentBlockBits = [message UInt32AtOffset:off];
    advance_offset(@"_parentBlockBits", message, &off, sizeof(uint32_t));

    //        header.parentBlockNonce = readUint32();
    _parentBlockNonce = [message UInt32AtOffset:off];
    advance_offset(@"_parentBlockNonce", message, &off, sizeof(uint32_t));

    _length = off;

    return self;
}


- (NSData *)constructParentHeader
{
    NSMutableData *d = [NSMutableData data];

    [d appendUInt32:_parentBlockVersion];
    [d appendData:_parentBlockPrev];
    [d appendData:_parentBlockMerkleRoot];
    [d appendUInt32:_parentBlockTime + NSTimeIntervalSince1970];
    [d appendUInt32:_parentBlockBits];
    [d appendUInt32:_parentBlockNonce];

    return d;
}



@end
