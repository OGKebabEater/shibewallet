//
//  BRAuxPowMessage.h
//  BreadWallet
//
//  Created by Filip Noetzel on 06/11/14.
//  Copyright (c) 2014 Aaron Voisine. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface BRAuxPowMessage : NSObject

+ (instancetype)blockWithMessage:(NSData *)message;
- (instancetype)initWithMessage:(NSData *)message;

- (NSData *)constructParentHeader;

@property (nonatomic, readonly) NSUInteger length;

// // Parent coinbase
// public long parentCoinbaseVerion;
@property (nonatomic, readonly) uint32_t parentCoinbaseVersion;

// public long parentCoinbaseTxInCount;
@property (nonatomic, readonly) uint64_t parentCoinbaseTxInCount;

// public byte[] parentCointbasePrevOut;
@property (nonatomic, readonly) NSData *parentCointbasePrevOut;

// public long parentCoinbaseInScriptLength;
@property (nonatomic, readonly) uint64_t parentCoinbaseInScriptLength;

// public byte[] parentCoinbaseInScript;
@property (nonatomic, readonly) NSData *parentCoinbaseInScript;

// public long parentCoinBaseSequenceNumber;
@property (nonatomic, readonly) uint64_t parentCoinBaseSequenceNumber;

// public long parentCoinbaseTxOutCount;
@property (nonatomic, readonly) uint64_t parentCoinbaseTxOutCount;

// public ArrayList<AuxCoinbaseOut> parentCoinbaseOuts;
@property (nonatomic, readonly) NSData *parentCoinbaseOuts;

// public long parentCoinbaseLockTime;
@property (nonatomic, readonly) uint32_t parentCoinbaseLockTime;

// // Coinbase link
// public Sha256Hash parentBlockHeaderHash;
@property (nonatomic, readonly) NSData *parentBlockHeaderHash;

// public long numOfCoinbaseLinks;
@property (nonatomic, readonly) uint64_t numOfCoinbaseLinks;

// public ArrayList<Sha256Hash> coinbaseLinks;
@property (nonatomic, readonly) NSData *coinbaseLinks;

// public long coinbaseBranchBitmask;
@property (nonatomic, readonly) uint32_t coinbaseBranchBitmask;

//
// // Aux chanin link
// public long numOfAuxChainLinks;
@property (nonatomic, readonly) uint64_t numOfAuxChainLinks;

// public ArrayList<Sha256Hash> auxChainLinks;
@property (nonatomic, readonly) NSData *auxChainLinks;

// public long auxChainBranchBitmask;
@property (nonatomic, readonly) uint32_t auxChainBranchBitmask;

//
// // Parent block header
// public long parentBlockVersion;
@property (nonatomic, readonly) uint32_t parentBlockVersion;

// public Sha256Hash parentBlockPrev;
@property (nonatomic, readonly) NSData *parentBlockPrev;

// public Sha256Hash parentBlockMerkleRoot;
@property (nonatomic, readonly) NSData *parentBlockMerkleRoot;

// public long parentBlockTime;
@property (nonatomic, readonly) NSTimeInterval parentBlockTime; // time interval since refrence date, 00:00:00 01/01/01 GMT

// public long parentBlockBits;
@property (nonatomic, readonly) uint32_t parentBlockBits;

// public long parentBlockNonce;
@property (nonatomic, readonly) uint32_t parentBlockNonce;




@end