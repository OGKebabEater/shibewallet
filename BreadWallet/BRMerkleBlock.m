//
//  BRMerkleBlock.m
//  BreadWallet
//
//  Created by Aaron Voisine on 10/22/13.
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

#import "BRMerkleBlock.h"
#import "BRAuxPowMessage.h"
#import "NSMutableData+Bitcoin.h"
#import "NSData+Bitcoin.h"
#import "NSData+Hash.h"
#import "openssl/bn.h"

#define MAX_TIME_DRIFT        (2*60*60)     // the furthest in the future a block is allowed to be timestamped
#define MAX_PROOF_OF_WORK      0x1e0fffff   // highest value for difficulty target (higher values are less difficult)
#define TARGET_TIMESPAN       (4*60*60)     // the targeted timespan between difficulty target adjustments
#define TARGET_TIMESPAN_NEW   60            // the new targeted timespan between difficulty target adjustments
#define TARGET_SPACING        60
#define DIFF_CHANGE_TARGET    145000


#define BLOCK_VERSION_AUXPOW_AUXBLOCK 0x00620102

// convert difficulty target format to bignum, as per: https://github.com/bitcoin/bitcoin/blob/master/src/uint256.h#L323
static void setCompact(BIGNUM *bn, uint32_t compact)
{
    uint32_t size = compact >> 24, word = compact & 0x007fffff;
    
    if (size > 3) {
        BN_set_word(bn, word);
        BN_lshift(bn, bn, (size - 3)*8);
    }
    else BN_set_word(bn, word >> (3 - size)*8);
    
    BN_set_negative(bn, (compact & 0x00800000) != 0);
}

static uint32_t getCompact(const BIGNUM *bn)
{
    uint32_t size = BN_num_bytes(bn), compact = 0;
    BIGNUM x;

    if (size > 3) {
        BN_init(&x);
        BN_rshift(&x, bn, (size - 3)*8);
        compact = BN_get_word(&x);
    }
    else compact = BN_get_word(bn) << (3 - size)*8;

    if (compact & 0x00800000) { // if sign is already set, divide the mantissa by 256 and increment the exponent
        compact >>= 8;
        size++;
    }

    return (compact | size << 24) | (BN_is_negative(bn) ? 0x00800000 : 0);
}

// from https://en.bitcoin.it/wiki/Protocol_specification#Merkle_Trees
// Merkle trees are binary trees of hashes. Merkle trees in bitcoin use a double SHA-256, the SHA-256 hash of the
// SHA-256 hash of something. If, when forming a row in the tree (other than the root of the tree), it would have an odd
// number of elements, the final double-hash is duplicated to ensure that the row has an even number of hashes. First
// form the bottom row of the tree with the ordered double-SHA-256 hashes of the byte streams of the transactions in the
// block. Then the row above it consists of half that number of hashes. Each entry is the double-SHA-256 of the 64-byte
// concatenation of the corresponding two hashes below it in the tree. This procedure repeats recursively until we reach
// a row consisting of just a single double-hash. This is the merkle root of the tree.
//
// from https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki#Partial_Merkle_branch_format
// The encoding works as follows: we traverse the tree in depth-first order, storing a bit for each traversed node,
// signifying whether the node is the parent of at least one matched leaf txid (or a matched txid itself). In case we
// are at the leaf level, or this bit is 0, its merkle node hash is stored, and its children are not explored further.
// Otherwise, no hash is stored, but we recurse into both (or the only) child branch. During decoding, the same
// depth-first traversal is performed, consuming bits and hashes as they written during encoding.
//
// example tree with three transactions, where only tx2 is matched by the bloom filter:
//
//     merkleRoot
//      /     \
//    m1       m2
//   /  \     /  \
// tx1  tx2 tx3  tx3
//
// flag bits (little endian): 00001011 [merkleRoot = 1, m1 = 1, tx1 = 0, tx2 = 1, m2 = 0, byte padding = 000]
// hashes: [tx1, tx2, m2]

@implementation BRMerkleBlock

// message can be either a merkleblock or header message
+ (instancetype)blockWithMessage:(NSData *)message
{
    return [[self alloc] initWithMessage:message];
}
+ (instancetype)blockWithMessage:(NSData *)message andParentBlock:(BRMerkleBlock *)parentBlock
{
    return [[self alloc] initWithMessage:message andParentBlock:parentBlock];
}

- (instancetype)initWithMessage:(NSData *)message andParentBlock:(BRMerkleBlock *)parentBlock
{
    self = [self initWithMessage:message];
    _parentBlock = parentBlock;
    return self;
}


- (instancetype)initWithMessage:(NSData *)message
{
    if (! (self = [self init])) return nil;
    
    if (message.length < 80) return nil;

    NSUInteger off = 0, l = 0, len = 0;

    _blockHash = [message subdataWithRange:NSMakeRange(0, 80)].SHA256_2;
    _version = [message UInt32AtOffset:off];
    off += sizeof(uint32_t);
    _prevBlock = [message hashAtOffset:off];
    off += CC_SHA256_DIGEST_LENGTH;
    _merkleRoot = [message hashAtOffset:off];
    off += CC_SHA256_DIGEST_LENGTH;
    _timestamp = [message UInt32AtOffset:off] - NSTimeIntervalSince1970;
    off += sizeof(uint32_t);
    _target = [message UInt32AtOffset:off];
    off += sizeof(uint32_t);
    _nonce = [message UInt32AtOffset:off];
    off += sizeof(uint32_t);
    if ([self isAuxPow]) {
        BRAuxPowMessage *auxpowmessage = [BRAuxPowMessage blockWithMessage:[message subdataWithRange:NSMakeRange(off, message.length - off)]];
        off += auxpowmessage.length;
        _parentBlock = [BRMerkleBlock blockWithMessage:[auxpowmessage constructParentHeader]];
    } else {
        _powHash = [message subdataWithRange:NSMakeRange(0, 80)].SCRYPT;
    }
    _totalTransactions = [message UInt32AtOffset:off];
    off += sizeof(uint32_t);
    len = (NSUInteger)[message varIntAtOffset:off length:&l]*CC_SHA256_DIGEST_LENGTH;
    off += l;
    _hashes = off + len > message.length ? nil : [message subdataWithRange:NSMakeRange(off, len)];
    off += len;
    _flags = [message dataAtOffset:off length:&l];
    _height = BLOCK_UNKOWN_HEIGHT;

    return self;
}

- (instancetype)initWithBlockHash:(NSData *)blockHash version:(uint32_t)version prevBlock:(NSData *)prevBlock
merkleRoot:(NSData *)merkleRoot timestamp:(NSTimeInterval)timestamp target:(uint32_t)target nonce:(uint32_t)nonce
totalTransactions:(uint32_t)totalTransactions hashes:(NSData *)hashes flags:(NSData *)flags height:(uint32_t)height
parentBlock:(NSData*)parentBlock
{
    if (! (self = [self init])) return nil;
    
    _blockHash = blockHash;
    _version = version;
    _prevBlock = prevBlock;
    _merkleRoot = merkleRoot;
    _timestamp = timestamp;
    _target = target;
    _nonce = nonce;
    _totalTransactions = totalTransactions;
    _hashes = hashes;
    _flags = flags;
    _height = height;
    _parentBlock = [BRMerkleBlock blockWithMessage:parentBlock];
    
    return self;
}

- (BOOL)isMerkleRootValid
{
    NSMutableData *d = [NSMutableData data];
    int hashIdx = 0, flagIdx = 0;
    NSData *merkleRoot =
    [self _walk:&hashIdx :&flagIdx :0 :^id (NSData *hash, BOOL flag) {
        return hash;
    } :^id (id left, id right) {
        [d setData:left];
        [d appendData:right ? right : left]; // if right branch is missing, duplicate left branch
        return d.SHA256_2;
    }];

    return !(_totalTransactions > 0 && ! [merkleRoot isEqual:_merkleRoot]);
}

// true if merkle tree and timestamp are valid, and proof-of-work matches the stated difficulty target
// NOTE: this only checks if the block difficulty matches the difficulty target in the header, it does not check if the
// target is correct for the block's height in the chain, use verifyDifficultyFromPreviousBlock: for that
- (BOOL)isValid
{
    if ([self isAuxPow]) {
        if (![_parentBlock isMerkleRootValid]) return NO;
    } else {
        if (![self isMerkleRootValid]) return NO;
    }

    BIGNUM hash, target, maxTarget;
    
    //TODO: use estimated network time instead of system time (avoids timejacking attacks and misconfigured time)
    NSTimeInterval max_time = [NSDate timeIntervalSinceReferenceDate] + MAX_TIME_DRIFT;

    NSTimeInterval checktime = _timestamp;
    if (_version == BLOCK_VERSION_AUXPOW_AUXBLOCK) {
        checktime = _parentBlock.timestamp;
    }

    if (checktime > max_time) return NO;
    if (checktime < 0) return NO;

    // check proof-of-work
    BN_init(&target);
    BN_init(&maxTarget);
    setCompact(&target, _target);
    setCompact(&maxTarget, MAX_PROOF_OF_WORK);
    if (BN_cmp(&target, BN_value_one()) < 0 || BN_cmp(&target, &maxTarget) > 0) return NO; // target out of range

    NSData* h;

    if (_version == BLOCK_VERSION_AUXPOW_AUXBLOCK) {
        h = _parentBlock.powHash;
    } else {
        h = _powHash;
    }

    BN_init(&hash);
    BN_bin2bn(h.reverse.bytes, (int)h.length, &hash);

    if (BN_cmp(&hash, &target) > 0) {
        return NO;
    }


    return YES;
}

- (NSData *)toData
{
    NSMutableData *d = [NSMutableData data];
    
    [d appendUInt32:_version];
    [d appendData:_prevBlock];
    [d appendData:_merkleRoot];
    [d appendUInt32:_timestamp + NSTimeIntervalSince1970];
    [d appendUInt32:_target];
    [d appendUInt32:_nonce];
    [d appendUInt32:_totalTransactions];
    [d appendVarInt:_hashes.length/CC_SHA256_DIGEST_LENGTH];
    [d appendData:_hashes];
    [d appendVarInt:_flags.length];
    [d appendData:_flags];
    
    return d;
}

// true if the given tx hash is included in the block
- (BOOL)containsTxHash:(NSData *)txHash
{
    for (NSUInteger i = 0; i < _hashes.length/CC_SHA256_DIGEST_LENGTH; i += CC_SHA256_DIGEST_LENGTH) {
        if (! [txHash isEqual:[_hashes hashAtOffset:i]]) continue;
        return YES;
    }
    
    return NO;
}

// returns an array of the matched tx hashes
- (NSArray *)txHashes
{
    int hashIdx = 0, flagIdx = 0;
    NSArray *txHashes =
        [self _walk:&hashIdx :&flagIdx :0 :^id (NSData *hash, BOOL flag) {
            return (flag && hash) ? @[hash] : @[];
        } :^id (id left, id right) {
            return [left arrayByAddingObjectsFromArray:right];
        }];
    
    return txHashes;
}

// Verifies the block difficulty target is correct for the block's position in the chain. Transition time may be 0 if
// height is not a multiple of BLOCK_DIFFICULTY_INTERVAL.
//
// The difficulty target algorithm works as follows:
// The target must be the same as in the previous block unless the block's height is a multiple of 2016. Every 2016
// blocks there is a difficulty transition where a new difficulty is calculated. The new target is the previous target
// multiplied by the time between the last transition block's timestamp and this one (in seconds), divided by the
// targeted time between transitions (14*24*60*60 seconds). If the new difficulty is more than 4x or less than 1/4 of
// the previous difficulty, the change is limited to either 4x or 1/4. There is also a minimum difficulty value
// intuitively named MAX_PROOF_OF_WORK... since larger values are less difficult.
- (BOOL)verifyDifficultyFromPreviousBlock:(BRMerkleBlock *)previous andTransitionTime:(NSTimeInterval)time andStoredBlocks:(NSMutableDictionary *)blocks
{

    int32_t retargetTimespan = TARGET_TIMESPAN;
    int32_t retargetInterval = BLOCK_DIFFICULTY_INTERVAL;
    int32_t nHeight = previous.height + 1;

    bool newDifficultyProtocol = nHeight >= DIFF_CHANGE_TARGET;

    if (newDifficultyProtocol) {
        retargetInterval = TARGET_TIMESPAN_NEW / TARGET_SPACING;
        retargetTimespan = TARGET_TIMESPAN_NEW;
    }

    if (_height != nHeight) return NO;

#if BITCOIN_TESTNET
    //TODO: implement testnet difficulty rule check
    return YES; // don't worry about difficulty on testnet for now
#endif

    // Dogecoin: This fixes an issue where a 51% attack can change difficulty at will.
    // Go back the full period unless it's the first retarget after genesis. Code courtesy of Art Forz
    int blockstogoback = retargetInterval - 1;

    if ((nHeight+1) != retargetInterval)
        blockstogoback = retargetInterval;

    BRMerkleBlock *cursor = blocks[self.prevBlock];

    for (int i = 0; cursor && i < blockstogoback; i++) {
        assert(cursor);
        cursor = blocks[cursor.prevBlock];
    }

    if (cursor == nil) return YES; // hit checkpoint

    int32_t nModulatedTimespan = (int32_t)((int64_t)previous.timestamp - (int64_t)cursor.timestamp);

    if (newDifficultyProtocol) {
        nModulatedTimespan = retargetTimespan + (nModulatedTimespan - retargetTimespan)/8;

        if (nModulatedTimespan < (retargetTimespan - (retargetTimespan/4))) {
          nModulatedTimespan = (retargetTimespan - (retargetTimespan/4));
        }
        if (nModulatedTimespan > (retargetTimespan + (retargetTimespan/2))) {
            nModulatedTimespan = (retargetTimespan + (retargetTimespan/2));
        }

    } else {
      int32_t timespan = (int32_t)((int64_t)self.timestamp - (int64_t)time);
      if (nHeight > 10000) {
        if (nModulatedTimespan < timespan/4) nModulatedTimespan = timespan/4;
        if (nModulatedTimespan > timespan*4) nModulatedTimespan = timespan*4;
      } else if (nHeight > 5000) {
        if (nModulatedTimespan < timespan/8) nModulatedTimespan = timespan/8;
        if (nModulatedTimespan > timespan*4) nModulatedTimespan = timespan*4;
      } else {
        if (nModulatedTimespan < timespan/16) nModulatedTimespan = timespan/16;
        if (nModulatedTimespan > timespan*4) nModulatedTimespan = timespan*4;
      }
    }

    BN_CTX *ctx = BN_CTX_new();

    BN_CTX_start(ctx);

    BIGNUM target;
    BIGNUM *maxTarget = BN_CTX_get(ctx);
    BIGNUM *span = BN_CTX_get(ctx);
    BIGNUM *targetSpan = BN_CTX_get(ctx);
    BIGNUM *bn = BN_CTX_get(ctx);

    BN_init(&target);
    setCompact(&target, previous.target);
    setCompact(maxTarget, MAX_PROOF_OF_WORK);
    BN_set_word(span, nModulatedTimespan);
    BN_set_word(targetSpan, retargetTimespan);
    BN_mul(bn, &target, span, ctx);
    BN_div(&target, NULL, bn, targetSpan, ctx);
    if (BN_cmp(&target, maxTarget) > 0) BN_copy(&target, maxTarget); // limit to MAX_PROOF_OF_WORK
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    
    return (_target == getCompact(&target)) ? YES : NO;
}

// recursively walks the merkle tree in depth first order, calling leaf(hash, flag) for each stored hash, and
// branch(left, right) with the result from each branch
- (id)_walk:(int *)hashIdx :(int *)flagIdx :(int)depth :(id (^)(NSData *, BOOL))leaf :(id (^)(id, id))branch
{
    if ((*flagIdx)/8 >= _flags.length || (*hashIdx + 1)*CC_SHA256_DIGEST_LENGTH > _hashes.length) return leaf(nil, NO);
    
    BOOL flag = (((const uint8_t *)_flags.bytes)[*flagIdx/8] & (1 << (*flagIdx % 8)));
    
    (*flagIdx)++;
    
    if (! flag || depth == ceil(log2(_totalTransactions))) {
        NSData *hash = [_hashes hashAtOffset:(*hashIdx)*CC_SHA256_DIGEST_LENGTH];
        
        (*hashIdx)++;
        return leaf(hash, flag);
    }
    
    id left = [self _walk:hashIdx :flagIdx :depth + 1 :leaf :branch];
    id right = [self _walk:hashIdx :flagIdx :depth + 1 :leaf :branch];
    
    return branch(left, right);
}

- (NSUInteger)hash
{
    if (_blockHash.length < sizeof(NSUInteger)) return [super hash];
    return *(const NSUInteger *)_blockHash.bytes;
}

- (BOOL)isAuxPow
{
    return _version == BLOCK_VERSION_AUXPOW_AUXBLOCK;
}

- (BOOL)isEqual:(id)object
{
    if (self == object) return true;
    if (!([object isKindOfClass:[BRMerkleBlock class]])) return false;
    if ([[object blockHash] isEqual:_blockHash]) return true;
    if ([object isAuxPow] && [self isAuxPow] && [[[object parentBlock] blockHash] isEqual:[_parentBlock blockHash]]) return true;

    return false;
}

@end
