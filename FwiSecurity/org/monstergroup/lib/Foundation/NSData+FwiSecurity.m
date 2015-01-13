#import "NSData+FwiSecurity.h"


@implementation NSData (FwiSecurity)


- (NSData *)fingerprint {
    return [self sha:kSHA256];
}
- (NSData *)sha:(FwiDigest)digest {
    if (!self || self.length <= 0) return nil;

    uint8_t *hashBytes = malloc(digest);
    bzero(hashBytes, digest);
    switch (digest) {
        case kSHA256: CC_SHA256([self bytes], (CC_LONG)[self length], hashBytes); break;
        case kSHA384: CC_SHA384([self bytes], (CC_LONG)[self length], hashBytes); break;
        case kSHA512: CC_SHA512([self bytes], (CC_LONG)[self length], hashBytes); break;
        default: CC_SHA1([self bytes], (CC_LONG)[self length], hashBytes); break;
    }

    __autoreleasing NSData *sha = FwiAutoRelease([[NSData alloc] initWithBytes:hashBytes length:digest]);
    free(hashBytes);
	return sha;
}


@end
