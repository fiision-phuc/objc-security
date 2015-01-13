#import "PrivateImpl_FwiKeypair.h"
#import "FwiFactoryRSA.h"


#define kDefaultIdentifier  @"com.key.rsa"


@interface PrivateImpl_FwiKeypair () {
}


- (void)_setPubKey:(id<FwiRsaPub>)pubKey;
- (void)_setPvtKey:(id<FwiRsaPvt>)pvtKey;

@end


@implementation PrivateImpl_FwiKeypair


#pragma mark - Class's constructors
- (id)init {
    self = [super init];
    if (self) {
        _pubKey = nil;
        _pvtKey = nil;
    }
    return self;
}


#pragma mark - Cleanup memory
- (void)dealloc {
    FwiRelease(_pubKey);
    FwiRelease(_pvtKey);

#if !__has_feature(objc_arc)
    [super dealloc];
#endif
}


#pragma mark - Class's properties


#pragma mark - Class's public methods
- (BOOL)inKeystore {
    if (!_pubKey || !_pvtKey) return NO;
    return ([_pubKey inKeystore] && [_pvtKey inKeystore]);
}
- (void)remove {
    if (_pubKey) [_pubKey remove];
    if (_pvtKey) [_pvtKey remove];
}

- (NSString *)createCSRWithSubject:(NSDictionary *)subject digest:(FwiDigest)digest {
    if (![self inKeystore]) return nil;

    // Generate sign object
    FwiDer *csrInfo = [FwiDer sequence:
                       [FwiDer integerWithInt:0],
                       FwiDictionaryToAttributes(subject),
                       [_pubKey encodeDER],
                       [FwiDer derWithIdentifier:0xa0],
                       nil];
    
    // Generate signature & signatureOID
    NSData *signature = [_pvtKey signData:[csrInfo encode] digest:digest];
    csrInfo = [FwiDer sequence:
               csrInfo,
               [FwiDer sequence:
                [FwiDer objectIdentifierWithOIDString:FwiSignatureOIDWithDigest(digest)],
                [FwiDer null],
                nil],
               [FwiDer bitStringWithData:signature padding:0],
               nil];

    // Standardize csr request
    __autoreleasing NSString *base64String = [csrInfo encodeBase64String];
    __autoreleasing NSString *csrRequest   = [[NSString alloc] initWithFormat:@"-----BEGIN CERTIFICATE REQUEST-----%@-----END CERTIFICATE REQUEST-----", base64String];
    
    return FwiAutoRelease(csrRequest);
}


#pragma mark - Class's private methods
- (void)_setPubKey:(id<FwiRsaPub>)pubKey {
    FwiRelease(_pubKey);
    _pubKey = FwiRetain(pubKey);
}
- (void)_setPvtKey:(id<FwiRsaPvt>)pvtKey {
    FwiRelease(_pvtKey);
    _pvtKey = FwiRetain(pvtKey);
}


@end


@implementation PrivateImpl_FwiKeypair (FwiKeypairCreation)


#pragma mark - Class's static constructors
+ (id<FwiKeypair>)keypairWithIdentifier:(NSString *)identifier {
    __autoreleasing PrivateImpl_FwiKeypair *kp = FwiAutoRelease([[PrivateImpl_FwiKeypair alloc] initWithIdentifier:identifier]);
    return kp;
}
+ (id<FwiKeypair>)keypairWithKeysize:(FwiRsaSize)keysize identifier:(NSString *)identifier {
    __autoreleasing PrivateImpl_FwiKeypair *kp = FwiAutoRelease([[PrivateImpl_FwiKeypair alloc] initWithKeysize:keysize identifier:identifier]);
    return kp;
}


#pragma mark - Class's constructors
- (id)initWithIdentifier:(NSString *)identifier {
    self = [self init];
    if (self) {
        /* Condition validation */
        if (!identifier || identifier.length <= 0) identifier = kDefaultIdentifier;

        @autoreleasepool {
            NSString *pubIdentifier = [NSString stringWithFormat:@"%@|pub", identifier];
            NSString *pvtIdentifier = [NSString stringWithFormat:@"%@|pvt", identifier];
            [self _setPubKey:[FwiFactoryRSA pubKeyWithIdentifier:pubIdentifier]];
            [self _setPvtKey:[FwiFactoryRSA pvtKeyWithIdentifier:pvtIdentifier]];
        }
    }
    return self;
}
- (id)initWithKeysize:(FwiRsaSize)keysize identifier:(NSString *)identifier {
    self = [self init];
    if (self) {
        /* Condition validation */
        if (!identifier || identifier.length <= 0) identifier = kDefaultIdentifier;

        /* Condition validation: If keysize does not valid, use default */
        if (!(keysize == k1024 || keysize == k2048 || keysize == k4096)) keysize = k1024;

        @autoreleasepool {
            NSString *pubIdentifier = [NSString stringWithFormat:@"%@|pub", identifier];
            NSString *pvtIdentifier = [NSString stringWithFormat:@"%@|pvt", identifier];
            NSData *pubID = [pubIdentifier toData];
            NSData *pvtID = [pvtIdentifier toData];

            /**
             * Remove all keys that are associated with these identifier
             */
            NSDictionary *keyInfo = nil;
            FwiSecStatus status = kSec_Success;

            // Remove all public keys that have similar identifier
            keyInfo = @{kClass:kClassKey, kAttr_atag:pubID};
            do {
                status = SecItemDelete((__bridge CFDictionaryRef)keyInfo);
            }
            while (status == kSec_Success);

            // Remove all private keys that have similar identifier
            keyInfo = @{kClass:kClassKey, kAttr_atag:pvtID};
            do {
                status = SecItemDelete((__bridge CFDictionaryRef)keyInfo);
            }
            while (status == kSec_Success);

            // Define attributes
            NSDictionary *pvtAttributes = @{kAttr_atag:pvtID, kAttr_perm:kValue_Y};
            NSDictionary *pubAttributes = @{kAttr_atag:pubID, kAttr_perm:kValue_Y};
            NSDictionary *kpAttributes  = @{kAttr_type:kClass_RSA,
                                            kPubKeyAttrs:pubAttributes,
                                            kPvtKeyAttrs:pvtAttributes,
                                            kAttr_bsiz:@(keysize)};

            SecKeyRef pvtKeyRef = nil;
            SecKeyRef pubKeyRef = nil;
            status = SecKeyGeneratePair((__bridge CFDictionaryRef)kpAttributes, &pubKeyRef, &pvtKeyRef);

            if (status == kSec_Success) {
                [self _setPubKey:[FwiFactoryRSA pubKeyWithIdentifier:pubIdentifier]];
                [self _setPvtKey:[FwiFactoryRSA pvtKeyWithIdentifier:pvtIdentifier]];
            }
            FwiReleaseCF(pvtKeyRef);
            FwiReleaseCF(pubKeyRef);
        }
    }
    return self;
}


@end