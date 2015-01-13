#import "PrivateImpl_FwiRsaPvt.h"


@interface PrivateImpl_FwiRsaPvt () {

}

@end


@implementation PrivateImpl_FwiRsaPvt


static FwiDer *_Pvt = nil;


+ (void)initialize {
    _Pvt = [FwiDer sequence:
            [FwiDer integer],
            [FwiDer integer],
            [FwiDer integer],
            [FwiDer integer],
            [FwiDer integer],
            [FwiDer integer],
            [FwiDer integer],
            [FwiDer integer],
            [FwiDer integer],
            nil];
}


#pragma mark - Class's static methods
+ (FwiDer *)structure {
    return [FwiDer sequence:
            [FwiDer integer],
            [FwiDer sequence:
             [FwiDer objectIdentifier],
             [FwiDer null],
             nil],
            [FwiDer octetString],
            nil];
}


#pragma mark - Class's constructors
- (id)init {
    self = [super init];
    if (self) {
        // Indentify key's attributes
        _attributes[kAttr_kcls] = kValue_Y;
    }
    return self;
}


#pragma mark - Cleanup memory
- (void)dealloc {
#if !__has_feature(objc_arc)
    [super dealloc];
#endif
}


#pragma mark - Class's override methods
- (NSString *)description {
    if (![self inKeystore]) return @"";

    NSString *description = nil;
    @autoreleasepool {
        NSData *data = [self encode];
        FwiDer *o = [data decodeDer];
        
        NSMutableString *builder = [NSMutableString stringWithFormat:@"\r\nRSA private key, %zi bits\r\n", _keysize];
        [builder appendFormat:@"  Modulus      (n)                : %@...\r\n", [[[o derAtIndex:1] getString] substringWithRange:NSMakeRange(0, 45)]];
        [builder appendFormat:@"  Pub exponent (e)                : %@\r\n"   , [[o derAtIndex:2] getString]];
        [builder appendFormat:@"  Pvt exponent (d)                : %@...\r\n", [[[o derAtIndex:3] getString] substringWithRange:NSMakeRange(0, 45)]];
        [builder appendFormat:@"  Prime 1      (p)                : %@...\r\n", [[[o derAtIndex:4] getString] substringWithRange:NSMakeRange(0, 45)]];
        [builder appendFormat:@"  Prime 2      (q)                : %@...\r\n", [[[o derAtIndex:5] getString] substringWithRange:NSMakeRange(0, 45)]];
        [builder appendFormat:@"  exponent 1   (d mod (p-1))      : %@...\r\n", [[[o derAtIndex:6] getString] substringWithRange:NSMakeRange(0, 45)]];
        [builder appendFormat:@"  exponent 2   (d mod (q-1))      : %@...\r\n", [[[o derAtIndex:7] getString] substringWithRange:NSMakeRange(0, 45)]];
        [builder appendFormat:@"  coefficient  ((inverse q) mod p): %@...\r\n", [[[o derAtIndex:8] getString] substringWithRange:NSMakeRange(0, 45)]];

        description = [[NSString alloc] initWithFormat:@"%@", [builder description]];
    }
    return FwiAutoRelease(description);
}


#pragma mark - Class's properties


#pragma mark - Class's public methods
- (void)setPKCS8Data:(NSData *)data {
    /* Condition validation */
    if (!data || data.length == 0) return;
    
    /* Condition validation: Validate data structure */
    FwiDer *o = [data decodeDer];
    if (![o isLike:[PrivateImpl_FwiRsaPvt structure]]) return;
    
    /* Condition validation: Validate object identifier */
    NSData *oID = [[o derWithPath:@"1/0"] getContent];
    if (![oID isEqualToData:[[FwiDer objectIdentifierWithOIDString:_objectIdentifier] encode]]) return;
    
    /**
     * RSAPrivateKey ::= SEQUENCE {
     *   0. version Version,
     *   1. modulus INTEGER, 			-- n
     *   2. publicExponent INTEGER, 	-- e
     *   3. privateExponent INTEGER,	-- d
     *   4. prime1 INTEGER, 			-- p
     *   5. prime2 INTEGER, 			-- q
     *   6. exponent1 INTEGER,			-- d mod (p-1)
     *   7. exponent2 INTEGER, 			-- d mod (q-1)
     *   8. coefficient INTEGER, 		-- (inverse of q) mod p
     * }
     */
    FwiDer *components = [[[o derAtIndex:2] getContent] decodeDer];
    if ([components isLike:_Pvt]) {
        [self updateKeysize:([[[components derAtIndex:3] getContent] length] << 3)];
        [self insertIntoKeystoreWithData:[components encode]];
    }
}
- (void)setPKCS8Base64String:(NSString *)base64String {
    /* Condition validation */
    if (!base64String || base64String.length == 0) return;
    base64String = [base64String parsePEM];
    
    if (base64String.length > 0) {
        [self setPKCS8Data:[base64String decodeBase64Data]];
    }
}

- (FwiDer *)encodeDER {
    if (![self inKeystore]) return [FwiDer null];
    FwiDer *pvt = [super encodeDER];
    
    FwiDer *o = [FwiDer sequence:
                 [FwiDer integerWithInt:0],
                 [FwiDer sequence:
                  [FwiDer objectIdentifierWithOIDString:_objectIdentifier],
                  [FwiDer null],
                  nil],
                 [FwiDer octetStringWithData:[pvt encode]],
                 nil];
    return o;
}
- (NSString *)encodePEM {
    /* Condition validation */
    if (![self inKeystore]) return nil;
    
    NSString *base64String = [self encodeBase64String];
    return [NSString stringWithFormat:@"-----BEGIN PRIVATE KEY-----%@-----END PRIVATE KEY-----", base64String];
}

- (NSData *)decryptData:(NSData *)data {
    /* Condition validation */
    if (![self inKeystore] || !data || data.length <= 0) return nil;

    /* Condition validation: verify signature length */
    size_t blocksize = self.blocksize;
    if (blocksize == 0) return nil;

    // Decrypt data
    uint8_t *buffer = malloc(blocksize);
    bzero(buffer, blocksize);
    SecKeyRef key = self.key;

    FwiSecStatus status = SecKeyDecrypt(key, kSecPaddingPKCS1, data.bytes, data.length, buffer, &blocksize);
    FwiReleaseCF(key);

    __autoreleasing NSData *result = nil;
    if (status == kSec_Success) result = [[NSData alloc] initWithBytes:buffer length:blocksize];

    free(buffer);
    return FwiAutoRelease(result);
}
- (NSData *)signData:(NSData *)data digest:(FwiDigest)digest {
    /* Condition validation */
    if (![self inKeystore]) return nil;

    /* Condition validation: verify signature length */
    size_t blocksize = self.blocksize;
    if (!data || data.length <= 0 || blocksize == 0) return nil;

    // Standardize signature
    NSData *digestData = [[FwiDer sequence:
                           [FwiDer sequence:
                            [FwiDer objectIdentifierWithOIDString:FwiDigestOIDWithDigest(digest)],
                            [FwiDer null],
                            nil],
                           [FwiDer octetStringWithData:[data sha:digest]],
                           nil] encode];

    // Create digital signature
    uint8_t *buffer = malloc(blocksize);
    bzero(buffer, blocksize);
    SecKeyRef key = self.key;
    
    FwiSecStatus status = SecKeyRawSign(key, kSecPaddingPKCS1, digestData.bytes, digestData.length, buffer, &blocksize);
    FwiReleaseCF(key);

	__autoreleasing NSData *result = nil;
    if (status == kSec_Success) result = [[NSData alloc] initWithBytes:buffer length:blocksize];

    free(buffer);
    return FwiAutoRelease(result);
}


@end


@implementation PrivateImpl_FwiRsaPvt (FwiRsaPvtCreation)


#pragma mark - Class's static constructors
+ (id<FwiRsaPvt>)pvtKeyWithBase64String:(NSString *)base64String identifier:(NSString *)identifier {
    __autoreleasing PrivateImpl_FwiRsaPvt *pvtKey = FwiAutoRelease([[PrivateImpl_FwiRsaPvt alloc] init]);
    [pvtKey setIdentifier:identifier];
    [pvtKey setPKCS8Base64String:base64String];
    return pvtKey;
}
+ (id<FwiRsaPvt>)pvtKeyWithData:(NSData *)data identifier:(NSString *)identifier {
    __autoreleasing PrivateImpl_FwiRsaPvt *pvtKey = FwiAutoRelease([[PrivateImpl_FwiRsaPvt alloc] init]);
    [pvtKey setIdentifier:identifier];
    [pvtKey setPKCS8Data:data];
    return pvtKey;
}
+ (id<FwiRsaPvt>)pvtKeyWithIdentifier:(NSString *)identifier {
    __autoreleasing PrivateImpl_FwiRsaPvt *pvtKey = FwiAutoRelease([[PrivateImpl_FwiRsaPvt alloc] initWithIdentifier:identifier]);
    return pvtKey;
}


@end