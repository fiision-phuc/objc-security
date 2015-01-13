#import "PrivateImpl_FwiRsaPub.h"


@interface PrivateImpl_FwiRsaPub () {
    
}

@end


@implementation PrivateImpl_FwiRsaPub


static FwiDer *_Pub = nil;


+ (void)initialize {
    _Pub = [FwiDer sequence:
            [FwiDer integer],
            [FwiDer integer],
            nil];
}


#pragma mark - Class's static methods
+ (FwiDer *)structure {
    return [FwiDer sequence:
            [FwiDer sequence:
             [FwiDer objectIdentifier],
             [FwiDer null],
             nil],
            [FwiDer bitString],
            nil];
}


#pragma mark - Class's constructors
- (id)init {
    self = [super init];
    if (self) {
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

    __autoreleasing NSString *description = nil;
    @autoreleasepool {
        NSData *data = [self encode];
        FwiDer *o = [data decodeDer];
        
        NSMutableString *builder = [NSMutableString stringWithFormat:@"\r\nRSA public key, %zi bits\r\n", _keysize];
        [builder appendFormat:@"  Modulus      (n): %@...\r\n", [[[o derAtIndex:0] getString] substringWithRange:NSMakeRange(0, 45)]];
        [builder appendFormat:@"  Pub exponent (e): %@\r\n"   , [[o derAtIndex:1] getString]];

        description = [[NSString alloc] initWithFormat:@"%@", [builder description]];
    }
    return FwiAutoRelease(description);
}


#pragma mark - Class's properties


#pragma mark - Class's public methods
- (void)setX509Data:(NSData *)data {
    /* Condition validation */
    if (!data || data.length == 0) return;
    
    /* Condition validation: Validate data structure */
    FwiDer *o = [data decodeDer];
    if (![o isLike:[PrivateImpl_FwiRsaPub structure]]) return;
    
    /* Condition validation: Validate object identifier */
    NSData *oID = [[o derWithPath:@"0/0"] getContent];
    if (![oID isEqualToData:[[FwiDer objectIdentifierWithOIDString:_objectIdentifier] encode]]) return;
    
    /**
     * RSAPublicKey ::= SEQUENCE {
     *   1. modulus INTEGER,			-- n
     *   2. publicExponent INTEGER, 	-- e
     * }
     */
    FwiDer *components = [[[o derAtIndex:1] getContent] decodeDer];
    if ([components isLike:_Pub]) {
        [self updateKeysize:(([[[components derAtIndex:0] getContent] length] - 1) << 3)];
        [self insertIntoKeystoreWithData:[components encode]];
    }
}
- (void)setX509Base64String:(NSString *)base64String {
    /* Condition validation */
    if (!base64String || base64String.length == 0) return;
    base64String = [base64String parsePEM];
    
    if (base64String.length > 0) {
        [self setX509Data:[base64String decodeBase64Data]];
    }
}

- (FwiDer *)encodeDER {
    if (![self inKeystore]) return [FwiDer null];
    FwiDer *pub = [super encodeDER];
    
    FwiDer *o = [FwiDer sequence:
                 [FwiDer sequence:
                  [FwiDer objectIdentifierWithOIDString:_objectIdentifier],
                  [FwiDer null],
                  nil],
                 [FwiDer bitStringWithData:[pub encode] padding:0],
                 nil];
    return o;
}
- (NSString *)encodePEM {
    /* Condition validation */
    if (![self inKeystore]) return nil;
    
    NSString *base64String = [self encodeBase64String];
    return [NSString stringWithFormat:@"-----BEGIN PUBLIC KEY-----%@-----END PUBLIC KEY-----", base64String];
}

- (NSData *)encryptData:(NSData *)data {
    /* Condition validation */
    if (![self inKeystore] || !data || data.length <= 0) return nil;

    /* Condition validation: verify blocksize length */
    size_t blocksize = self.blocksize;
    if (blocksize == 0) return nil;
    
    /* Condition validation: Verify overhead raw data */
    if (data.length > (blocksize - 12)) return nil;
    
    // Encrypt data
    uint8_t *buffer = malloc(blocksize);
    bzero(buffer, blocksize);
    
    SecKeyRef key = self.key;
    __autoreleasing NSData *result = nil;

    FwiSecStatus status = SecKeyEncrypt(key, kSecPaddingPKCS1, data.bytes, data.length, buffer, &blocksize);
    FwiReleaseCF(key);
    
    if (status == kSec_Success) result = FwiAutoRelease([[NSData alloc] initWithBytes:buffer length:blocksize]);
    free(buffer);
    
    return result;
}

- (BOOL)verifyData:(NSData *)data digest:(FwiDigest)digest signature:(NSData *)signature {
    /* Condition validation */
    if (![self inKeystore]) return NO;

    /* Condition validation: verify signature length */
    size_t blocksize = signature.length;
    if (!data || data.length <= 0 || !signature || signature.length <= 0 || blocksize == 0) return NO;

    // Standardize signature
    NSData *digestData = [[FwiDer sequence:
                           [FwiDer sequence:
                            [FwiDer objectIdentifierWithOIDString:FwiDigestOIDWithDigest(digest)],
                            [FwiDer null],
                            nil],
                           [FwiDer octetStringWithData:[data sha:digest]],
                           nil] encode];

    // Verify signature
    SecKeyRef key = self.key;
    FwiSecStatus status = SecKeyRawVerify(key, kSecPaddingPKCS1, digestData.bytes, digestData.length, signature.bytes, blocksize);
    
    FwiReleaseCF(key);
	return (status == kSec_Success);
}


@end


@implementation PrivateImpl_FwiRsaPub (FwiRsaPubCreation)


#pragma mark - Class's static constructors
+ (id<FwiRsaPub>)pubKeyWithBase64String:(NSString *)base64String identifier:(NSString *)identifier {
    __autoreleasing PrivateImpl_FwiRsaPub *pubKey = FwiAutoRelease([[PrivateImpl_FwiRsaPub alloc] init]);
    [pubKey setIdentifier:identifier];
    [pubKey setX509Base64String:base64String];
    return pubKey;
}
+ (id<FwiRsaPub>)pubKeyWithData:(NSData *)data identifier:(NSString *)identifier {
    __autoreleasing PrivateImpl_FwiRsaPub *pubKey = FwiAutoRelease([[PrivateImpl_FwiRsaPub alloc] init]);
    [pubKey setIdentifier:identifier];
    [pubKey setX509Data:data];
    return pubKey;
}
+ (id<FwiRsaPub>)pubKeyWithIdentifier:(NSString *)identifier {
    __autoreleasing PrivateImpl_FwiRsaPub *pubKey = FwiAutoRelease([[PrivateImpl_FwiRsaPub alloc] initWithIdentifier:identifier]);
    return pubKey;
}


@end