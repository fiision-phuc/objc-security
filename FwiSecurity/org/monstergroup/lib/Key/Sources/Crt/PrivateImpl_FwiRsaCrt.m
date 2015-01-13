#import "PrivateImpl_FwiRsaCrt.h"
#import "FwiFactoryRSA.h"


@interface PrivateImpl_FwiRsaCrt () {

    NSMutableArray *_error;
}

@property (nonatomic, assign) BOOL isSigned;
@property (nonatomic, assign) BOOL isVerified;

@property (nonatomic, readonly) SecKeyRef key;
@property (nonatomic, readonly) size_t blocksize;


/**
 * Check expiration date
 */
- (BOOL)_isExpired;
/**
 * Verify X.509 certificate's components
 */
- (void)_verifyCertificate;

/**
 * Insert this key into keystore
 */
- (void)_insertIntoKeystoreWithData:(NSData *)data;

@end


@implementation PrivateImpl_FwiRsaCrt


@synthesize identifier=_identifier, version=_version;
@synthesize issuer=_issuer, subject=_subject, extensions=_extensions;
@synthesize serialNumber=_serialNumber, notAfter=_notAfter, notBefore=_notBefore, signatureData=_signatureData, signatureDigest=_signatureDigest, tbsData=_tbsData;


#pragma mark - Class's static methods
+ (FwiDer *)structure {
    return [FwiDer sequence:
            [FwiDer sequence:
             [FwiDer derWithIdentifier:0xa0 Ders:[FwiDer integer], nil],      // Version
             [FwiDer integer],                                                      // Serial Number
             [FwiDer sequence:                                                      // Signature Algorithm
              [FwiDer objectIdentifier],
              [FwiDer null],
              nil],
             [FwiDer sequence],                                                     // Issuer
             [FwiDer sequence:                                                      // Validity
              [FwiDer utcTime],                                                         // Not Before
              [FwiDer utcTime],                                                         // Not After
              nil],
             [FwiDer sequence],                                                     // Subject
             [FwiDer sequence:                                                      // Subject Public Key Info
              [FwiDer sequence:                                                         // Public Key Algorithm
               [FwiDer objectIdentifier],
               [FwiDer null],
               nil],
              [FwiDer bitString],                                                       // Subject Public Key
              nil],
             [FwiDer derWithIdentifier:0xa3 Ders:[FwiDer sequence], nil],         // Extensions
             nil],
            [FwiDer sequence:                                                       // Signature Algorithm
             [FwiDer objectIdentifier],
             [FwiDer null],
             nil],
            [FwiDer bitString],                                                     // Signature
            nil];
}


#pragma mark - Class's constructors
- (id)init {
    self = [super init];
    if (self) {
        _identifier      = nil;
        _version         = 0;
        
        _serialNumber    = nil;
        _notAfter        = nil;
        _notBefore       = nil;
        _signatureData   = nil;
        _signatureDigest = kSHA1;
        _tbsData         = nil;
        
        _issuer          = nil;
        _subject         = nil;
        _extensions      = nil;

        _attributes      = nil;
        _entry           = NULL;
        _certificate     = NULL;
    }
    return self;
}


#pragma mark - Cleanup memory
- (void)dealloc {
    FwiRelease(_identifier);
    
    FwiRelease(_serialNumber);
    FwiRelease(_notAfter);
    FwiRelease(_notBefore);
    FwiRelease(_signatureData);
    FwiRelease(_tbsData);
    
    FwiRelease(_issuer);
    FwiRelease(_subject);
    FwiRelease(_extensions);
    
    FwiRelease(_error);
    FwiRelease(_attributes);
    FwiReleaseCF(_entry);
    FwiReleaseCF(_certificate);

#if !__has_feature(objc_arc)
    [super dealloc];
#endif
}


#pragma mark - Class's properties
- (NSString *)identifier {
    if (![self inKeystore]) return _identifier;
    return _attributes[kAttr_labl];
}

- (SecKeyRef)key {
    /* Condition validation */
    if (![self inKeystore]) return nil;
    
    // Create trust policy
    SecKeyRef    key       = nil;
    SecTrustRef  trustRef  = nil;
    SecPolicyRef policyRef = SecPolicyCreateBasicX509();
    FwiSecStatus status    = SecTrustCreateWithCertificates(_certificate, policyRef, &trustRef);
    
    // Create search trust result
    SecTrustResultType trustResult;
    if (status == kSec_Success) {
        status = SecTrustEvaluate(trustRef, &trustResult);
        
        // Load public key
        if (status == kSec_Success) {
            key = SecTrustCopyPublicKey(trustRef);
        }
    }
    FwiReleaseCF(policyRef);
    FwiReleaseCF(trustRef);
    return key;
}
- (size_t)blocksize {
    /* Condition validation */
    if (![self inKeystore]) return 0;
    
    SecKeyRef key = self.key;
    size_t blocksize = 0;
    
    if (key) {
        blocksize = SecKeyGetBlockSize(key);
    }
    FwiReleaseCF(key);
    return blocksize;
}


#pragma mark - Class's public methods
- (void)setX509Data:(NSData *)data shouldInsert:(BOOL)shouldInsert {
    /* Condition validation */
    if (!data || data.length == 0) return;
    
    /* Condition validation: Stop if it is not a valid X.509 Certificate */
    FwiDer *o = [data decodeDer];
    if (![o isLike:[PrivateImpl_FwiRsaCrt structure]]) return;
    
    _tbsData		  = FwiRetain([[o derAtIndex:0] encode]);
    _version		  = [[o derWithPath:@"0/0/0"] getInt];
    _serialNumber	  = FwiRetain([[o derWithPath:@"0/1"] getBigInt]);
    _signatureDigest  = FwiDigestWithSignatureOID([[o derWithPath:@"0/2/0"] getString]);
    // Validity
    _notBefore		  = FwiRetain([[o derWithPath:@"0/4/0"] getTime]);
    _notAfter		  = FwiRetain([[o derWithPath:@"0/4/1"] getTime]);
    // Signature
    _signatureData	  = FwiRetain([[o derAtIndex:2] getContent]);
    
    // X.509 issuer, subject & extensions
    FwiDer *issuer    = [o derWithPath:@"0/3"];
    FwiDer *subject   = [o derWithPath:@"0/5"];
    FwiDer *extension = [o derWithPath:@"0/7"];
    if (issuer) _issuer        = FwiRetain(FwiAttributesToDictionary(issuer));
    if (subject) _subject      = FwiRetain(FwiAttributesToDictionary(subject));
    if (extension) _extensions = FwiRetain(FwiExtensionsToDictionary(extension));
    
    // Update certificate's status
    [self _verifyCertificate];
    if (!self.isVerified) return;
    
    if (shouldInsert) {
        // Insert X.509 certificate into keystore
        [self _insertIntoKeystoreWithData:data];
    }

    // Verify root certificate
    if ([_serialNumber isEqualTo:[FwiBigInt bigIntWithInteger:0]]) {
        [self verifyCertificate:self];
    }
}
- (void)setX509Base64String:(NSString *)base64String shouldInsert:(BOOL)shouldInsert {
    /* Condition validation */
    if (!base64String || base64String.length == 0) return;
    base64String = [base64String parsePEM];
    
    if (base64String.length > 0) {
        [self setX509Data:[base64String decodeBase64Data] shouldInsert:shouldInsert];
    }
}


#pragma mark - FwiRsaCrt's members
- (BOOL)inKeystore {
    BOOL inKeystore = (_entry && _certificate && _attributes);
    return inKeystore;
}
- (void)remove {
    /* Condition validation */
    if (![self inKeystore]) {
        DLog(@"[INFO] '%@' key was not inserted into keystore or had been removed from keystore, skip this step...", self.identifier);
        return;
    }
    
    @autoreleasepool {
        NSDictionary *keyInfo = @{kValuePersistentRef:(__bridge id)_entry};
        
        FwiSecStatus status = SecItemDelete((__bridge CFDictionaryRef)keyInfo);
        if (status == kSec_Success) {
            DLog(@"[INFO] '%@' key had been removed from keystore...", self.identifier);
            
            // Remove all keys that have similar identifier but different size
            keyInfo = @{kClass:kClass_CRT, kAttr_labl:self.identifier, kReturnPersistentRef:kValue_Y};
            do {
                status = SecItemDelete((__bridge CFDictionaryRef)keyInfo);
            }
            while (status == kSec_Success);
            
            // Release this entry
            FwiRelease(_attributes);
            FwiReleaseCF(_entry);
            FwiReleaseCF(_certificate);
        }
        else {
            DLog(@"[ERROR] Could not remove '%@' key from keystore!", self.identifier);
        }
    }
}

- (NSData *)encode {
    /* Condition validation */
    if (![self inKeystore]) return nil;
    
    __autoreleasing NSData *data = (NSData *)CFBridgingRelease(SecCertificateCopyData(_certificate));
    return FwiAutoRelease(data);
}
- (FwiDer *)encodeDER {
    if (![self inKeystore]) return [FwiDer null];
    return [[self encode] decodeDer];
}
- (NSString *)encodePEM {
    /* Condition validation */
    if (![self inKeystore]) return nil;
    
    NSString *base64String = [self encodeBase64String];
    return [NSString stringWithFormat:@"-----BEGIN CERTIFICATE-----%@-----END CERTIFICATE-----", base64String];
}
- (NSData *)encodeBase64Data {
    return [[self encode] encodeBase64Data];
}
- (NSString *)encodeBase64String {
    return [[self encodeBase64Data] toString];
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
    FwiDer *digestDer  = [FwiDer sequence:
                          [FwiDer sequence:
                           [FwiDer objectIdentifierWithOIDString:FwiDigestOIDWithDigest(digest)],
                           [FwiDer null],
                           nil],
                          [FwiDer octetStringWithData:[data sha:digest]],
                          nil];
    NSData *digestData = [digestDer encode];
    
    // Verify signature
    SecKeyRef key = self.key;
    FwiSecStatus status = SecKeyRawVerify(key, kSecPaddingPKCS1, digestData.bytes, digestData.length, signature.bytes, blocksize);
    
    FwiReleaseCF(key);
	return (status == kSec_Success);
}

- (BOOL)verifyCertificate:(id<FwiRsaCrt>)certificate {
    BOOL isSigned = NO;
    
    if (!((PrivateImpl_FwiRsaCrt *)certificate).isVerified) {
        [certificate remove];
        return isSigned;
    }
    
    // Cast certificate
    isSigned = [self verifyData:[certificate tbsData] digest:[certificate signatureDigest] signature:[certificate signatureData]];
    if (!isSigned) [certificate remove];
    
    ((PrivateImpl_FwiRsaCrt *)certificate).isSigned = isSigned;
    return isSigned;
}


#pragma mark - Class's private methods
- (BOOL)_isExpired {
    /* Condition validation */
    if (!_notAfter || !_notBefore) return YES;
    
    NSDate *today = [NSDate date];
    return !(([today compare:_notBefore] >= 0 && [today compare:_notAfter] < 0));
}
- (void)_verifyCertificate {
    [_error removeAllObjects];
    FwiBigInt *thredHold = [FwiBigInt bigIntWithInteger:0];
    
    if (_version != 2)                        { [_error addObject:@(kX509Error_InvalidVersion)];            }
    if ([_serialNumber isLessThan:thredHold]) { [_error addObject:@(kX509Error_InvalidSerialNumber)];       }
    if ([self _isExpired])                    { [_error addObject:@(kX509Error_CertificateExpired)];        }
    if (![self inKeystore])                   { [_error addObject:@(kX509Error_InvalidPublicKey)];          }
    if (!_signatureDigest)                    { [_error addObject:@(kX509Error_InvalidSignatureAlgorithm)]; }
    if (!_signatureData)                      { [_error addObject:@(kX509Error_InvalidSignatureData)];      }
    if (!_issuer)                             { [_error addObject:@(kX509Error_MissingIssuerInfo)];         }
    if (!_subject)                            { [_error addObject:@(kX509Error_MissingSubjectInfo)];        }
    if (!_extensions)                         { [_error addObject:@(kX509Error_MissingExtensionsInfo)];     }
    
    // Dump error status
    if (_error.count > 0) DLog(@"%@", _error);
    
    // Update validation status
    self.isVerified = (_error.count == 0);
}

- (void)_insertIntoKeystoreWithData:(NSData *)data {
    // Create X.509 certificate
    FwiReleaseCF(_certificate);
    _certificate = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)data);
    NSString *subject = (NSString *)CFBridgingRelease(SecCertificateCopySubjectSummary(_certificate));
    
    
    // Insert X.509 certificate into keystore
    NSDictionary *keyInfo = @{kClass:kClass_CRT, kValueRef:(__bridge id)_certificate, kReturnPersistentRef:kValue_Y};
    FwiSecStatus status = SecItemAdd((__bridge CFDictionaryRef)keyInfo, (CFTypeRef *)&_entry);
    
    if (status == kSec_Success) {
        DLog(@"[INFO] Success insert '%@' crt into keystore...", subject);
    }
    else if (status == kSec_KeychainDuplicateItem) {
        DLog(@"[INFO] '%@' crt is available within keystore...", subject);
        
        keyInfo = @{kClass:kClass_CRT, kAttr_labl:subject, kReturnPersistentRef:kValue_Y};
        status = SecItemCopyMatching((__bridge CFDictionaryRef)keyInfo, (CFTypeRef *)&_entry);
    }
    else {
        DLog(@"[ERROR] Could not insert '%@' crt into keystore!", subject);
    }
    FwiRelease(subject);
    
    // Load X.509 certificate's attributes
    if (status == kSec_Success) {
        CFDictionaryRef attrRef = nil;
        NSDictionary *attrQuery = @{kValuePersistentRef:(__bridge id)_entry, kReturnAttributes:kValue_Y};
        
        status = SecItemCopyMatching((__bridge CFDictionaryRef)attrQuery, (CFTypeRef *)&attrRef);
        if (status == kSec_Success) {
            _attributes = [[NSMutableDictionary alloc] initWithDictionary:(__bridge NSDictionary *)attrRef];
        }
        FwiReleaseCF(attrRef);
    }
}


@end


@implementation PrivateImpl_FwiRsaCrt (PrivateImpl_FwiRsaCrtCreation)


#pragma mark - Class's static constructors
+ (id<FwiRsaCrt>)crtWithBase64String:(NSString *)base64String {
    __autoreleasing PrivateImpl_FwiRsaCrt *crt = FwiAutoRelease([[PrivateImpl_FwiRsaCrt alloc] init]);
    [crt setX509Base64String:base64String shouldInsert:YES];
    
    return crt;
}
+ (id<FwiRsaCrt>)crtWithData:(NSData *)data {
    __autoreleasing PrivateImpl_FwiRsaCrt *crt = FwiAutoRelease([[PrivateImpl_FwiRsaCrt alloc] init]);
    [crt setX509Data:data  shouldInsert:YES];
    
    return crt;
}
+ (id<FwiRsaCrt>)crtWithIdentifier:(NSString *)identifier {
    __autoreleasing PrivateImpl_FwiRsaCrt *crt = FwiAutoRelease([[PrivateImpl_FwiRsaCrt alloc] initWithWithIdentifier:identifier]);
    return crt;
}


#pragma mark - Class's constructors
- (id)initWithWithIdentifier:(NSString *)identifier {
    self = [self init];
    if (self) {
        _identifier = FwiRetain(identifier);
        
        // 1. Query crt entry
        NSDictionary *keyQuery = @{kClass:kClass_CRT, kAttr_labl:identifier, kReturnPersistentRef:kValue_Y};
        FwiSecStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)keyQuery, (CFTypeRef *)&_entry);
        
        // 2. If success, query crt's attributes
        if (status == kSec_Success) {
            NSDictionary *attrQuery = @{kValuePersistentRef:(__bridge id)_entry, kReturnAttributes:kValue_Y};

            CFDictionaryRef attrRef = nil;
            status = SecItemCopyMatching((__bridge CFDictionaryRef)attrQuery, (CFTypeRef *)&attrRef);
            if (status == kSec_Success) {
                _attributes = [[NSMutableDictionary alloc] initWithDictionary:(__bridge NSDictionary *)attrRef];

                // 3. If success, create crt
                NSDictionary *dataQuery = @{kValuePersistentRef:(__bridge id)_entry, kReturnData:kValue_Y};

                CFDataRef dataRef = nil;
                status = SecItemCopyMatching((__bridge CFDictionaryRef)dataQuery, (CFTypeRef *)&dataRef);
                if (status == kSec_Success) {
                    FwiReleaseCF(_certificate);

                    _certificate = SecCertificateCreateWithData(NULL, dataRef);
                    [self setX509Data:(__bridge NSData *)dataRef shouldInsert:NO];
                }
                FwiReleaseCF(dataRef);
            }
            FwiReleaseCF(attrRef);
        }
    }
    return self;
}


@end