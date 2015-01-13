#import "PrivateImpl_FwiAes.h"


@interface PrivateImpl_FwiAes () {
}

@end


@implementation PrivateImpl_FwiAes


#pragma mark - Class's constructors
- (id)init {
    self = [super init];
    if (self) {
        [self updateKeysize:k128];
        [self setIdentifier:@"com.key.aes"];
        
        _attributes[kAttr_type] = kClass_AES;
        _attributes[kAttr_encr] = kValue_Y;
        _attributes[kAttr_decr] = kValue_Y;
    }
    return self;
}


#pragma mark - Cleanup memory
- (void)dealloc {
    FwiRelease(_iv);

#if !__has_feature(objc_arc)
    [super dealloc];
#endif
}


#pragma mark - Class's properties
- (size_t)blocksize {
    return kCCBlockSizeAES128;
}


#pragma mark - Class's public methods
- (NSData *)decryptData:(NSData *)data, ... NS_REQUIRES_NIL_TERMINATION {
    /* Condition validation */
    if (![self inKeystore]) {
        DLog(@"[INFO] '%@' key was not inserted into keystore or had been removed from keystore, skip this step...", self.identifier);
        return nil;
    }
    
    /* Condition validation: Do not need to decrypt if there is no encrypted data */
    if (!data) return nil;

    // Append all data together
    NSMutableData *encryptedData = [[NSMutableData alloc] initWithData:data];
	va_list args;
	va_start(args, data);
	while ((data = va_arg(args, id))) {
        if ([data isKindOfClass:[NSData class]]) [encryptedData appendData:data];
	}
	va_end(args);

    /* Condition validation: Do not need to decrypt if there is no encrypted data */
	if (encryptedData.length <= 0) {
        FwiRelease(encryptedData);
        return nil;
    }

    /* Condition validation: Do not need to decrypt if there is no valid iv */
    if (!_iv || _iv.length != 16) {
        FwiRelease(encryptedData);
        return nil;
    }

    // Perform decrypt
    size_t lengthEst = encryptedData.length;    // Estimate output length
    size_t lengthAct = 0;                       // Actual output length

    uint8_t *output  = malloc(lengthEst);
    NSData  *keyData = [self encode];
    CCCryptorStatus status = CCCrypt(kCCDecrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                                     keyData.bytes, keyData.length, _iv.bytes,
                                     encryptedData.bytes, encryptedData.length,
                                     output, lengthEst, &lengthAct);
    [keyData clearBytes];

    // Clean up
    FwiRelease(encryptedData);
    __autoreleasing NSData *rawData = nil;

    // Prepare output data
    if (status == kCCSuccess) rawData = FwiAutoRelease([[NSData alloc] initWithBytes:output length:lengthAct]);
    else rawData = [[NSData alloc] init];

    free(output);
	return rawData;
}
- (NSData *)encryptData:(NSData *)data, ... NS_REQUIRES_NIL_TERMINATION {
    /* Condition validation */
    if (![self inKeystore]) {
        DLog(@"[INFO] '%@' key was not inserted into keystore or had been removed from keystore, skip this step...", self.identifier);
        return nil;
    }
    
    /* Condition validation: Do not need to encrypt if there is no data */
    if (!data) return nil;

    // Append all data together
    NSMutableData *rawData = [[NSMutableData alloc] initWithData:data];
	va_list args;
	va_start(args, data);
	while ((data = va_arg(args, id))) {
        if ([data isKindOfClass:[NSData class]]) [rawData appendData:data];
	}
	va_end(args);

    /* Condition validation: Do not need to encrypt if there is no data */
	if (rawData.length <= 0) {
        FwiRelease(rawData);
        return nil;
    }

    // Create iv if it is not available
    if (!_iv || _iv.length == 0) {
        FwiRelease(_iv);

        // Compute new iv
        uint8_t *ivBytes = malloc(16);  // Note: Java only accept iv 16 bytes
		bzero(ivBytes, 16);

        SecRandomCopyBytes(kSecRandomDefault, 16, ivBytes);
        _iv = [[NSData alloc] initWithBytesNoCopy:ivBytes length:16];
    }

    // Perform encrypt
    size_t lengthEst = rawData.length + self.blocksize;     // Estimate output length
    size_t lengthAct = 0;                                   // Actual output length

    uint8_t *output  = malloc(lengthEst);
    NSData  *keyData = [self encode];
    CCCryptorStatus status = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                                     keyData.bytes, keyData.length, _iv.bytes,
                                     rawData.bytes, rawData.length,
                                     output, lengthEst, &lengthAct);
    [keyData clearBytes];

    // Clean up
    FwiRelease(rawData);
    __autoreleasing NSData *encryptedData = nil;

    // Prepare output data
    if (status == kCCSuccess) encryptedData = FwiAutoRelease([[NSData alloc] initWithBytes:output length:lengthAct]);
    else encryptedData = [[NSData alloc] init];

    free(output);
	return encryptedData;
}


@end


@implementation PrivateImpl_FwiAes (FwkAESKeyCreation)


#pragma mark - Class's static constructors
+ (id<FwiAes>)aesKeyWithKeysize:(FwiAesSize)keysize identifier:(NSString *)identifier {
    __autoreleasing PrivateImpl_FwiAes *aesKey = FwiAutoRelease([[PrivateImpl_FwiAes alloc] initWithKeysize:keysize identifier:identifier]);
    return aesKey;
}


#pragma mark - Class's constructors
- (id)initWithKeysize:(FwiAesSize)keysize identifier:(NSString *)identifier {
    self = [self init];
    if (self) {
        /* Condition validation: Validate new identifier, if it is not valid, use default */
        if (identifier && identifier.length > 0) [self setIdentifier:identifier];

        /* Condition validation: Validate new keysize, if it is not valid, use default */
        if (keysize == k128 || keysize == k192 || keysize == k256) _keysize = keysize;

        // Update attributes
        _attributes[kAttr_bsiz] = @(_keysize);
        _attributes[kAttr_esiz] = @(_keysize);
        
        // Generate new aes key
        uint8_t *keyBytes = malloc(_keysize);
		bzero(keyBytes, _keysize);

		FwiSecStatus status = SecRandomCopyBytes(kSecRandomDefault, _keysize, keyBytes);
		if (status == kSec_Success) {
            NSData *data = [[NSData alloc] initWithBytesNoCopy:keyBytes length:_keysize];
            [self insertIntoKeystoreWithData:data];
            [data clearBytes];
            FwiRelease(data);
        }
        else {
            free(keyBytes);
        }
    }
    return self;
}


@end