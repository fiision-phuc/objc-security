#import "PrivateImpl_FwiKey.h"


@implementation PrivateImpl_FwiKey


#pragma mark - Class's constructors
- (id)init {
    self = [super init];
    if (self) {
        _identifier = @"com.key";
        _entry      = nil;
        _keysize    = 0;
        _blocksize  = 0;
        
        // Initialize attributes dictionary
        _attributes = [[NSMutableDictionary alloc] initWithCapacity:25];
        
        // Identify secret key
        _attributes[kClass] = kClassKey;
        _attributes[kAttr_atag] = [_identifier toData];
        _attributes[kAttr_bsiz] = @(_keysize);
        _attributes[kAttr_esiz] = @(_keysize);
        
        // Indentify key's attributes
        _attributes[kAttr_crtr] = kValue_N;
        _attributes[kAttr_decr] = kValue_N;
        _attributes[kAttr_drve] = kValue_N;
        _attributes[kAttr_encr] = kValue_N;
        _attributes[kAttr_kcls] = kValue_N;
        _attributes[kAttr_perm] = kValue_Y;
        _attributes[kAttr_sign] = kValue_N;
        _attributes[kAttr_unwp] = kValue_N;
        _attributes[kAttr_vrfy] = kValue_N;
        _attributes[kAttr_wrap] = kValue_N;
    }
    return self;
}


#pragma mark - Cleanup memory
- (void)dealloc {
    FwiRelease(_identifier);
    FwiRelease(_attributes);
    FwiReleaseCF(_entry);

#if !__has_feature(objc_arc)
    [super dealloc];
#endif
}


#pragma mark - Class's properties
- (SecKeyRef)key {
    /* Condition validation */
    if (![self inKeystore]) return nil;

    NSDictionary *query = @{kValuePersistentRef:(__bridge id)_entry, kReturnRef:kValue_Y};
    SecKeyRef key = nil;
    
    SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&key);
    return key;
}
- (size_t)keysize {
    return _keysize;
}
- (size_t)blocksize {
    /* Condition validation */
    if (![self inKeystore]) return 0;

    SecKeyRef key = self.key;
    size_t blocksize = 0;
    
    if (key) {
        blocksize = SecKeyGetBlockSize(key);
        FwiReleaseCF(key);
    }
    return blocksize;
}

- (void)setIdentifier:(NSString *)identifier {
    /* Condition validation */
    if (!identifier || identifier.length == 0) return;
    
    NSData *data = nil;
    if ([self inKeystore]) {
        // 1. Backup current key's data
        data = [self encode];
        
        // 2. Remove key from keystore
        [self remove];
    }

    // 3. Update key's identifier
    FwiRelease(_identifier);
    _identifier = FwiRetain(identifier);
    _attributes[kAttr_atag] = [_identifier toData];

    // 4. Insert into keystore again
    if (data && data.length > 0) {
        [self insertIntoKeystoreWithData:data];
        [data clearBytes];
    }
}


#pragma mark - Class's public methods
- (BOOL)inKeystore {
    BOOL inKeystore = (_entry != nil);
    return inKeystore;
}
- (void)remove {
    /* Condition validation */
    if (![self inKeystore]) {
        DLog(@"[INFO] '%@' key was not inserted into keystore or had been removed from keystore, skip this step...", _identifier);
        return;
    }
    
    NSDictionary *keyInfo = @{kValuePersistentRef:(__bridge id)_entry};
    FwiSecStatus status   = SecItemDelete((__bridge CFDictionaryRef)keyInfo);

    if (status == kSec_Success) {
        DLog(@"[INFO] '%@' key had been removed from keystore...", _identifier);
        
        // Remove all keys that have similar identifier but different size
        keyInfo = @{kClass:kClassKey, kAttr_atag:[_identifier toData]};
        do {
            status = SecItemDelete((__bridge CFDictionaryRef)keyInfo);
        }
        while (status == kSec_Success);
        
        // Release this entry
        FwiReleaseCF(_entry);
    }
    else {
        DLog(@"[ERROR] Could not remove '%@' key from keystore!", _identifier);
    }
}

- (NSData *)encode {
    /* Condition validation */
    if (![self inKeystore]) return nil;
    
    
    CFDataRef dataRef = nil;
    __autoreleasing NSData *data = nil;
    __autoreleasing NSDictionary *keyInfo = @{kValuePersistentRef:(__bridge id)_entry, kReturnData:kValue_Y};
    
    FwiSecStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)keyInfo, (CFTypeRef *)&dataRef);
    if (status == kSec_Success) {
        data = FwiAutoRelease((__bridge NSData *)dataRef);
    }
    else {
        FwiReleaseCF(dataRef);
    }
    return data;
}
- (NSData *)encodeBase64Data {
    return [[self encode] encodeBase64Data];
}
- (NSString *)encodeBase64String {
    return [[self encodeBase64Data] toString];
}

- (void)updateKeysize:(size_t)keysize {
    _keysize = keysize;
    _attributes[kAttr_bsiz] = @(keysize);
    _attributes[kAttr_esiz] = @(keysize);
}
- (void)insertIntoKeystoreWithData:(NSData *)data {
    NSMutableDictionary *keyInfo = [_attributes mutableCopy];
    keyInfo[kReturnPersistentRef] = kValue_Y;
    keyInfo[kValueData] = data;

    FwiSecStatus status = SecItemAdd((__bridge CFDictionaryRef)keyInfo, (CFTypeRef *)&_entry);
    if (status == kSec_Success) {
        DLog(@"[INFO] Success insert '%@' key into keystore...", _identifier);
    }
    else if (status == kSec_KeychainDuplicateItem) {
        DLog(@"[INFO] '%@' key is available within keystore, trying to update...", _identifier);
        
        NSDictionary *newInfo = @{kValueData:data};
        [self updateKeyInfo:keyInfo newInfo:newInfo];
    }
    else {
        DLog(@"[ERROR] Could not insert '%@' key into keystore!", _identifier);
    }
    FwiRelease(keyInfo);
}
- (void)updateKeyInfo:(NSDictionary *)keyInfo newInfo:(NSDictionary *)newInfo {
    FwiSecStatus status = SecItemUpdate((__bridge CFDictionaryRef)keyInfo, (__bridge CFDictionaryRef)newInfo);
    if (status == kSec_Success) {
        NSDictionary *query = @{kClass:_attributes[kClass],
                                kAttr_atag:[_identifier toData],
                                kReturnPersistentRef:kValue_Y};
        
        FwiSecStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&_entry);
        if (status == kSec_Success) {
            DLog(@"[INFO] Success update '%@' key inside keystore...", _identifier);
        }
        else {
            DLog(@"[ERROR] Could not update '%@' key inside keystore!", _identifier);
        }
    }
    else {
        DLog(@"[ERROR] Could not update '%@' key inside keystore!", _identifier);
    }
}


@end


@implementation PrivateImpl_FwiKey (FwiKeyCreation)


#pragma mark - Class's constructors
- (id)initWithIdentifier:(NSString *)identifier {
    self = [self init];
    if (self) {
        [self setIdentifier:identifier];

        // 1. Query key entry
        NSDictionary *query = @{kClass:_attributes[kClass],
                                kAttr_atag:[_identifier toData],
                                kReturnPersistentRef:kValue_Y};
        FwiSecStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&_entry);

        // 2. If success, query key's attributes
        if (status == kSec_Success) {
            NSDictionary *attrQuery = @{kValuePersistentRef:(__bridge id)_entry,
                                        kReturnAttributes:kValue_Y};

            CFDictionaryRef attrRef = nil;
            status = SecItemCopyMatching((__bridge CFDictionaryRef)attrQuery, (CFTypeRef *)&attrRef);
            if (status == kSec_Success) {
                FwiRelease(_attributes);
                _attributes = [[NSMutableDictionary alloc] initWithDictionary:(__bridge NSDictionary *)attrRef];
                _keysize    = [(NSNumber *)_attributes[kAttr_bsiz] unsignedIntegerValue];
            }
            FwiReleaseCF(attrRef);
        }
    }
    return self;
}


@end