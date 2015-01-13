#import "FwiFactoryAES.h"
#import "PrivateImpl_FwiAes.h"


@implementation FwiFactoryAES


#pragma mark - Class's static methods
+ (id<FwiAes>)generateAesKey:(FwiAesSize)size {
    return [FwiFactoryAES generateAesKey:size identifier:[NSString randomIdentifier]];
}
+ (id<FwiAes>)generateAesKey:(FwiAesSize)size identifier:(NSString *)identifier {
    return [PrivateImpl_FwiAes aesKeyWithKeysize:size identifier:identifier];
}

+ (id<FwiAes>)aesKeyWithIdentifier:(NSString *)identifier {
    __autoreleasing PrivateImpl_FwiAes *aesKey = FwiAutoRelease([[PrivateImpl_FwiAes alloc] initWithIdentifier:identifier]);
    return aesKey;
}
+ (id<FwiAes>)aesKeyWithData:(NSData *)keyData identifier:(NSString *)identifier {
    if (!keyData || !(keyData.length == k128 || keyData.length == k192 || keyData.length == k256)) return nil;
    
    __autoreleasing PrivateImpl_FwiAes *aesKey = FwiAutoRelease([[PrivateImpl_FwiAes alloc] init]);
    [aesKey setIdentifier:identifier];
    [aesKey insertIntoKeystoreWithData:keyData];
    return aesKey;
}
+ (id<FwiAes>)aesKeyWithBase64String:(NSString *)base64String identifier:(NSString *)identifier {
    /* Condition validation */
    if (![base64String isBase64]) return nil;
    return [FwiFactoryAES aesKeyWithData:[base64String decodeBase64Data] identifier:identifier];
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


@end
