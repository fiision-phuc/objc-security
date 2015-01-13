#import "FwiFactoryRSA.h"
#import "PrivateImpl_FwiKeypair.h"
#import "PrivateImpl_FwiRsaPub.h"
#import "PrivateImpl_FwiRsaPvt.h"
#import "PrivateImpl_FwiRsaCrt.h"


@implementation FwiFactoryRSA


#pragma mark - Class's static methods
+ (id<FwiKeypair>)keypairWithKeysize:(FwiRsaSize)size identifier:(NSString *)identifier {
    return [PrivateImpl_FwiKeypair keypairWithKeysize:size identifier:identifier];
}
+ (id<FwiKeypair>)keypairWithIdentifier:(NSString *)identifier {
    return [PrivateImpl_FwiKeypair keypairWithIdentifier:identifier];
}

+ (id<FwiRsaPub>)pubKeyWithBase64String:(NSString *)base64String identifier:(NSString *)identifier {
    return [PrivateImpl_FwiRsaPub pubKeyWithBase64String:base64String identifier:identifier];
}
+ (id<FwiRsaPub>)pubKeyWithData:(NSData *)data identifier:(NSString *)identifier {
    return [PrivateImpl_FwiRsaPub pubKeyWithData:data identifier:identifier];
}
+ (id<FwiRsaPub>)pubKeyWithIdentifier:(NSString *)identifier {
    return [PrivateImpl_FwiRsaPub pubKeyWithIdentifier:identifier];
}

+ (id<FwiRsaPvt>)pvtKeyWithBase64String:(NSString *)base64String identifier:(NSString *)identifier {
    return [PrivateImpl_FwiRsaPvt pvtKeyWithBase64String:base64String identifier:identifier];
}
+ (id<FwiRsaPvt>)pvtKeyWithData:(NSData *)data identifier:(NSString *)identifier {
    return [PrivateImpl_FwiRsaPvt pvtKeyWithData:data identifier:identifier];
}
+ (id<FwiRsaPvt>)pvtKeyWithIdentifier:(NSString *)identifier {
    return [PrivateImpl_FwiRsaPvt pvtKeyWithIdentifier:identifier];
}

+ (id<FwiRsaCrt>)crtWithBase64String:(NSString *)base64String {
    return [PrivateImpl_FwiRsaCrt crtWithBase64String:base64String];
}
+ (id<FwiRsaCrt>)crtWithData:(NSData *)data {
    return [PrivateImpl_FwiRsaCrt crtWithData:data];
}
+ (id<FwiRsaCrt>)crtWithIdentifier:(NSString *)identifier {
    return [PrivateImpl_FwiRsaCrt crtWithIdentifier:identifier];
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
