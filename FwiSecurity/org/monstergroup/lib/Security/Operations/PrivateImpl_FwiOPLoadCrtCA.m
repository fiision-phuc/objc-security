#import "PrivateImpl_FwiOPLoadCrtCA.h"
#import "FwiFactoryRSA.h"


@interface PrivateImpl_FwiOPLoadCrtCA () {
    
}

@end


@implementation PrivateImpl_FwiOPLoadCrtCA


#pragma mark - Class's constructors
- (id)init {
    self = [super init];
    if (self) {
        _crtCAURL = nil;
    }
    return self;
}


#pragma mark - Cleanup memory
- (void)dealloc {
    FwiRelease(_crtCAURL);

#if !__has_feature(objc_arc)
    [super dealloc];
#endif
}


#pragma mark - Class's public methods
- (void)businessLogic {
    NSUserDefaults *userDefault = [NSUserDefaults standardUserDefaults];
    
    // Load X.509 certificate information
    NSString *record = [userDefault objectForKey:@"hostname"];
    if (record && record.length > 0) {
        NSDictionary *crtID = [userDefault objectForKey:record];
        if (crtID && crtID.count == 2) {
            NSString *class1 = crtID[@"class1CRT"];
            NSString *class3 = crtID[@"class3CRT"];
            
            id<FwiRsaCrt> crt1 = [FwiFactoryRSA crtWithIdentifier:class1];
            id<FwiRsaCrt> crt3 = [FwiFactoryRSA crtWithIdentifier:class3];
            
            // Validate Peer's hostname is changing or not
            NSString *hostname = [_crtCAURL host];
            if ([hostname isEqualToString:record]) {
                // Verify crt3
                if ([crt1 inKeystore]) {
                    BOOL isSigned = [crt1 verifyCertificate:crt3];
                    
                    if (isSigned && [crt3 inKeystore]) {
                        _userInfo = FwiRetain(@{@"crtCA":crt3});
                        return;
                    }
                }
            }
            
            // Invalid crt1 & crt3
            [crt1 remove];
            [crt3 remove];
        }
    }
    
    // Default case
    if (record) [userDefault removeObjectForKey:record];
    [userDefault removeObjectForKey:@"hostname"];
    [userDefault synchronize];
}


@end


@implementation PrivateImpl_FwiOPLoadCrtCA (PrivateImpl_FwiOPLoadCrtCACreation)


#pragma mark - Class's constructors
+ (FwiOperation *)operationWithCrtCAURL:(NSURL *)crtCAURL {
    __autoreleasing FwiOperation *operation = FwiAutoRelease([[PrivateImpl_FwiOPLoadCrtCA alloc] initWithCrtCAURL:crtCAURL]);
    return operation;
}


#pragma mark - Class's constructors
- (id)initWithCrtCAURL:(NSURL *)crtCAURL {
    self = [self init];
    if (self) {
        _crtCAURL = FwiRetain(crtCAURL);
    }
    return self;
}


@end