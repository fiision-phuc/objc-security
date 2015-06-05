#import "PrivateImpl_FwiOPGenerateKeypair.h"
#import "FwiFactoryRSA.h"
#import "FwiHost.h"
#import "FwiSP.h"


@interface PrivateImpl_FwiOPGenerateKeypair () {
    
}

@end


@implementation PrivateImpl_FwiOPGenerateKeypair


#pragma mark - Class's constructors
- (id)init {
    self = [super init];
    if (self) {
        _hostname = nil;
    }
    return self;
}


#pragma mark - Cleanup memory
- (void)dealloc {
    FwiRelease(_hostname);

#if !__has_feature(objc_arc)
    [super dealloc];
#endif
}


#pragma mark - Class's public methods
- (void)businessLogic {
    BOOL shouldRemove = NO;
    id<FwiHost> host  = [[FwiSP sharedInstance] host];
    
    // Load / Check if keypair is exist or not and check if keysize is update or not
    id<FwiKeypair> kp = [FwiFactoryRSA keypairWithIdentifier:_hostname];
    if ([[kp pvtKey] keysize] != _keysize) {
        DLog(@"[INFO] Keysize had been changed, new keypair will be generated...");
        [kp remove];
        shouldRemove = YES;
    }
    
    // Alternative, generate new keypair
    if (![kp inKeystore]) {
        DLog(@"[INFO] Generate keypair...");
        kp = [FwiFactoryRSA keypairWithKeysize:_keysize identifier:_hostname];
    }
    else {
        DLog(@"[INFO] Keypair is available...");
    }
    
    // Verify host's X.509 certificate
    id<FwiRsaCrt> crt = [FwiFactoryRSA crtWithIdentifier:_hostname];
    if (!shouldRemove && [crt inKeystore]) {
        if ([host digest] != [crt signatureDigest] || [[host subject] isEqualToDictionary:[crt subject]]) {
            DLog(@"[INFO] Host's X.509 certificate info is different, Request new X.509 certificate...");
            [crt remove];
        }
        else {
            DLog(@"[INFO] Host's X.509 certificate is up to date...");
        }
    }
    else {
        DLog(@"[INFO] Request new X.509 certificate...");
        [crt remove];
    }
    
    _userInfo = FwiRetain(@{@"kp":kp});
}


@end


@implementation PrivateImpl_FwiOPGenerateKeypair (PrivateImpl_FwiOPGenerateKeypairCreation)


#pragma mark - Class's static constructors
+ (FwiOperation *)operationWithHostname:(NSString *)hostname keysize:(FwiRsaSize)keysize {
    __autoreleasing FwiOperation *operation = FwiAutoRelease([[PrivateImpl_FwiOPGenerateKeypair alloc] initWithHostname:hostname keysize:keysize]);
    return operation;
}


#pragma mark - Class's constructors
- (id)initWithHostname:(NSString *)hostname keysize:(FwiRsaSize)keysize {
    self = [self init];
    if (self) {
        _hostname = FwiRetain(hostname);
        _keysize  = keysize;
    }
    return self;
}


@end