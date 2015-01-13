#import "FwiSP.h"
#import "FwiSS.h"
#import "FwiFactoryAES.h"


@interface FwiSS () <FwiOperationDelegate, FwiServiceDelegate> {
}

@end


@implementation FwiSS


@synthesize stage=_stage;
@synthesize host=_host, ssID=_ssID, aesKey=_aesKey, peerCrt=_peerCrt;


#pragma mark - Class's constructors
- (id)init {
    self = [super init];
    if (self) {
        _host      = nil;
        _ssID      = nil;
        _aesKey    = nil;
        _peerCrt   = nil;
        _initSSURL = nil;
    }
    return self;
}


#pragma mark - Cleanup memory
- (void)dealloc {
    _delegate = nil;
    _host = nil;
    FwiRelease(_ssID);
    FwiRelease(_aesKey);
    FwiRelease(_peerCrt);
    FwiRelease(_initSSURL);

#if !__has_feature(objc_arc)
    [super dealloc];
#endif
}


#pragma mark - Class's properties


#pragma mark - Class's public methods
- (void)startWithURL:(NSURL *)initSSURL peerCrt:(id<FwiRsaCrt>)peerCrt {
    /* Condition validation: Validate secured session */
    FwiSP *provider = [FwiSP sharedInstance];
    if (provider.stage != kSPStage_Ready) return;
    
    @synchronized(self) {
        if (_stage == kSSStage_Ready || _stage == kSSStage_Starting) return;
        _stage = kSSStage_Starting;
    }
    DLog(@"[INFO] Secured session is starting...");
    
    _host      = provider.host;
    _peerCrt   = FwiRetain(peerCrt);
    _initSSURL = FwiRetain(initSSURL);
    
    // Send request
    FwiJson *request = [FwiJson object:
                        @"hostname", [FwiJson stringWithString:[_host hostname]],
                        nil];
    __block FwiRESTService *net = [FwiRESTService serviceWithURL:_initSSURL method:kHTTP_Post requestMessage:request];
    [net setIdentifier:@"__initSS"];
    [net setDelegate:self];
    [net executeWithCompletion:^(FwiJson *responseMessage) {
        if ([responseMessage isLike:[FwiJson object:@"ss", [FwiJson string], nil]]) {
            NSString *encryptedSS = [[responseMessage jsonWithPath:@"ss"] getString];
            NSData *encryptedData = [encryptedSS decodeBase64Data];

            // Decrypted data
            NSData  *decryptedData = [[FwiSP sharedInstance].pvt decryptData:encryptedData];
            FwiJson *sessionInfo   = [FwiJson objectWithJSONData:decryptedData];

            // Update session info
            _ssID = FwiRetain([[sessionInfo jsonWithPath:@"ssID"] getString]);
            id<FwiAes> aesKey = [FwiFactoryAES aesKeyWithIdentifier:_ssID];

            if (![aesKey inKeystore]) {
                aesKey = FwiRetain([FwiFactoryAES aesKeyWithBase64String:[[sessionInfo jsonWithPath:@"keyCurrent"] getString] identifier:_ssID]);
            }
            _aesKey = FwiRetain(aesKey);
            _stage  = kSSStage_Ready;
        }
        else {
            _stage = kSSStage_Error;
            DLog(@"[ERROR] '%@' return invalid structure!", net.identifier);
        }

        // Validate secured session status
        if (_stage == kSSStage_Ready) {
            DLog(@"[INFO] Secured session is ready...");
        }
        else {
            DLog(@"[ERROR] Secured session is not ready!");
        }

        // Notify delegate
        if (_delegate && [_delegate respondsToSelector:@selector(session:didFinishWithStage:)])
            [_delegate session:self didFinishWithStage:_stage];
    }];
}
- (void)updateWithSessionID:(NSString *)sessionID aesKey:(id<FwiAes>)aesKey {
    [_aesKey remove];
    FwiRelease(_ssID);
    FwiRelease(_aesKey);
    
    _aesKey = FwiRetain(aesKey);
    _ssID = FwiRetain(sessionID);
}


#pragma mark - Class's private methods


#pragma mark - Class's notification handlers


#pragma mark - FwiOperationDelegate's members
- (void)operationWillStart:(FwiOperation *)operation {
    DLog(@"[INFO] '%@' will start...", operation.identifier);
}
- (void)operationDidCancel:(FwiOperation *)operation {
    DLog(@"[INFO] '%@' did cancel!", operation.identifier);
}
- (void)operation:(FwiOperation *)operation didFinishWithStage:(FwiOPState)stage userInfo:(NSDictionary *)userInfo {
    DLog(@"[INFO] '%@' did finish...", operation.identifier);
}


#pragma mark - FwiNetDelegate's members
- (void)service:(FwiService *)network errorOccurred:(NSError *)error errorCode:(FwiNetworkStatus)errorCode {
    DLog(@"[ERROR] '%@' request has an error:%@!", network.identifier, error);
}

- (void)network:(FwiService *)network didFinishWithResponseMessage:(FwiJson *)responseMessage {
    DLog(@"[INFO] '%@' request did finish...", network.identifier);
}


@end
