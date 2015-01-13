#import "FwiSP.h"
#import "FwiFactoryAES.h"
#import "FwiFactoryRSA.h"
#import "PrivateImpl_FwiOPGenerateKeypair.h"
#import "PrivateImpl_FwiOPLoadCrtCA.h"


@interface FwiSP () <FwiOperationDelegate, FwiServiceDelegate> {
    
    NSMutableDictionary *_sessions;
}

@property (atomic, assign) BOOL isOp1Finished;
@property (atomic, assign) BOOL isOp2Finished;


/**
 * Call whenever status updated
 */
- (void)_validateStatus;

@end


@implementation FwiSP


@synthesize stage=_stage;
@synthesize host=_host, pvt=_pvt, crt=_crt, crtCA=_crtCA;


#pragma mark - Class's constructors
- (id)init {
    self = [super init];
    if (self) {
        _stage    = kSPStage_Initialize;
        _delegate = nil;
        _host     = nil;
        _pvt      = nil;
        _crt      = nil;
        _crtCA    = nil;
        _sessions = [[NSMutableDictionary alloc] initWithCapacity:1];
    }
    return self;
}


#pragma mark - Cleanup memory
- (void)dealloc {
    _delegate = nil;
    _host = nil;
    
    FwiRelease(_crtCAURL);
    FwiRelease(_csrURL);
    FwiRelease(_pvt);
    FwiRelease(_crt);
    FwiRelease(_crtCA);
    FwiRelease(_sessions);

#if !__has_feature(objc_arc)
    [super dealloc];
#endif
}


#pragma mark - Class's properties


#pragma mark - Class's public methods
- (FwiSS *)sessionWithPeerHostname:(NSString *)peerHostname {
    if (!peerHostname || peerHostname.length <= 0) return nil;
    return _sessions[peerHostname];
}
- (void)removeSessionWithPeerHostname:(NSString *)peerHostname {
    if (!peerHostname || peerHostname.length <= 0) return;
    @synchronized(_sessions) {
        [_sessions removeObjectForKey:peerHostname];
    }
}
- (void)registerSession:(FwiSS *)session peerHostname:(NSString *)peerHostname {
    if (!peerHostname || peerHostname.length <= 0 || !session) return;
    @synchronized (_sessions) {
        if (!_sessions[peerHostname]) _sessions[peerHostname] = session;
    }
}

- (void)startWithHost:(id<FwiHost>)host crtCAURL:(NSURL *)crtCAURL csrURL:(NSURL *)csrURL {
    /* Condition validation */
    @synchronized(self) {
        if (_stage == kSPStage_Ready || _stage == kSSStage_Starting) return;
        _stage = kSPStage_Starting;
    }
    DLog(@"[INFO] Security provider is starting...");
    
    _host     = host;
    _csrURL   = FwiRetain(csrURL);
    _crtCAURL = FwiRetain(crtCAURL);
    
    // Load / Generate keypair
    FwiOperation *op1 = [PrivateImpl_FwiOPGenerateKeypair operationWithHostname:[_host hostname] keysize:[_host keysize]];
    [op1 setIdentifier:@"__Generatekeypair"];
    [op1 setDelegate:self];
    [op1 execute];
    
    // Load X.509 CrtCA
    FwiOperation *op2 = [PrivateImpl_FwiOPLoadCrtCA operationWithCrtCAURL:_crtCAURL];
    [op2 setIdentifier:@"__LoadCrtCA"];
    [op2 setDelegate:self];
    [op2 execute];
}


#pragma mark - Class's private methods
- (void)_validateStatus {
    if (!(self.isOp1Finished && self.isOp2Finished)) return;
    
    // Only verify host's X.509 certificate if there is no error
    if (_stage == kSPStage_Starting) {
        BOOL isSigned = [_crtCA verifyCertificate:_crt];
        if (isSigned) {
            _stage = kSPStage_Ready;
            DLog(@"[INFO] Security provider is ready...");
        }
        else {
            _stage = kSPStage_Error;
            DLog(@"[ERROR] Security provider is not ready!");
        }
    }
    else {
        DLog(@"[ERROR] Security provider is not ready!");
    }
    
    // Notify delegate
    if (_delegate && [_delegate respondsToSelector:@selector(provider:didFinishWithStage:)])
        [_delegate provider:self didFinishWithStage:_stage];
}


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
    
    if ([operation.identifier isEqualToString:@"__Generatekeypair"]) {
        // Save private key
        id<FwiKeypair> kp = (id<FwiKeypair>)userInfo[@"kp"];
        _pvt = FwiRetain([kp pvtKey]);
        
        // Load host's X.509 certificate
        id<FwiRsaCrt> crt = [FwiFactoryRSA crtWithIdentifier:[_host hostname]];
        if ([crt inKeystore]) {
            DLog(@"[INFO] Host's X.509 certificate is available, waiting to be verified...");
            FwiRelease(_crt);
            _crt = FwiRetain(crt);
            
            // Update op1's status
            self.isOp1Finished = YES;
            [self _validateStatus];
        }
        else {
            DLog(@"[INFO] Host's X.509 certificate is not available, requesting...");
            
            // Generate csr
            NSString *csr = [kp createCSRWithSubject:[_host subject] digest:[_host digest]];
            
            // Generate request
            FwiJson *request = [FwiJson object:
                                @"csr", [FwiJson stringWithString:csr],
                                nil];
            
            // Send request
            __block FwiRESTService *net = [FwiRESTService serviceWithURL:_csrURL method:kHTTP_Post requestMessage:request];
            [net setIdentifier:@"__csr"];
            [net setDelegate:self];
            [net executeWithCompletion:^(FwiJson *responseMessage) {
                DLog(@"[INFO] '%@' request did finish...", net.identifier);
                
                if ([responseMessage isLike:[FwiJson object:@"crt", [FwiJson string], nil]]) {
                    NSString *crtString = [[responseMessage jsonWithPath:@"crt"] getString];
                    id<FwiRsaCrt> crt = [FwiFactoryRSA crtWithBase64String:crtString];
                    if ([crt inKeystore]) {
                        FwiRelease(self->_crt);
                        self->_crt = FwiRetain(crt);
                    }
                    else {
                        _stage = kSPStage_Error;
                    }
                }
                else {
                    _stage = kSPStage_Error;
                    DLog(@"[ERROR] '%@' return invalid structure!", net.identifier);
                }
                
                // Update op1's status
                self.isOp1Finished = YES;
                [self _validateStatus];
            }];
        }
    }
    else if ([operation.identifier isEqualToString:@"__LoadCrtCA"]) {
        id<FwiRsaCrt> crtCA = (id<FwiRsaCrt>)userInfo[@"crtCA"];
        if (crtCA) {
            DLog(@"[INFO] CA's X.509 certificate is available...");
            FwiRelease(_crtCA);
            _crtCA = FwiRetain(crtCA);
        }
        else {
            DLog(@"[INFO] CA's X.509 certificate is not available, downloading...");
        }
        
        // Always check crtCA
        NSData  *crt3Hash = ([_crtCA inKeystore] ? [[_crtCA encode] sha:kSHA1] : nil);
        FwiJson *request  = [FwiJson object:
                             @"crt3Hash", [FwiJson stringWithString:[crt3Hash encodeBase64String]],
                             nil];
        
        // Send request
        __block FwiRESTService *net = [FwiRESTService serviceWithURL:_crtCAURL method:kHTTP_Post requestMessage:request];
        [net setIdentifier:@"__crtCA"];
        [net setDelegate:self];
        [net executeWithCompletion:^(FwiJson *responseMessage) {
            DLog(@"[INFO] '%@' request did finish...", net.identifier);
            
            if ([responseMessage isLike:[FwiJson object:
                                         @"class1CRT", [FwiJson string],
                                         @"class3CRT", [FwiJson string],
                                         nil]])
            {
                NSString *class1CRT = [[responseMessage jsonWithPath:@"class1CRT"] getString];
                NSString *class3CRT = [[responseMessage jsonWithPath:@"class3CRT"] getString];
                id<FwiRsaCrt> crt1  = [FwiFactoryRSA crtWithBase64String:class1CRT];
                id<FwiRsaCrt> crt3  = [FwiFactoryRSA crtWithBase64String:class3CRT];

                // Verify crt3
                if ([crt1 inKeystore]) {
                    BOOL isSigned = [crt1 verifyCertificate:crt3];

                    if (isSigned && [crt3 inKeystore]) {
                        NSDictionary   *crtID       = @{@"class1CRT":[crt1 identifier], @"class3CRT":[crt3 identifier]};
                        NSUserDefaults *userDefault = [NSUserDefaults standardUserDefaults];
                        NSString       *hostname    = [_crtCAURL host];

                        [userDefault setObject:hostname forKey:@"hostname"];
                        [userDefault setObject:crtID forKey:hostname];
                        [userDefault synchronize];

                        FwiRelease(_crtCA);
                        _crtCA = FwiRetain(crt3);
                    }
                }
            }
            else if ([responseMessage isLike:[FwiJson null]]) {
                DLog(@"[INFO] CA's X.509 certificate is not changed...");
            }
            else {
                _stage = kSPStage_Error;
                DLog(@"[ERROR] '%@' return invalid structure!", net.identifier);
            }
            
            // Update op2's status
            self.isOp2Finished = YES;
            [self _validateStatus];
        }];
    }
}


#pragma mark - FwiNetDelegate's members
- (void)service:(FwiService *)network errorOccurred:(NSError *)error errorCode:(FwiNetworkStatus)errorCode {
    DLog(@"[ERROR] '%@' request has an error:%@!", network.identifier, error);
}

- (void)network:(FwiService *)network didFinishWithResponseMessage:(FwiJson *)responseMessage {
    DLog(@"[INFO] '%@' request did finish...", network.identifier);
}


@end


@implementation FwiSP (FwiSPCreation)


static FwiSP *_Instance = nil;


#pragma mark - Class's static constructors
+ (FwiSP *)sharedInstance {
    if (_Instance) return _Instance;
    
    @synchronized(self) {
        if (!_Instance) _Instance = [[FwiSP alloc] init];
    }
    return _Instance;
}


@end