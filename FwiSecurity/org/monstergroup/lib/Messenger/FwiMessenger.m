#import "FwiMessenger.h"
#import "FwiFactoryAES.h"
#import "FwiSP.h"
#import "FwiSS.h"


@interface FwiMessenger () {
}

@end


@implementation FwiMessenger


static NSInteger _AppVersion = 0;
static FwiJson   *_ResponseValidation = nil;


+ (void)initialize {
    _AppVersion = [[[NSBundle mainBundle] objectForInfoDictionaryKey:(id)kCFBundleVersionKey] doubleValue];
    __autoreleasing FwiJson *json = [FwiJson object:
                                       @"header" , [FwiJson object:
                                                      @"appVersion" , [FwiJson number],
                                                      @"messageType", [FwiJson number],
                                                    nil],
                                       @"content", [FwiJson object],
                                     nil];
    _ResponseValidation = FwiRetain(json);
}


#pragma mark - Class's constructors
- (id)init {
    self = [super init];
    if (self) {
        _validateStructures = [[NSMutableArray alloc] initWithCapacity:1];
    }
    return self;
}


#pragma mark - Cleanup memory
- (void)dealloc {
    FwiRelease(_validateStructures);

#if !__has_feature(objc_arc)
    [super dealloc];
#endif
}


#pragma mark - Class's properties


#pragma mark - Class's public methods
- (FwiJson *)decodeMessage:(FwiJson *)message {
    /* Condition validation: Validate response structure */
    if (!message || ![message isLike:_ResponseValidation]) {
        DLog(@"[ERROR] Invalid response structure!");
        return [FwiJson null];
    }
    
    /* Condition validation: Validate message type */
    FwiMessageType type = [[[message jsonWithPath:@"header/messageType"] getNumber] integerValue];
    if (!(type == kAesUnsign || type == kAesSigned || type == kRsaUnsign || type == kRsaSigned)) {
        DLog(@"[ERROR] Invalid response message type!");
        return [FwiJson null];
    }
    
    /* Condition validation: Validate application version */
    NSInteger appVersion = [[[message jsonWithPath:@"header/appVersion"] getNumber] integerValue];
    if (appVersion < 1) {
        DLog(@"[ERROR] Invalid application version!");
        return [FwiJson null];
    }
    
    /* Condition validation: Validate security provider status */
    FwiSP *provider = [FwiSP sharedInstance];
    if (provider.stage != kSPStage_Ready) {
        DLog(@"[ERROR] Security Provider is not ready!");
        return [FwiJson null];
    }
    
    /* Condition validation: Validate secured session status */
    FwiSS *session = [provider sessionWithPeerHostname:_peerHostname];
    if (session.stage != kSSStage_Ready) {
        DLog(@"[ERROR] Secured session is not ready!");
        return [FwiJson null];
    }
    
    // Decode process
    __block FwiJson *response = nil;
    NSData  *iv = nil;
    
    // Special case
    if (type == kRsaUnsign || type == kRsaSigned) {
        NSData *encodedSession = [[[message jsonWithPath:@"content/session"] getString] decodeBase64Data];
        NSData *decodedSession = [provider.pvt decryptData:encodedSession];
        
        if (!decodedSession || decodedSession.length <= 0) {
            DLog(@"[ERROR] Invalid new session info!");
            return [FwiJson null];
        }
        
        // Retrieve new session info
        FwiJson *sessionInfo = [FwiJson objectWithJSONData:decodedSession];
        NSString *ssID = [[sessionInfo jsonWithPath:@"ssID"] getString];
        if (![ssID isEqualToString:session.ssID]) {
            id<FwiAes> aesKey = [FwiFactoryAES aesKeyWithBase64String:[[sessionInfo jsonWithPath:@"keyCurrent"] getString] identifier:ssID];
        
            // Update session
            [session updateWithSessionID:ssID aesKey:aesKey];
        }
        
        // Get IV
        iv = [[[sessionInfo jsonWithPath:@"iv"] getString] decodeBase64Data];
        
        // Update message type
        type = (type == kRsaUnsign ? kAesUnsign : kAesSigned);
    }
    
    // Default data flow
    if (type == kAesUnsign || type == kAesSigned) {
        NSData *encodedIV = [[[message jsonWithPath:@"content/iv"] getString] decodeBase64Data];
        NSData *encodedMessage = [[[message jsonWithPath:@"content/encodeMessage"] getString] decodeBase64Data];
        
        // Decode IV
        if (!iv) {
            iv = [provider.pvt decryptData:encodedIV];
            if (!iv || iv.length != 16) {
                DLog(@"[ERROR] Invalid initialization vector!");
                return [FwiJson null];
            }
        }
        [session.aesKey setIv:iv];
        
        // Decode message
        NSData *decodedMessage = [session.aesKey decryptData:encodedMessage, nil];

        if(!decodedMessage){
            DLog(@"[ERROR] Could not decoded message!");
            return [FwiJson null];
        }
        
        if (type == kAesSigned) {
            NSData *signature = [[[message jsonWithPath:@"content/signatureData"] getString] decodeBase64Data];
            if (![session.peerCrt verifyData:decodedMessage digest:[session.peerCrt signatureDigest] signature:signature]) {
                DLog(@"[ERROR] Invalid signature!");
                return [FwiJson null];
            }
        }
        response = [FwiJson objectWithJSONData:decodedMessage];
        [session.aesKey setIv:nil];
    }
    
    // Verify content structures
    __block BOOL isVerified = NO;
    if (_validateStructures.count <= 0) {
        isVerified = YES;
    }
    else {
        [_validateStructures enumerateObjectsUsingBlock:^(FwiJson *structure, NSUInteger idx, BOOL *stop) {
            if ([response isLike:structure]) {
                *stop = YES;
                isVerified = YES;
            }
        }];
        if (!isVerified) response = nil;
    }
    
    // Return content
    return (response ? response : [FwiJson null]);
}
- (FwiJson *)encodeMessage:(FwiJson *)message messageType:(FwiMessageType)messageType {
    /* Condition validation: Validate message type */
    if (!(messageType == kAesUnsign || messageType == kAesSigned)) messageType = kAesUnsign;
    
    /* Condition validation: Validate security provider status */
    FwiSP *provider = [FwiSP sharedInstance];
    if (provider.stage != kSPStage_Ready) {
        DLog(@"[ERROR] Security Provider is not ready!");
        return [FwiJson null];
    }
    
    /* Condition validation: Validate secured session status */
    FwiSS *session = [provider sessionWithPeerHostname:_peerHostname];
    if (session.stage != kSSStage_Ready) {
        DLog(@"[ERROR] Secured session is not ready!");
        return [FwiJson null];
    }
    
    // Encode process
    NSData *encodeMessage = [message encode];
    NSData *iv			  = nil;
    NSData *encryptedData = nil;
    NSData *signatureData = nil;
    
    encryptedData = [session.aesKey encryptData:encodeMessage, nil];
    iv = [session.aesKey iv];
    
    // Encode iv
    FwiJson *jsonIV = [FwiJson object:
                       @"iv", [FwiJson stringWithString:[iv encodeBase64String]],
                       @"hostname", [FwiJson stringWithString:[[provider host] hostname]],
                       @"sessionID", [FwiJson stringWithString:[session ssID]],
                       nil];
    NSData *encodedIV = [session.peerCrt encryptData:[jsonIV encode]];
    
    // Create content
    FwiJson *content = [FwiJson object:
                        @"iv", [FwiJson stringWithString:[encodedIV encodeBase64String]],
                        @"encodeMessage", [FwiJson stringWithString:[encryptedData encodeBase64String]],
                        nil];
    
    // Create signature
    if (messageType == kAesSigned) {
        signatureData = [provider.pvt signData:encodeMessage digest:[provider.crt signatureDigest]];
        [content addKeysAndJsons:@"signatureData", [FwiJson stringWithString:[signatureData encodeBase64String]], nil];
    }
    
    // Create request message
    if (!content) content = [FwiJson null];
    FwiJson *request = [FwiJson object:
                        @"header", [FwiJson object:
                                    @"appVersion" , [FwiJson numberWithInteger:_AppVersion],
                                    @"messageType", [FwiJson numberWithInteger:messageType],
                                    nil],
                        @"content", content,
                        nil];
    return request;
}

- (void)addValidStructures:(FwiJson *)structure, ... NS_REQUIRES_NIL_TERMINATION {
    /* Condition validation */
    if (!structure) return;
    
    va_list structures;
	va_start(structures, structure);
    
    while ((structure = va_arg(structures, FwiJson*))) {
        [_validateStructures addObject:structure];
    }
	va_end(structures);
}


#pragma mark - Class's private methods


@end


@implementation FwiMessenger (FwiMessengerCreation)


#pragma mark - Class's static constructors
+ (FwiMessenger *)messengerWithPeerHostname:(NSString *)peerHostname {
    return FwiAutoRelease([[FwiMessenger alloc] initWithPeerHostname:peerHostname]);
}


#pragma mark - Class's constructors
- (id)initWithPeerHostname:(NSString *)peerHostname {
    self = [self init];
    if (self) {
        _peerHostname = FwiRetain(peerHostname);
    }
    return self;
}


@end