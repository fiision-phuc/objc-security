#import "FwiOAuthConsumer.h"


@interface FwiOAuthConsumer () {
}

@end


@implementation FwiOAuthConsumer


@synthesize realm=_realm, apiKey=_apiKey, secretKey=_secretKey;


#pragma mark - Class's constructors
- (id)init {
    self = [super init];
    if (self) {
        _realm             = nil;
        _apiKey            = nil;
        _secretKey         = nil;
        _authorizationCode = nil;
    }
    return self;
}


#pragma mark - Cleanup memory
- (void)dealloc {
    FwiRelease(_realm);
    FwiRelease(_apiKey);
    FwiRelease(_secretKey);
    FwiRelease(_authorizationCode);
    [super dealloc];
}


#pragma mark - Class's properties


#pragma mark - Class's public methods
- (void)_request {
    if (_authorizationCode) {
//    https://www.linkedin.com/uas/oauth2/accessToken?grant_type=authorization_code
//        &code=AUTHORIZATION_CODE
//        &redirect_uri=YOUR_REDIRECT_URI
//        &client_id=YOUR_API_KEY
//        &client_secret=YOUR_SECRET_KEY
//        FwiFormParameter *p1 = [FwiFormParameter parameterWithKey:@"grant_type" andValue:@"authorization_code"];
//        FwiFormParameter *p2 = [FwiFormParameter parameterWithKey:@"code" andValue:_authorizationCode];
//        FwiFormParameter *p3 = [FwiFormParameter parameterWithKey:@"redirect_uri" andValue:_realm];
//        FwiFormParameter *p4 = [FwiFormParameter parameterWithKey:@"client_id" andValue:_apiKey];
//        FwiFormParameter *p5 = [FwiFormParameter parameterWithKey:@"client_secret" andValue:_secretKey];
//        NSArray *array = @[p1,p2,p3,p4,p5];
//        NSString *params = [array componentsJoinedByString:@"&"];
//
//        FwiService *net = [FwiService netWithURL:[NSURL URLWithString:[NSString stringWithFormat:@"%@?%@", @"https://www.linkedin.com/uas/oauth2/accessToken", params]]
//                                  method:kHTTPRequest_MethodPOST
//                           requestString:nil];
//        [net executeWithCompletion:^(NSData *responseData, FwiJson *responseMessage) {
//            DLog(@"%@", [responseData toString]);
//        }];
    }
}
- (void)updateAuthorization:(NSString *)redirectURI {
    NSRange  range  = [redirectURI rangeOfString:[NSString stringWithFormat:@"%@/?", _realm]];
    NSString *info  = [redirectURI substringFromIndex:(range.location + range.length)];

    // Parse autorization code
    NSArray *array = [info componentsSeparatedByString:@"&"];
    [array enumerateObjectsUsingBlock:^(NSString *token, NSUInteger idx, BOOL *stop) {
        FwiFormParameter *parameter = [FwiFormParameter decode:token];
        if (parameter) {
            if ([parameter.key isEqualToStringIgnoreCase:@"code"]) {
                _authorizationCode = [parameter.value retain];
            }
            else if ([parameter.key isEqualToStringIgnoreCase:@"state"]) {
                DLog(@"%@", parameter.value);
            }
        }
    }];

    

    [self performSelector:@selector(_request) withObject:nil afterDelay:15.0f];
}


#pragma mark - Class's private methods


#pragma mark - Class's notification handlers


#pragma mark - NSCoding's members
- (id)initWithCoder:(NSCoder *)aDecoder {
    self = [self init];
    if (self && aDecoder) {
        _realm     = [[aDecoder decodeObjectForKey:@"_realm"] retain];
        _apiKey    = [[aDecoder decodeObjectForKey:@"_apiKey"] retain];
        _secretKey = [[aDecoder decodeObjectForKey:@"_secretKey"] retain];
    }
    return self;
}
- (void)encodeWithCoder:(NSCoder *)aCoder {
    if (!aCoder) return;
    [aCoder encodeObject:_realm forKey:@"_realm"];
    [aCoder encodeObject:_apiKey forKey:@"_apiKey"];
    [aCoder encodeObject:_secretKey forKey:@"_secretKey"];
}


@end


@implementation FwiOAuthConsumer (FwiOAuthConsumerCreation)


#pragma mark - Class's static constructors
+ (FwiOAuthConsumer *)consumerWithRealm:(NSString *)realm apiKey:(NSString *)apiKey secretKey:(NSString *)secretKey {
    return [[[FwiOAuthConsumer alloc] initWithRealm:realm apiKey:apiKey secretKey:secretKey] autorelease];
}


#pragma mark - Class's constructors
- (id)initWithRealm:(NSString *)realm apiKey:(NSString *)apiKey secretKey:(NSString *)secretKey {
    self = [self init];
    if (self) {
        _realm     = [realm retain];
        _apiKey    = [apiKey retain];
        _secretKey = [secretKey retain];
    }
    return self;
}


@end