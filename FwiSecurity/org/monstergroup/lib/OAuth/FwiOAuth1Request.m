#import "FwiOAuth1Request.h"


@interface FwiOAuth1Request () {
}


/**
 * Create sign data
 */
- (NSString *)_signData;

@end

@implementation FwiOAuth1Request


@synthesize nonce=_nonce, signature=_signature, timestamp=_timestamp;


#pragma mark - Cleanup memory
- (void) dealloc {
    FwiRelease(_consumer);
    FwiRelease(_token);
    FwiRelease(_nonce);
    FwiRelease(_signature);
    FwiRelease(_timestamp);

#if !__has_feature(objc_arc)
    [super dealloc];
#endif
}


#pragma mark - Class's override methods
- (size_t)prepare {
    @autoreleasepool {
        // Sign the request
        NSString *secret = [NSString stringWithFormat:@"%@&%@", _consumer.secretKey, (_token ? _token.tokenSecret : @"")];

        NSString *signData = [self _signData];
        _signature = FwiRetain([[signData hmachash:kHmacHash_1 salt:secret] encodeBase64String]);

        // OAuth header components
        NSMutableArray *values = [NSMutableArray arrayWithCapacity:(7 + _token.parameters.count)];
        [values addObject:[FwiOAuthValue realmWithValue:_consumer.realm]];

        [values addObject:[FwiOAuthValue consumerKeyWithValue:_consumer.apiKey]];
        for (NSString *key in [_token parameters]) {
            FwiOAuthValue *value = [[FwiOAuthValue alloc] initWithKey:key andValue:[[_token parameters] objectForKey:key]];
            [values addObject:value];
            FwiRelease(value);
        }
        
        [values addObject:[FwiOAuthValue signatureMethod]];
        [values addObject:[FwiOAuthValue signatureWithValue:_signature]];
        [values addObject:[FwiOAuthValue timestampWithValue:_timestamp]];
        [values addObject:[FwiOAuthValue nonceWithValue:_nonce]];
        [values addObject:[FwiOAuthValue versionWithValue:@"1.0"]];

        // Construct OAuth header
        NSString *oauthHeader = [NSString stringWithFormat:@"OAuth %@", [values componentsJoinedByString:@", "]];
        [self setValue:oauthHeader forHTTPHeaderField:@"Authorization"];
    }
    return [super prepare];
}


#pragma mark - Class's private methods
- (NSString *)_signData {
    NSDictionary *tokenParameters = [_token parameters];
    __block NSMutableArray *pairs = [NSMutableArray arrayWithCapacity:(5 + _params.count + tokenParameters.count)];

	[pairs addObject:[FwiFormParameter parameterWithKey:@"oauth_consumer_key" andValue:_consumer.apiKey]];
    [pairs addObject:[FwiFormParameter parameterWithKey:@"oauth_signature_method" andValue:@"HMAC-SHA1"]];
    [pairs addObject:[FwiFormParameter parameterWithKey:@"oauth_timestamp" andValue:_timestamp]];
    [pairs addObject:[FwiFormParameter parameterWithKey:@"oauth_nonce" andValue:_nonce]];
    [pairs addObject:[FwiFormParameter parameterWithKey:@"oauth_version" andValue:@"1.0"]];

    [tokenParameters enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSString *value, BOOL *stop) {
        [pairs addObject:[FwiFormParameter parameterWithKey:key andValue:value]];
    }];

    if (![[self valueForHTTPHeaderField:@"Content-Type"] hasPrefix:@"multipart/form-data"]) {
        [_params enumerateObjectsUsingBlock:^(FwiFormParameter *parameter, NSUInteger idx, BOOL *stop) {
            if (![pairs containsObject:parameter]) [pairs addObject:parameter];
        }];
	}
    [pairs sortUsingSelector:@selector(compare:)];
    
    NSString *normalized = [pairs componentsJoinedByString:@"&"];
    return [NSString stringWithFormat:@"%@&%@&%@", self.HTTPMethod, [[self.URL absoluteString] encodeHTML], [normalized encodeHTML]];
}


@end


@implementation FwiOAuth1Request (FwiOAuth1RequestCreation)


#pragma mark - Class's static constructors
+ (FwiOAuth1Request *)requestWithURL:(NSURL *)url consumer:(FwiOAuthConsumer *)consumer token:(FwiOAuthToken *)token {
    return FwiAutoRelease([[FwiOAuth1Request alloc] initWithURL:url consumer:consumer token:token]);
}


#pragma mark - Class's constructors
- (id)initWithURL:(NSURL *)url consumer:(FwiOAuthConsumer *)consumer token:(FwiOAuthToken *)token {
    self = [super initWithURL:url];
    if (self) {
        _consumer  = FwiRetain(consumer);
        _timestamp = FwiRetain([NSString timestamp]);
        _nonce     = FwiRetain([NSString randomIdentifier]);

        if (!token) _token = nil;
        else _token = FwiRetain(token);
    }
    return self;
}


@end