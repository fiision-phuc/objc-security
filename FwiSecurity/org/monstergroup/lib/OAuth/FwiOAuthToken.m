#import "FwiOAuthToken.h"


@interface FwiOAuthToken (Private)

+ (NSString *)settingsKey:(const NSString *)name provider:(const NSString *)provider prefix:(const NSString *)prefix;
+ (id)loadSetting:(const NSString *)name provider:(const NSString *)provider prefix:(const NSString *)prefix;
+ (void)saveSetting:(NSString *)name object:(id)object provider:(const NSString *)provider prefix:(const NSString *)prefix;
+ (NSNumber *)durationWithString:(NSString *)aDuration;
+ (NSDictionary *)attributesWithString:(NSString *)theAttributes;

@end


@implementation FwiOAuthToken


#pragma mark - Class's constructors
- (id)init {
    self = [super init];
    if (self) {
        _token = nil;
        _tokenSecret = nil;
        _session = nil;
        _verifier = nil;
        _duration = nil;
        _attributes = nil;
        _created = nil;
        _renewable = NO;
        _forRenewal = NO;
    }
    return self;
}

- (id)initWithKey:(NSString *)aKey secret:(NSString *)aSecret {
	return [self initWithKey:aKey secret:aSecret session:nil verifier:nil duration:nil
				  attributes:nil created:nil renewable:NO];
}

- (id)initWithKey:(NSString *)aKey 
           secret:(NSString *)aSecret 
          session:(NSString *)aSession
         verifier:(NSString *)aVerifier
		 duration:(NSNumber *)aDuration 
       attributes:(NSDictionary *)theAttributes 
          created:(NSDate *)creation
		renewable:(BOOL)renew 
{
	self = [super init];
    if (self) {
        self.token = aKey;
        self.tokenSecret = aSecret;
        self.session = aSession;
        self.verifier = aVerifier;
        self.duration = aDuration;
        self.attributes = [[NSMutableDictionary alloc] initWithDictionary:theAttributes];
        
        _created = FwiRetain(creation);
        _renewable = renew;
        _forRenewal = NO;
    }
	return self;
}

- (void)setVerifierWithUrl:(NSURL *)aURL
{
    NSString *query = [aURL query];
    NSArray *pairs = [query componentsSeparatedByString:@"&"];
    
	for (NSString *pair in pairs) 
    {
        NSArray *elements = [pair componentsSeparatedByString:@"="];
        if ([[elements objectAtIndex:0] isEqualToString:@"oauth_verifier"]) 
        {
            self.verifier = [elements objectAtIndex:1];
        } 
    }
}

- (id)initWithResponse:(NSString *)response {
    self = [self init];
    if (self) {
//        NSNumber *aDuration = nil;
//        NSDictionary *attrs = nil;

        NSArray *pairs = [response componentsSeparatedByString:@"&"];
        for (NSString *pair in pairs) {
            FwiFormParameter *parameter = [FwiFormParameter decode:pair];

            if ([parameter.key isEqualToString:@"oauth_token"]) {
                _token = FwiRetain(parameter.value);
            }
            else if ([parameter.key isEqualToString:@"oauth_token_secret"]) {
                _tokenSecret = FwiRetain(parameter.value);
            }
            else if ([parameter.key isEqualToString:@"oauth_verifier"]) {
                _verifier = FwiRetain(parameter.value);
            }
            else if ([parameter.key isEqualToString:@"user_id"]) {
                _userId = FwiRetain(parameter.value);
            }
            else if ([parameter.key isEqualToString:@"screen_name"]) {
                _screenName = FwiRetain(parameter.value);
            }
//            else if ([parameter.key isEqualToString:@"oauth_session_handle"]) {
//                _session = [parameter.value retain];
//            }
//            else if ([parameter.key isEqualToString:@"oauth_token_attributes"]) {
//                attrs = [[self class] attributesWithString:[[elements objectAtIndex:1] decodeHTML]];
//            }
//            else if ([parameter.key isEqualToString:@"oauth_token_duration"]) {
//                aDuration = [[self class] durationWithString:[elements objectAtIndex:1]];
//                _created = [[NSDate date] retain];
//            }
//            else if ([parameter.key isEqualToString:@"oauth_token_renewable"]) {
//                if ([parameter.key isEqualToStringIgnoreCase:@"true"] || [parameter.key isEqualToStringIgnoreCase:@"t"]) {
//                    _renewable = YES;
//                }
//                else {
//                    _renewable = NO;
//                }
//            }
        }
    }
    return self;
}

- (id)initWithUserDefaultsUsingServiceProviderName:(const NSString *)provider prefix:(const NSString *)prefix {
	self = [super init];
	self.token = [FwiOAuthToken loadSetting:@"key" provider:provider prefix:prefix];
	self.tokenSecret = [FwiOAuthToken loadSetting:@"secret" provider:provider prefix:prefix];
	self.session = [FwiOAuthToken loadSetting:@"session" provider:provider prefix:prefix];
    self.verifier = [FwiOAuthToken loadSetting:@"verifier" provider:provider prefix:prefix];
	self.duration = [FwiOAuthToken loadSetting:@"duration" provider:provider prefix:prefix];
	self.attributes = [FwiOAuthToken loadSetting:@"attributes" provider:provider prefix:prefix];
    
	_renewable = [[FwiOAuthToken loadSetting:@"renewable" provider:provider prefix:prefix] boolValue];

    FwiRelease(_created);
    _created = [FwiOAuthToken loadSetting:@"created" provider:provider prefix:prefix];
	return self;
}

#pragma mark dealloc

- (void)dealloc {
    self.token = nil;
    self.tokenSecret = nil;
    self.duration = nil;
    self.attributes = nil;

#if !__has_feature(objc_arc)
    [super dealloc];
#endif
}

#pragma mark settings

- (BOOL)isValid {
	return (_token != nil && ![_token isEqualToString:@""] && _tokenSecret != nil && ![_tokenSecret isEqualToString:@""]);
}

- (int)storeInUserDefaultsWithServiceProviderName:(const NSString *)provider prefix:(const NSString *)prefix {
	[FwiOAuthToken saveSetting:@"key" object:_token provider:provider prefix:prefix];
	[FwiOAuthToken saveSetting:@"secret" object:_tokenSecret provider:provider prefix:prefix];
	[FwiOAuthToken saveSetting:@"created" object:_created provider:provider prefix:prefix];
	[FwiOAuthToken saveSetting:@"duration" object:_duration provider:provider prefix:prefix];
	[FwiOAuthToken saveSetting:@"session" object:_session provider:provider prefix:prefix];
    [FwiOAuthToken saveSetting:@"verifier" object:_verifier provider:provider prefix:prefix];
	[FwiOAuthToken saveSetting:@"attributes" object:_attributes provider:provider prefix:prefix];
	[FwiOAuthToken saveSetting:@"renewable" object:_renewable ? @"t" : @"f" provider:provider prefix:prefix];
	
	[[NSUserDefaults standardUserDefaults] synchronize];
	return(0);
}

#pragma mark duration

- (void)setDurationWithString:(NSString *)aDuration {
	self.duration = [[self class] durationWithString:aDuration];
}

- (BOOL)hasExpired
{
	return _created && [_created timeIntervalSinceNow] > [_duration intValue];
}

- (BOOL)isRenewable
{
	return _session && _renewable && _created && [_created timeIntervalSinceNow] < (2 * [_duration intValue]);
}


#pragma mark attributes

- (void)setAttribute:(const NSString *)aKey value:(const NSString *)aAttribute {
	if (!_attributes) {
		_attributes = [[NSMutableDictionary alloc] init];
	}
	[_attributes setObject: aAttribute forKey: aKey];
}

- (void)setAttributes:(NSDictionary *)theAttributes {
	FwiRelease(_attributes);
	if (theAttributes) {
		_attributes = [[NSMutableDictionary alloc] initWithDictionary:theAttributes];
	}else {
		_attributes = nil;
	}
	
}

- (BOOL)hasAttributes {
	return (_attributes && [_attributes count] > 0);
}

- (NSString *)attributeString {
	if (![self hasAttributes]) {
		return @"";
	}
	
	NSMutableArray *chunks = [[NSMutableArray alloc] init];
	for(NSString *aKey in self.attributes) {
		[chunks addObject:[NSString stringWithFormat:@"%@:%@", aKey, [_attributes objectForKey:aKey]]];
	}
	NSString *attrs = [chunks componentsJoinedByString:@";"];
    FwiRelease(chunks);
	return attrs;
}

- (NSString *)attribute:(NSString *)aKey
{
	return [_attributes objectForKey:aKey];
}

- (void)setAttributesWithString:(NSString *)theAttributes
{
	self.attributes = [[self class] attributesWithString:theAttributes];
}

- (NSDictionary *)parameters
{
	NSMutableDictionary *params = [[[NSMutableDictionary alloc] init] autorelease];

	if (_token)
    {
		[params setObject:_token forKey:@"oauth_token"];
		if ([self isForRenewal]) 
        {
			[params setObject:_session forKey:@"oauth_session_handle"];
		}
	} 
    else 
    {
		if (_duration)
        {
			[params setObject:[_duration stringValue] forKey: @"oauth_token_duration"];
		}
		if ([_attributes count])
        {
			[params setObject:[self attributeString] forKey:@"oauth_token_attributes"];
		}
	}
    
    if (_verifier)
    {
        [params setObject:_verifier forKey:@"oauth_verifier"];
    }
	return params;
}

#pragma mark comparisions

- (BOOL)isEqual:(id)object {
	if([object isKindOfClass:[self class]]) {
		return [self isEqualToToken:(FwiOAuthToken *)object];
	}
	return NO;
}

- (BOOL)isEqualToToken:(FwiOAuthToken *)aToken {
	/* Since ScalableOAuth determines that the token may be
	 renewed using the same key and secret, we must also
	 check the creation date */
	if ([self.token isEqualToString:aToken.token] &&
		[self.tokenSecret isEqualToString:aToken.tokenSecret]) {
		/* May be nil */
		if (_created == aToken->_created || [_created isEqualToDate:aToken->_created]) {
			return YES;
		}
	}
	
	return NO;
}
			
#pragma mark class_functions
			
+ (NSString *)settingsKey:(NSString *)name provider:(NSString *)provider prefix:(NSString *)prefix {
	return [NSString stringWithFormat:@"OAUTH_%@_%@_%@", provider, prefix, [name uppercaseString]];
}
			
+ (id)loadSetting:(NSString *)name provider:(NSString *)provider prefix:(NSString *)prefix {
	return [[NSUserDefaults standardUserDefaults] objectForKey:[self settingsKey:name
																		provider:provider
																		  prefix:prefix]];
}
			
+ (void)saveSetting:(NSString *)name object:(id)object provider:(NSString *)provider prefix:(NSString *)prefix {
	[[NSUserDefaults standardUserDefaults] setObject:object forKey:[self settingsKey:name
																			provider:provider
																			  prefix:prefix]];
}
	
+ (void)removeFromUserDefaultsWithServiceProviderName:(NSString *)provider prefix:(NSString *)prefix {
	NSArray *keys = [NSArray arrayWithObjects:@"key", @"secret", @"created", @"duration", @"session", @"verifier", @"attributes", @"renewable", nil];
	for(NSString *name in keys) {
		[[NSUserDefaults standardUserDefaults] removeObjectForKey:[FwiOAuthToken settingsKey:name provider:provider prefix:prefix]];
	}
}
			
+ (NSNumber *)durationWithString:(NSString *)aDuration {
	NSUInteger length = [aDuration length];
	unichar c = toupper([aDuration characterAtIndex:length - 1]);
	int mult;
	if (c >= '0' && c <= '9') {
		return [NSNumber numberWithInt:[aDuration intValue]];
	}
	if (c == 'S') {
		mult = 1;
	} else if (c == 'H') {
		mult = 60 * 60;
	} else if (c == 'D') {
		mult = 60 * 60 * 24;
	} else if (c == 'W') {
		mult = 60 * 60 * 24 * 7;
	} else if (c == 'M') {
		mult = 60 * 60 * 24 * 30;
	} else if (c == 'Y') {
		mult = 60 * 60 * 365;
	} else {
		mult = 1;
	}
	
	return [NSNumber numberWithInt: mult * [[aDuration substringToIndex:length - 1] intValue]];
}

+ (NSDictionary *)attributesWithString:(NSString *)theAttributes {
	NSArray *attrs = [theAttributes componentsSeparatedByString:@";"];
	NSMutableDictionary *dct = [[NSMutableDictionary alloc] init];
	for (NSString *pair in attrs) {
		NSArray *elements = [pair componentsSeparatedByString:@":"];
		[dct setObject:[elements objectAtIndex:1] forKey:[elements objectAtIndex:0]];
	}
	return [dct autorelease];
}

#pragma mark description

- (NSString *)description {
	return [NSString stringWithFormat:@"oauth_token \"%@\" oauth_token_secret \"%@\" oauth_verifier \"%@\"", _token, _tokenSecret, _verifier];
}

@end


@implementation FwiOAuthToken (FwiOAuthTokenCreation)


#pragma mark - Class's static constructors
+ (FwiOAuthToken *)tokenWithResponse:(NSString *)response {
    return [[[FwiOAuthToken alloc] initWithResponse:response] autorelease];
}

@end