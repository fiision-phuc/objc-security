#import "FwiOAuthValue.h"


@interface FwiOAuthValue () {
}

@end


@implementation FwiOAuthValue


#pragma mark - Class's constructors
- (id)init {
    self = [super init];
    if (self) {
        _key   = nil;
        _value = nil;
    }
    return self;
}


#pragma mark - Cleanup memory
- (void)dealloc {
    FwiRelease(_key);
    FwiRelease(_value);
    [super dealloc];
}


#pragma mark - Class's override methods
- (BOOL)isEqual:(id)object {
	if ([object isKindOfClass:[FwiOAuthValue class]]) {
        FwiOAuthValue *other = (FwiOAuthValue *)object;
        return ([_key isEqualToString:other.key] && [_value isEqualToString:other.value]);
	}
	return NO;
}

- (NSString *)description {
    return [NSString stringWithFormat:@"%@=\"%@\"", _key, [_value encodeHTML]];
}


#pragma mark - Class's properties


#pragma mark - Class's public methods


#pragma mark - Class's private methods


#pragma mark - Class's notification handlers


#pragma mark - NSCoding's members
- (id)initWithCoder:(NSCoder *)aDecoder {
    self = [self init];
    if (self && aDecoder) {
        _key   = [[aDecoder decodeObjectForKey:@"_key"] retain];
        _value = [[aDecoder decodeObjectForKey:@"_value"] retain];
    }
    return self;
}
- (void)encodeWithCoder:(NSCoder *)aCoder {
    if (!aCoder) return;
    [aCoder encodeObject:_key forKey:@"_key"];
    [aCoder encodeObject:_value forKey:@"_value"];
}


@end


@implementation FwiOAuthValue (FwiOAuthValueCreation)


#pragma mark - Class's static constructors
+ (FwiOAuthValue *)signatureMethod {
    return [[[FwiOAuthValue alloc] initWithKey:@"oauth_signature_method" andValue:@"HMAC-SHA1"] autorelease];
}


+ (FwiOAuthValue *)callbackWithValue:(NSString *)callback {
    return [[[FwiOAuthValue alloc] initWithKey:@"oauth_callback" andValue:callback] autorelease];
}
+ (FwiOAuthValue *)consumerKeyWithValue:(NSString *)consumerKey {
    return [[[FwiOAuthValue alloc] initWithKey:@"oauth_consumer_key" andValue:consumerKey] autorelease];
}
+ (FwiOAuthValue *)nonceWithValue:(NSString *)nonce {
    return [[[FwiOAuthValue alloc] initWithKey:@"oauth_nonce" andValue:nonce] autorelease];
}
+ (FwiOAuthValue *)realmWithValue:(NSString *)realm {
    return [[[FwiOAuthValue alloc] initWithKey:@"realm" andValue:realm] autorelease];
}
+ (FwiOAuthValue *)signatureWithValue:(NSString *)signature {
    return [[[FwiOAuthValue alloc] initWithKey:@"oauth_signature" andValue:signature] autorelease];
}
+ (FwiOAuthValue *)timestampWithValue:(NSString *)timestamp {
    return [[[FwiOAuthValue alloc] initWithKey:@"oauth_timestamp" andValue:timestamp] autorelease];
}
+ (FwiOAuthValue *)versionWithValue:(NSString *)version {
    return [[[FwiOAuthValue alloc] initWithKey:@"oauth_version" andValue:version] autorelease];
}


#pragma mark - Class's constructors
- (id)initWithKey:(NSString *)key andValue:(NSString *)value {
    self = [self init];
    if (self) {
        _key   = [key retain];
        _value = [value retain];
    }
    return self;
}


@end