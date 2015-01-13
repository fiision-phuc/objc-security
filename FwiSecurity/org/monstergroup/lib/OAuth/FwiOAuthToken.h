#import <Foundation/Foundation.h>


@interface FwiOAuthToken : NSObject {

@private
	NSDate *_created;
	BOOL _renewable;
	BOOL _forRenewal;
}

@property (nonatomic, retain) NSString *token;
@property (nonatomic, retain) NSString *tokenSecret;

@property (nonatomic, retain) NSString *userId;
@property (nonatomic, retain) NSString *screenName;

@property(nonatomic, retain) NSString *session;
@property(nonatomic, retain) NSString *verifier;
@property(nonatomic, retain) NSNumber *duration;
@property(nonatomic, retain) NSMutableDictionary *attributes;
@property(nonatomic, assign, getter=isForRenewal) BOOL forRenewal;

- (id)initWithKey:(NSString *)aKey secret:(NSString *)aSecret;
- (id)initWithKey:(NSString *)aKey 
           secret:(NSString *)aSecret 
          session:(NSString *)aSession
         verifier:(NSString *)aVerifier
		 duration:(NSNumber *)aDuration 
       attributes:(NSDictionary *)theAttributes 
          created:(NSDate *)creation
		renewable:(BOOL)renew;

- (id)initWithResponse:(NSString *)response;

- (id)initWithUserDefaultsUsingServiceProviderName:(NSString *)provider prefix:(NSString *)prefix;
- (int)storeInUserDefaultsWithServiceProviderName:(NSString *)provider prefix:(NSString *)prefix;

- (BOOL)isValid;

- (void)setAttribute:(NSString *)aKey value:(NSString *)aValue;
- (NSString *)attribute:(NSString *)aKey;
- (void)setAttributesWithString:(NSString *)aAttributes;
- (NSString *)attributeString;

- (BOOL)hasExpired;
- (BOOL)isRenewable;
- (void)setDurationWithString:(NSString *)aDuration;
- (void)setVerifierWithUrl:(NSURL *)aURL;
- (BOOL)hasAttributes;
- (NSDictionary *)parameters;

- (BOOL)isEqualToToken:(FwiOAuthToken *)aToken;

+ (void)removeFromUserDefaultsWithServiceProviderName:(const NSString *)provider prefix:(const NSString *)prefix;

@end


@interface FwiOAuthToken (FwiOAuthTokenCreation)

// Class's static constructors
+ (FwiOAuthToken *)tokenWithResponse:(NSString *)response;

@end
