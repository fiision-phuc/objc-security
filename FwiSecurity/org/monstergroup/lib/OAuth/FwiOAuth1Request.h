#import <Foundation/Foundation.h>


@interface FwiOAuth1Request : FwiRequest {

@private
    FwiOAuthConsumer *_consumer;
    FwiOAuthToken    *_token;
}

@property(nonatomic, readonly) NSString *nonce;
@property(nonatomic, readonly) NSString *signature;
@property(nonatomic, readonly) NSString *timestamp;

@end


@interface FwiOAuth1Request (FwiOAuth1RequestCreation)

// Class's static constructors
+ (FwiOAuth1Request *)requestWithURL:(NSURL *)url consumer:(FwiOAuthConsumer *)consumer token:(FwiOAuthToken *)token;

// Class's constructors
- (id)initWithURL:(NSURL *)url consumer:(FwiOAuthConsumer *)consumer token:(FwiOAuthToken *)token;

@end