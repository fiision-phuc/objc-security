//  Project name: FwiData
//  File name   : FwiOAuthConsumer.h
//
//  Author      : Phuc, Tran Huu
//  Created date: 8/4/13
//  Version     : 1.00
//  --------------------------------------------------------------
//  Copyright (C) 2013 Trinity 0715. All rights reserved.
//  --------------------------------------------------------------

#import <Foundation/Foundation.h>


@interface FwiOAuthConsumer : NSObject <NSCoding> {

@private
    NSString *_realm;
    NSString *_apiKey;
    NSString *_secretKey;

    __block NSString *_authorizationCode;
}

@property (nonatomic, readonly) NSString *realm;
@property (nonatomic, readonly) NSString *apiKey;
@property (nonatomic, readonly) NSString *secretKey;

@property (nonatomic, readonly) NSString *authorizationCode;


/**
 * Set authorization code when redirect uri was called.
 */
- (void)updateAuthorization:(NSString *)redirectURI;

@end


@interface FwiOAuthConsumer (FwiOAuthConsumerCreation)

// Class's static constructors
+ (FwiOAuthConsumer *)consumerWithRealm:(NSString *)realm apiKey:(NSString *)apiKey secretKey:(NSString *)secretKey;

// Class's constructors
- (id)initWithRealm:(NSString *)realm apiKey:(NSString *)apiKey secretKey:(NSString *)secretKey;

@end