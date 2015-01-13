//  Project name: OAuthStarterKit
//  File name   : FwiOAuthValue.h
//
//  Author      : Phuc, Tran Huu
//  Created date: 8/9/13
//  Version     : 1.00
//  --------------------------------------------------------------
//  Copyright (C) 2013 Trinity 0715. All rights reserved.
//  --------------------------------------------------------------

#import <Foundation/Foundation.h>


@interface FwiOAuthValue : NSObject <NSCoding> {

@private
    NSString *_key;
    NSString *_value;
}

@property (nonatomic, readonly) NSString *key;
@property (nonatomic, readonly) NSString *value;


@end


@interface FwiOAuthValue (FwiOAuthValueCreation)

// Class's static constructors
+ (FwiOAuthValue *)signatureMethod;

+ (FwiOAuthValue *)callbackWithValue:(NSString *)callback;
+ (FwiOAuthValue *)consumerKeyWithValue:(NSString *)consumerKey;
+ (FwiOAuthValue *)nonceWithValue:(NSString *)nonce;
+ (FwiOAuthValue *)realmWithValue:(NSString *)realm;
+ (FwiOAuthValue *)signatureWithValue:(NSString *)signature;
+ (FwiOAuthValue *)timestampWithValue:(NSString *)timestamp;
+ (FwiOAuthValue *)versionWithValue:(NSString *)version;


// Class's constructors
- (id)initWithKey:(NSString *)key andValue:(NSString *)value;

@end