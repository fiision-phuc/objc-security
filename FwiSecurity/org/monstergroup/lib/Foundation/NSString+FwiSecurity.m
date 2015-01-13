#import "NSString+FwiSecurity.h"


@implementation NSString (FwiSecurity)


- (NSString *)parsePEM {
    /* Condition validation */
    if (!self || self.length == 0) return @"";

    NSMutableString *builder = [[NSMutableString alloc] initWithString:self];
    [builder replaceOccurrencesOfString:@"-----[A-Z]+(\\s[A-Z]+)*-----" withString:@""
                                options:(NSRegularExpressionSearch|NSCaseInsensitiveSearch)
                                  range:NSMakeRange(0, self.length)];
    
    NSString *result = [NSString stringWithFormat:@"%@", [builder description]];
    FwiRelease(builder);
    return result;
}
- (NSData *)hmachash:(FwiHmacHash)algorithm salt:(NSString *)salt {
    /* Condition validation */
    if (!self || self.length <= 0 || !salt || salt.length <= 0) return nil;

    // Convert to C string
    NSData *key  = [salt toData];
    NSData *data = [self toData];

    // Identify length
    size_t length = 0;
    switch (algorithm) {
        case kHmacHash_256: {
            length = CC_SHA256_DIGEST_LENGTH;
            break;
        }
        case kHmacHash_384: {
            length = CC_SHA384_DIGEST_LENGTH;
            break;
        }
        case kHmacHash_512: {
            length = CC_SHA512_DIGEST_LENGTH;
            break;
        }
        default:
            length = CC_SHA1_DIGEST_LENGTH;
            break;
    }
    unsigned char hmac[length];

    CCHmac(algorithm, key.bytes, key.length, data.bytes, data.length, hmac);
    NSData *result = [NSData dataWithBytes:hmac length:length];
    return result;
}


@end
