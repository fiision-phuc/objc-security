#import "PrivateImpl_FwiRsa.h"


@implementation PrivateImpl_FwiRsa


#pragma mark - Class's static methods
+ (FwiDer *)structure {
    return nil;
}


#pragma mark - Class's constructors
- (id)init {
    self = [super init];
    if (self) {
        _objectIdentifier = @"1.2.840.113549.1.1.1";
        _version = 2;
        
        // Indentify key's attributes
        _attributes[@"asen"] = kValue_N;
        _attributes[kAttr_decr] = kValue_Y;
        _attributes[kAttr_drve] = kValue_Y;
        _attributes[@"extr"] = kValue_Y;
        _attributes[kAttr_klbl] = [@"K3oWETTJGjEui1w+FpWTpoh0dAg=" decodeBase64Data];
        _attributes[@"modi"] = kValue_Y;
        _attributes[@"next"] = kValue_N;
        _attributes[@"priv"] = kValue_Y;
        _attributes[@"sens"] = kValue_N;
        _attributes[kAttr_sign] = kValue_Y;
        _attributes[@"snrc"] = kValue_N;
        _attributes[@"type"] = @42U;
        _attributes[kAttr_unwp] = kValue_Y;
        _attributes[@"vyrc"] = kValue_N;
    }
    return self;
}


#pragma mark - Cleanup memory
- (void)dealloc {
    FwiRelease(_objectIdentifier);

#if !__has_feature(objc_arc)
    [super dealloc];
#endif
}


#pragma mark - Class's properties
- (NSUInteger)version {
    return _version;
}


#pragma mark - Class's public methods
- (NSData *)encode {
    return [[self encodeDER] encode];
}
- (FwiDer *)encodeDER {
    if (![self inKeystore]) return [FwiDer null];
    return [[super encode] decodeDer];
}


@end
