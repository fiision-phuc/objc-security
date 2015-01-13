#import "FwiSecurity.h"
#import "FwiX509Utils_Private.h"


FwiDigest (^FwiDigestWithLength)(NSInteger length) = ^(NSInteger length) {
    switch (length) {
        case 32: {
            return kSHA256;
            break;
        }
        case 48: {
            return kSHA384;
            break;
        }
        case 64: {
            return kSHA512;
            break;
        }
        case 20:
        default: {
            return kSHA1;
            break;
        }
    }
};
FwiDigest (^FwiDigestWithDigestOID)(NSString *digestOID) = ^(NSString *digestOID) {
         if ([digestOID isEqualToString:@"2.16.840.1.101.3.4.2.1"]) return kSHA256;
	else if ([digestOID isEqualToString:@"2.16.840.1.101.3.4.2.2"]) return kSHA384;
	else if ([digestOID isEqualToString:@"2.16.840.1.101.3.4.2.3"]) return kSHA512;
	else return kSHA1;
};
FwiDigest (^FwiDigestWithSignatureOID)(NSString *signatureOID) = ^(NSString *signatureOID) {
         if ([signatureOID isEqualToString:@"1.2.840.113549.1.1.11"]) return kSHA256;
	else if ([signatureOID isEqualToString:@"1.2.840.113549.1.1.12"]) return kSHA384;
	else if ([signatureOID isEqualToString:@"1.2.840.113549.1.1.13"]) return kSHA512;
	else return kSHA1;
};

NSInteger (^FwiLengthWithDigest)(FwiDigest digest) = ^(FwiDigest digest) {
    NSInteger length = 0;
    switch (digest) {
        case kSHA256: {
            length = 32;
            break;
        }
        case kSHA384: {
            length = 48;
            break;
        }
        case kSHA512: {
            length = 64;
            break;
        }
        case kSHA1:
        default: {
            length = 20;
            break;
        }
    }
    return length;
};
NSString* (^FwiDigestOIDWithDigest)(FwiDigest digest) = ^(FwiDigest digest) {
    switch (digest) {
        case kSHA256: {
            return @"2.16.840.1.101.3.4.2.1";
            break;
        }
        case kSHA384: {
            return @"2.16.840.1.101.3.4.2.2";
            break;
        }
        case kSHA512: {
            return @"2.16.840.1.101.3.4.2.3";
            break;
        }
        case kSHA1:
        default: {
            return @"1.3.14.3.2.26";
            break;
        }
    }
};
NSString* (^FwiSignatureOIDWithDigest)(FwiDigest digest) = ^(FwiDigest digest) {
    switch (digest) {
        case kSHA256: {
            return @"1.2.840.113549.1.1.11";
            break;
        }
        case kSHA384: {
            return @"1.2.840.113549.1.1.12";
            break;
        }
        case kSHA512: {
            return @"1.2.840.113549.1.1.13";
            break;
        }
        case kSHA1:
        default: {
            return @"1.2.840.113549.1.1.5";
            break;
        }
    }
};


NSString* (^FwiQueryOID)(NSString *name) = ^(NSString *name) {
    return [FwiX509Utils_Private queryOID:name];
};
NSString* (^FwiQueryName)(NSString *oid) = ^(NSString *oid) {
    return [FwiX509Utils_Private queryName:oid];
};
NSString* (^FwiDescriptionOID)(NSString *oid) = ^(NSString *oid) {
    return [FwiX509Utils_Private descriptionOID:oid];
};

NSDictionary* (^FwiAttributesToDictionary)(FwiDer *attributes) = ^(FwiDer *attributes) {
    return [FwiX509Utils_Private attributesToDictionary:attributes];
};
NSDictionary* (^FwiExtensionsToDictionary)(FwiDer *extensions) = ^(FwiDer *extensions) {
    return [FwiX509Utils_Private extensionsToDictionary:extensions];
};

FwiDer* (^FwiDictionaryToAttributes)(NSDictionary *dictionary) = ^(NSDictionary *dictionary) {
    return [FwiX509Utils_Private dictionaryToAttributes:dictionary];
};
FwiDer* (^FwiDictionaryToExtensions)(NSDictionary *dictionary) = ^(NSDictionary *dictionary) {
    return [FwiX509Utils_Private dictionaryToExtensions:dictionary];
};