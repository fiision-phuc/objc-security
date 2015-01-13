#import "FwiX509Utils_Private.h"


@interface FwiX509Utils_Private () {
}

@end


@implementation FwiX509Utils_Private


static NSDictionary *_pkcs1 = nil;
static NSDictionary *_attributeType = nil;
static NSDictionary *_extendedKeyUsage = nil;
static NSDictionary *_certificateExtension = nil;


+ (void)initialize {
    if (!_pkcs1) {
        NSDictionary *temp = @{@"rsaEncryption"          :@"1.2.840.113549.1.1.1",
                               @"id-RSASSA-PSS"          :@"1.2.840.113549.1.1.10",
                               @"sha256WithRSAEncryption":@"1.2.840.113549.1.1.11",
                               @"sha384WithRSAEncryption":@"1.2.840.113549.1.1.12",
                               @"sha512WithRSAEncryption":@"1.2.840.113549.1.1.13",
                               @"sha224WithRSAEncryption":@"1.2.840.113549.1.1.14",
                               @"md2WithRSAEncryption"   :@"1.2.840.113549.1.1.2",
                               @"md4withRSAEncryption"   :@"1.2.840.113549.1.1.3",
                               @"md5WithRSAEncryption"   :@"1.2.840.113549.1.1.4",
                               @"sha1-with-rsa-signature":@"1.2.840.113549.1.1.5",
                               @"rsaOAEPEncryptionSET"   :@"1.2.840.113549.1.1.6",
                               @"id-RSAES-OAEP"          :@"1.2.840.113549.1.1.7",
                               @"id-mgf1"                :@"1.2.840.113549.1.1.8",
                               @"id-pSpecified"          :@"1.2.840.113549.1.1.9"};
        _pkcs1 = FwiRetain(temp);
    }

    if (!_attributeType) {
        NSDictionary *temp = @{@"objectClass"                       :@"2.5.4.0",
                               @"aliasedEntryName"                  :@"2.5.4.1",
                               @"organizationName"                  :@"2.5.4.10",
                               @"organizationUnitName"              :@"2.5.4.11",
                               @"title"                             :@"2.5.4.12",
                               @"description"                       :@"2.5.4.13",
                               @"searchGuide"                       :@"2.5.4.14",
                               @"businessCategory"                  :@"2.5.4.15",
                               @"postalAddress"                     :@"2.5.4.16",
                               @"postalCode"                        :@"2.5.4.17",
                               @"postOfficeBox"                     :@"2.5.4.18",
                               @"physicalDeliveryOfficeName"        :@"2.5.4.19",
                               @"knowledgeInformation"              :@"2.5.4.2",
                               @"telephoneNumber"                   :@"2.5.4.20",
                               @"telexNumber"                       :@"2.5.4.21",
                               @"teletexTerminalIdentifier"         :@"2.5.4.22",
                               @"facsimileTelephoneNumber"          :@"2.5.4.23",
                               @"x121Address"                       :@"2.5.4.24",
                               @"internationalISDNNumber"           :@"2.5.4.25",
                               @"registeredAddress"                 :@"2.5.4.26",
                               @"destinationIndicator"              :@"2.5.4.27",
                               @"preferredDeliveryMethod"           :@"2.5.4.28",
                               @"presentationAddress"               :@"2.5.4.29",
                               @"commonName"                        :@"2.5.4.3",
                               @"supportedApplicationContext"       :@"2.5.4.30",
                               @"member"                            :@"2.5.4.31",
                               @"owner"                             :@"2.5.4.32",
                               @"roleOccupant"                      :@"2.5.4.33",
                               @"seeAlso"                           :@"2.5.4.34",
                               @"userPassword"                      :@"2.5.4.35",
                               @"userCertificate"                   :@"2.5.4.36",
                               @"cAcertificate"                     :@"2.5.4.37",
                               @"authorityRevocationList"           :@"2.5.4.38",
                               @"certificateRevocationList"         :@"2.5.4.39",
                               @"surname"                           :@"2.5.4.4",
                               @"crossCertificatePair"              :@"2.5.4.40",
                               @"name"                              :@"2.5.4.41",
                               @"givenName"                         :@"2.5.4.42",
                               @"initials"                          :@"2.5.4.43",
                               @"generationQualifier"               :@"2.5.4.44",
                               @"uniqueIdentifier"                  :@"2.5.4.45",
                               @"dnQualifier"                       :@"2.5.4.46",
                               @"enhancedSearchGuide"               :@"2.5.4.47",
                               @"protocolInformation"               :@"2.5.4.48",
                               @"distinguishedName"                 :@"2.5.4.49",
                               @"serialNumber"                      :@"2.5.4.5",
                               @"uniqueMember"                      :@"2.5.4.50",
                               @"houseIdentifier"                   :@"2.5.4.51",
                               @"supportedAlgorithms"               :@"2.5.4.52",
                               @"deltaRevocationList"               :@"2.5.4.53",
                               @"dmdName"                           :@"2.5.4.54",
                               @"clearance"                         :@"2.5.4.55",
                               @"defaultDirQop"                     :@"2.5.4.56",
                               @"attributeIntegrityInfo"            :@"2.5.4.57",
                               @"attributeCertificate"              :@"2.5.4.58",
                               @"attributeCertificateRevocationList":@"2.5.4.59",
                               @"countryName"                       :@"2.5.4.6",
                               @"confKeyInfo"                       :@"2.5.4.60",
                               @"aACertificate"                     :@"2.5.4.61",
                               @"attributeDescriptorCertificate"    :@"2.5.4.62",
                               @"attributeAuthorityRevocationList"  :@"2.5.4.63",
                               @"family-information"                :@"2.5.4.64",
                               @"pseudonym"                         :@"2.5.4.65",
                               @"communicationsService"             :@"2.5.4.66",
                               @"communicationsNetwork"             :@"2.5.4.67",
                               @"certificationPracticeStmt"         :@"2.5.4.68",
                               @"certificatePolicy"                 :@"2.5.4.69",
                               @"localityName"                      :@"2.5.4.7",
                               @"pkiPath"                           :@"2.5.4.70",
                               @"privPolicy"                        :@"2.5.4.71",
                               @"role"                              :@"2.5.4.72",
                               @"delegationPath"                    :@"2.5.4.73",
                               @"id-at-protPrivPolicy"              :@"2.5.4.74",
                               @"id-at-xMLPrivilegeInfo"            :@"2.5.4.75",
                               @"xmlPrivPolicy"                     :@"2.5.4.76",
                               @"uuidpair"                          :@"2.5.4.77",
                               @"stateOrProvinceName"               :@"2.5.4.8",
                               @"streetAddress"                     :@"2.5.4.9",
                               @"CN"                                :@"2.5.4.3",
                               @"SN"                                :@"2.5.4.5",
                               @"C"                                 :@"2.5.4.6",
                               @"L"                                 :@"2.5.4.7",
                               @"ST"                                :@"2.5.4.8",
                               @"STREET"                            :@"2.5.4.9",
                               @"O"                                 :@"2.5.4.10",
                               @"OU"                                :@"2.5.4.11",
                               @"T"                                 :@"2.5.4.12",
                               @"NAME"                              :@"2.5.4.41",
                               @"GIVENNAME"                         :@"2.5.4.42",
                               @"INITIALS"                          :@"2.5.4.43",
                               @"GENERATION"                        :@"2.5.4.44",
                               @"DNQ"                               :@"2.5.4.46",
                               @"DN"                                :@"2.5.4.49",
                               @"EMAIL"                             :@"1.2.840.113549.1.9.1",
                               @"DC"                                :@"0.9.2342.19200300.100.1.25",
                               @"UID"                               :@"0.9.2342.19200300.100.1.1"};
        _attributeType = FwiRetain(temp);
    }

    if (!_extendedKeyUsage) {
        NSDictionary *temp = @{@"serverAuth"             :@"1.3.6.1.5.5.7.3.1",
                               @"dvcs"                   :@"1.3.6.1.5.5.7.3.10",
                               @"sbgpCertAAServerAuth"   :@"1.3.6.1.5.5.7.3.11",
                               @"id-kp-scvp-responder"   :@"1.3.6.1.5.5.7.3.12",
                               @"id-kp-eapOverPPP"       :@"1.3.6.1.5.5.7.3.13",
                               @"id-kp-eapOverLAN"       :@"1.3.6.1.5.5.7.3.14",
                               @"id-kp-scvpServer"       :@"1.3.6.1.5.5.7.3.15",
                               @"id-kp-scvpClient"       :@"1.3.6.1.5.5.7.3.16",
                               @"id-kp-ipsecIKE"         :@"1.3.6.1.5.5.7.3.17",
                               @"id-kp-capwapAC"         :@"1.3.6.1.5.5.7.3.18",
                               @"id-kp-capwapWTP"        :@"1.3.6.1.5.5.7.3.19",
                               @"clientAuth"             :@"1.3.6.1.5.5.7.3.2",
                               @"id-kp-sipDomain"        :@"1.3.6.1.5.5.7.3.20",
                               @"id-kp-secureShellClient":@"1.3.6.1.5.5.7.3.21",
                               @"id-kp-secureShellServer":@"1.3.6.1.5.5.7.3.22",
                               @"id-kp-sendRouter"       :@"1.3.6.1.5.5.7.3.23",
                               @"id-kp-sendProxy"        :@"1.3.6.1.5.5.7.3.24",
                               @"id-kp-sendOwner"        :@"1.3.6.1.5.5.7.3.25",
                               @"codeSigning"            :@"1.3.6.1.5.5.7.3.3",
                               @"emailProtection"        :@"1.3.6.1.5.5.7.3.4",
                               @"ipsecEndSystem"         :@"1.3.6.1.5.5.7.3.5",
                               @"ipsecTunnel"            :@"1.3.6.1.5.5.7.3.6",
                               @"ipsecUser"              :@"1.3.6.1.5.5.7.3.7",
                               @"timeStamping"           :@"1.3.6.1.5.5.7.3.8",
                               @"ocspSigning"            :@"1.3.6.1.5.5.7.3.9"};
        _extendedKeyUsage = FwiRetain(temp);
    }

    if (!_certificateExtension) {
        NSDictionary *temp = @{@"authorityKeyIdentifier"          :@"2.5.29.1",
                               @"basicConstraints"                :@"2.5.29.10",
                               @"subjectKeyIdentifier"            :@"2.5.29.14",
                               @"keyUsage"                        :@"2.5.29.15",
                               @"privateKeyUsagePeriod"           :@"2.5.29.16",
                               @"subjectAltName2"                 :@"2.5.29.17",
                               @"issuerAltName2"                  :@"2.5.29.18",
                               @"basicConstraints2"               :@"2.5.29.19",
                               @"keyAttributes"                   :@"2.5.29.2",
                               @"cRLNumber"                       :@"2.5.29.20",
                               @"reasonCode"                      :@"2.5.29.21",
                               @"expirationDate"                  :@"2.5.29.22",
                               @"instructionCode"                 :@"2.5.29.23",
                               @"invalidityDate"                  :@"2.5.29.24",
                               @"cRLDistributionPoints"           :@"2.5.29.25",
                               @"issuingDistributionPoint"        :@"2.5.29.26",
                               @"deltaCRLIndicator"               :@"2.5.29.27",
                               @"issuingDistributionPoint2"       :@"2.5.29.28",
                               @"certificateIssuer"               :@"2.5.29.29",
                               @"certificatePolicies"             :@"2.5.29.3",
                               @"nameConstraints"                 :@"2.5.29.30",
                               @"cRLDistributionPoints2"          :@"2.5.29.31",
                               @"certificatePolicies2"            :@"2.5.29.32",
                               @"policyMappings2"                 :@"2.5.29.33",
                               @"policyConstraints"               :@"2.5.29.34",
                               @"authorityKeyIdentifier2"         :@"2.5.29.35",
                               @"policyConstraints2"              :@"2.5.29.36",
                               @"extKeyUsage"                     :@"2.5.29.37",
                               @"authorityAttributeIdentifier"    :@"2.5.29.38",
                               @"roleSpecCertIdentifier"          :@"2.5.29.39",
                               @"keyUsageRestriction"             :@"2.5.29.4",
                               @"cRLStreamIdentifier"             :@"2.5.29.40",
                               @"basicAttConstraints"             :@"2.5.29.41",
                               @"delegatedNameConstraints"        :@"2.5.29.42",
                               @"timeSpecification"               :@"2.5.29.43",
                               @"cRLScope"                        :@"2.5.29.44",
                               @"statusReferrals"                 :@"2.5.29.45",
                               @"freshestCRL"                     :@"2.5.29.46",
                               @"orderedList"                     :@"2.5.29.47",
                               @"attributeDescriptor"             :@"2.5.29.48",
                               @"userNotice"                      :@"2.5.29.49",
                               @"policyMapping"                   :@"2.5.29.5",
                               @"sOAIdentifier"                   :@"2.5.29.50",
                               @"baseUpdateTime"                  :@"2.5.29.51",
                               @"acceptableCertPolicies"          :@"2.5.29.52",
                               @"deltaInfo"                       :@"2.5.29.53",
                               @"inhibitAnyPolicy"                :@"2.5.29.54",
                               @"targetInformation"               :@"2.5.29.55",
                               @"noRevAvail"                      :@"2.5.29.56",
                               @"acceptablePrivilegePolicies"     :@"2.5.29.57",
                               @"id-ce-toBeRevoked"               :@"2.5.29.58",
                               @"id-ce-RevokedGroups"             :@"2.5.29.59",
                               @"subtreesConstraint"              :@"2.5.29.6",
                               @"id-ce-expiredCertsOnCRL"         :@"2.5.29.60",
                               @"indirectIssuer"                  :@"2.5.29.61",
                               @"id-ce-noAssertion"               :@"2.5.29.62",
                               @"id-ce-aAissuingDistributionPoint":@"2.5.29.63",
                               @"id-ce-issuedOnBehaIFOF"          :@"2.5.29.64",
                               @"subjectAltName"                  :@"2.5.29.7",
                               @"issuerAltName"                   :@"2.5.29.8",
                               @"subjectDirectoryAttributes"      :@"2.5.29.9"};
        _certificateExtension = FwiRetain(temp);
    }
}


#pragma mark - Class's static methods
+ (NSString *)queryOID:(NSString *)name {
    /* Condition validation */
    if (!name|| name.length == 0) return @"";
    NSString *oid = nil;
    
    if (_pkcs1[name]) {
        oid = _pkcs1[name];
    }
    else if (_attributeType[name]) {
        oid = _attributeType[name];
    }
    else if (_extendedKeyUsage[name]) {
        oid = _extendedKeyUsage[name];
    }
    else if (_certificateExtension[name]) {
        oid = _certificateExtension[name];
    }
    return (oid ? oid : @"");
}
+ (NSString *)queryName:(NSString *)oid {
    /* Condition validation */
    if (!oid|| oid.length == 0) return @"";
    NSString *name = nil;
    
    // Find the right value collections
    NSArray *c1 = [_pkcs1 allValues];
    NSArray *c2 = [_attributeType allValues];
    NSArray *c3 = [_extendedKeyUsage allValues];
    NSArray *c4 = [_certificateExtension allValues];
    
    if ([c1 containsObject:oid]) {
        name = [_pkcs1 allKeys][[c1 indexOfObject:oid]];
    }
    else if ([c2 containsObject:oid]) {
        name = [_attributeType allKeys][[c2 indexOfObject:oid]];
    }
    else if ([c3 containsObject:oid]) {
        name = [_extendedKeyUsage allKeys][[c3 indexOfObject:oid]];
    }
    else if ([c4 containsObject:oid]) {
        name = [_certificateExtension allKeys][[c4 indexOfObject:oid]];
    }
        
    return (name ? name : @"");
}
+ (NSString *)descriptionOID:(NSString *)oid {
    /* Condition validation */
    if (!oid|| oid.length == 0) return @"";
    
    NSString *name = [FwiX509Utils_Private queryName:oid];
    return [NSString stringWithFormat:@"%@ (%@)", oid, name];
}

+ (NSDictionary *)attributesToDictionary:(FwiDer *)attributes {
    /* Condition validation */
    if (!attributes || ![attributes isLike:[FwiDer sequence]]) return nil;
    FwiDer *elementValidation1 = [FwiDer set:
                                  [FwiDer sequence:
                                   [FwiDer objectIdentifier],
                                   [FwiDer printableString],
                                   nil],
                                  nil];
    FwiDer *elementValidation2 = [FwiDer set:
                                  [FwiDer sequence:
                                   [FwiDer objectIdentifier],
                                   [FwiDer ia5String],
                                   nil],
                                  nil];

    NSMutableDictionary *dictionary = [NSMutableDictionary dictionaryWithCapacity:[attributes count]];
    for	(NSUInteger i = 0; i < [attributes count]; i++) {
        /* Condition validation: Validate element structure */
        FwiDer *attribute = [attributes derAtIndex:i];
        if (!([attribute isLike:elementValidation1] || [attribute isLike:elementValidation2])) continue;
        
        /* Condition validation: Validate oID */
        NSString *oid = [[attribute derWithPath:@"0/0"] getString];
        if (!oid || oid.length == 0) continue;
        
        NSString *value = [[attribute derWithPath:@"0/1"] getString];
        NSString *name  = [FwiX509Utils_Private queryName:oid];
        dictionary[name] = value;
    }
    return dictionary;
}
+ (NSDictionary *)extensionsToDictionary:(FwiDer *)extensions {
    /* Condition validation */
    if (!extensions || ![extensions isLike:[FwiDer derWithIdentifier:0xa3 Ders:[FwiDer sequence], nil]]) return nil;
    extensions = [extensions derAtIndex:0];
    
    FwiDer *elementValidation1 = [FwiDer sequence:
                                  [FwiDer objectIdentifier],
                                  [FwiDer octetString],
                                  nil];
    FwiDer *elementValidation2 = [FwiDer sequence:
                                  [FwiDer objectIdentifier],
                                  [FwiDer boolean],
                                  [FwiDer octetString],
                                  nil];
    
    NSMutableDictionary *dictionary = [NSMutableDictionary dictionaryWithCapacity:[extensions count]];
    for	(NSUInteger i = 0; i < [extensions count]; i++) {
        /* Condition validation: Validate element structure */
        FwiDer *extension = [extensions derAtIndex:i];
        if (!([extension isLike:elementValidation1] || [extension isLike:elementValidation2])) continue;
        
        /* Condition validation: Validate oID */
        NSString *oid = [[extension derAtIndex:0] getString];
        if (!oid || oid.length == 0) continue;
        
        NSString *name = [FwiX509Utils_Private queryName:oid];
        if ([name isEqualToString:@"basicConstraints2"] || [name isEqualToString:@"subjectKeyIdentifier"] || [name isEqualToString:@"authorityKeyIdentifier2"]) {
            dictionary[name] = [extension encodeBase64String];
        }
    }
    return dictionary;
}

+ (FwiDer *)dictionaryToAttributes:(NSDictionary *)dictionary {
    /* Condition validation */
    if (!dictionary || dictionary.count == 0) return [FwiDer null];
    
    // Setup iterator
    __block FwiDer *object = [FwiDer sequence];
    [dictionary enumerateKeysAndObjectsUsingBlock:^(NSString *name, NSString *obj, BOOL *stop) {
        NSString *oid = [FwiX509Utils_Private queryOID:name];
        
        if (oid && oid.length > 0) {
            FwiDer *value = nil;
            
            if ([name isEqualToString:@"EMAIL"]) {
                value = [FwiDer ia5StringWithString:obj];
            }
            else {
                value = [FwiDer printableStringWithString:obj];
            }
            [object addDers:[FwiDer set:
                                [FwiDer sequence:
                                 [FwiDer objectIdentifierWithOIDString:oid],
                                 value,
                                 nil],
                                nil],
             nil];
        }
    }];
    return object;
}
+ (FwiDer *)dictionaryToExtensions:(NSDictionary *)dictionary {
    /* Condition validation */
    if (!dictionary || dictionary.count == 0) return [FwiDer null];
    
    FwiDer *object = [FwiDer derWithIdentifier:0xa3
                                          Ders:[FwiDer sequence:
                                                   [dictionary[@"basicConstraints2"] decodeBase64Der],
                                                   [dictionary[@"subjectKeyIdentifier"] decodeBase64Der],
                                                   [dictionary[@"authorityKeyIdentifier2"] decodeBase64Der],
                                                   nil],
                      nil];
    return object;
}


#pragma mark - Class's constructors
- (id)init {
    self = [super init];
    if (self) {
    }
    return self;
}


#pragma mark - Cleanup memory
- (void)dealloc {
#if !__has_feature(objc_arc)
    [super dealloc];
#endif
}


@end
