//  Project name: FwiSecurity
//  File name   : FwiSecurity.h
//
//  Author      : Phuc, Tran Huu
//  Created date: 1/25/13
//  Version     : 1.00
//  --------------------------------------------------------------
//  Copyright (C) 2012, 2014 Monster Group.
//  All Rights Reserved.
//  --------------------------------------------------------------
//
//
//  MONSTER GROUP CONFIDENTIAL
//  __________________________
//
//  All information contained herein is, and remains the property of Monster Group. The intellectual
//  and technical concepts contained herein are proprietary to Monster Group and may be  covered  by
//  U.S. and Foreign Patents, patents in process, and are protected by  trade  secret  or  copyright
//  law. Dissemination of this information or reproduction of this material  is  strictly  forbidden
//  unless prior written permission is obtained from Monster Group.
//
//  THIS SOFTWARE IS PROVIDED BY MONSTER GROUP  'AS IS'  AND  ANY  EXPRESS  OR  IMPLIED  WARRANTIES,
//  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES  OF  MERCHANTABILITY  AND  FITNESS  FOR  A
//  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL MONSTER GROUP BE  LIABLE  FOR  ANY  DIRECT,
//  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT  NOT  LIMITED
//  TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,  DATA,  OR  PROFITS;  OR  BUSINESS
//  INTERRUPTION) HOWEVER CAUSED AND ON  ANY  THEORY  OF  LIABILITY,  WHETHER  IN  CONTRACT,  STRICT
//  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//
//  Disclaimer
//  __________
//  Although reasonable care has been taken  to  ensure  the  correctness  of  this  software,  this
//  software should never be used in  any  application  without  proper  verification  and  testing.
//  Monster Group disclaim all liability and responsibility to any person or entity with respect  to
//  any loss or damage caused, or alleged to be caused, directly or indirectly, by the use  of  this
//  software. However, if any kind of bugs had been discovered, please feel  free  to  feedback  the
//  author at phuc.monster@gmail.com.

#ifndef __FWI_SECURITY__
#define __FWI_SECURITY__


#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonCryptor.h>


typedef NS_ENUM(NSInteger, FwiAesSize) {
    k128    = kCCKeySizeAES128,         // 16 bytes
    k192    = kCCKeySizeAES192,         // 24 bytes
    k256    = kCCKeySizeAES256          // 32 bytes
};  // AES Key size supported

typedef NS_ENUM(NSInteger, FwiRsaSize) {
    k1024   = 1024,                     // 128 bytes
    k2048   = 2048,                     // 256 bytes
    k4096   = 4096                      // 512 bytes
};  // RSA Key size supported

typedef NS_ENUM(NSInteger, FwiDigest) {
	kSHA1   = CC_SHA1_DIGEST_LENGTH,    // 20 bytes     iOS 5
	kSHA256 = CC_SHA256_DIGEST_LENGTH,  // 32 bytes     iOS 6
	kSHA384 = CC_SHA384_DIGEST_LENGTH,  // 48 bytes     ?????
	kSHA512 = CC_SHA512_DIGEST_LENGTH   // 64 bytes     iOS 5
};  // Digest supported

typedef NS_ENUM(NSInteger, FwiHmacHash) {
	kHmacHash_1   = kCCHmacAlgSHA1,     // 20 bytes
	kHmacHash_256 = kCCHmacAlgSHA256,   // 32 bytes
	kHmacHash_384 = kCCHmacAlgSHA384,   // 48 bytes
	kHmacHash_512 = kCCHmacAlgSHA512    // 64 bytes
};  // HmacHash supported

typedef NS_ENUM(NSInteger, FwiX509Error) {
    kX509Error_CertificateExpired		 = 0x01,
    kX509Error_InvalidSerialNumber		 = 0x02,
    kX509Error_InvalidSignatureAlgorithm = 0x03,
    kX509Error_InvalidSignatureData		 = 0x04,
    kX509Error_InvalidPublicKey			 = 0x05,
    kX509Error_InvalidVersion			 = 0x06,
    kX509Error_MissingExtensionsInfo     = 0x07,
    kX509Error_MissingIssuerInfo         = 0x08,
    kX509Error_MissingSubjectInfo		 = 0x09
};  // X.509 Certificate validation error


typedef NS_ENUM(NSInteger, FwiMessageType) {
    kUnknown   = 0x00,
    kAesUnsign = 0x01,
    kAesSigned = 0x02,
    kRsaUnsign = 0x03,
    kRsaSigned = 0x04
};  // Message type supported

typedef NS_ENUM(NSInteger, FwiSPStage) {
    kSPStage_Initialize = 0x00,
    kSPStage_Starting	= 0x01,
    kSPStage_Error		= 0x02,
    kSPStage_Ready		= 0x03
};  // Security provider stage

typedef NS_ENUM(NSInteger, FwiSSStage) {
    kSSStage_Initialize	= 0x00,
    kSSStage_Starting	= 0x01,
    kSSStage_Error		= 0x02,
    kSSStage_Expired	= 0x03,
    kSSStage_Ready		= 0x04
};  // Secured session stage


// FwiDigest helpers
extern FwiDigest (^FwiDigestWithLength)(NSInteger length);
extern FwiDigest (^FwiDigestWithDigestOID)(NSString *digestOID);
extern FwiDigest (^FwiDigestWithSignatureOID)(NSString *signatureOID);

extern NSInteger (^FwiLengthWithDigest)(FwiDigest digest);
extern NSString* (^FwiDigestOIDWithDigest)(FwiDigest digest);
extern NSString* (^FwiSignatureOIDWithDigest)(FwiDigest digest);


// X.509 Helpers
extern NSString* (^FwiQueryOID)(NSString *name);
extern NSString* (^FwiQueryName)(NSString *oid);
extern NSString* (^FwiDescriptionOID)(NSString *oid);

extern NSDictionary* (^FwiAttributesToDictionary)(FwiDer *attributes);
extern NSDictionary* (^FwiExtensionsToDictionary)(FwiDer *extensions);

extern FwiDer* (^FwiDictionaryToAttributes)(NSDictionary *dictionary);
extern FwiDer* (^FwiDictionaryToExtensions)(NSDictionary *dictionary);


#endif
