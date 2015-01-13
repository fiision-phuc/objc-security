//  Project name: FwiSecurity
//  File name   : FwiSecurity_Private.h
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

#ifndef __FWI_SECURITY_PRIVATE__
#define __FWI_SECURITY_PRIVATE__


#import <Foundation/Foundation.h>


#define kClass_AES              (id)[NSNumber numberWithLong:2147483649]
#define kClass_RSA              (__bridge id)kSecAttrKeyTypeRSA              // Indicating the algorithm associated with the key.
#define kClass_CRT              (__bridge id)kSecClassCertificate
#define kClass_ID               (__bridge id)kSecClassIdentity
#define kValue_N                (__bridge id)kCFBooleanFalse
#define kValue_Y                (__bridge id)kCFBooleanTrue

#define kClass                  (__bridge id)kSecClass
#define kClassKey               (__bridge id)kSecClassKey
#define kPvtKeyAttrs            (__bridge id)kSecPrivateKeyAttrs
#define kPubKeyAttrs            (__bridge id)kSecPublicKeyAttrs
#define kValueData              (__bridge id)kSecValueData                   // Data is secret (encrypted) and may require the user to enter a password for access.
#define kValueRef               (__bridge id)kSecValueRef
#define kValuePersistentRef     (__bridge id)kSecValuePersistentRef

#define kReturnAttributes       (__bridge id)kSecReturnAttributes
#define kReturnData             (__bridge id)kSecReturnData
#define kReturnPersistentRef    (__bridge id)kSecReturnPersistentRef
#define kReturnRef              (__bridge id)kSecReturnRef

#define kAttr_pdmn              (__bridge id)kSecAttrAccessible
#define kAttr_agrp              (__bridge id)kSecAttrAccessGroup
#define kAttr_cdat              (__bridge id)kSecAttrCreationDate
#define kAttr_mdat              (__bridge id)kSecAttrModificationDate
#define kAttr_desc              (__bridge id)kSecAttrDescription
#define kAttr_icmt              (__bridge id)kSecAttrComment
#define kAttr_crtr              (__bridge id)kSecAttrCreator
#define kAttr_type              (__bridge id)kSecAttrType                    // (__bridge id)kSecAttrKeyType
#define kAttr_labl              (__bridge id)kSecAttrLabel
#define kAttr_invi              (__bridge id)kSecAttrIsInvisible
#define kAttr_nega              (__bridge id)kSecAttrIsNegative
#define kAttr_acct              (__bridge id)kSecAttrAccount
#define kAttr_svce              (__bridge id)kSecAttrService
#define kAttr_gena              (__bridge id)kSecAttrGeneric
#define kAttr_sdmn              (__bridge id)kSecAttrSecurityDomain
#define kAttr_srvr              (__bridge id)kSecAttrServer
#define kAttr_ptcl              (__bridge id)kSecAttrProtocol
#define kAttr_atyp              (__bridge id)kSecAttrAuthenticationType
#define kAttr_port              (__bridge id)kSecAttrPort
#define kAttr_path              (__bridge id)kSecAttrPath
#define kAttr_ctyp              (__bridge id)kSecAttrCertificateType
#define kAttr_cenc              (__bridge id)kSecAttrCertificateEncoding
#define kAttr_subj              (__bridge id)kSecAttrSubject
#define kAttr_issr              (__bridge id)kSecAttrIssuer
#define kAttr_slnr              (__bridge id)kSecAttrSerialNumber
#define kAttr_skid              (__bridge id)kSecAttrSubjectKeyID
#define kAttr_pkhh              (__bridge id)kSecAttrPublicKeyHash
#define kAttr_kcls              (__bridge id)kSecAttrKeyClass
#define kAttr_klbl              (__bridge id)kSecAttrApplicationLabel
#define kAttr_perm              (__bridge id)kSecAttrIsPermanent
#define kAttr_atag              (__bridge id)kSecAttrApplicationTag
#define kAttr_bsiz              (__bridge id)kSecAttrKeySizeInBits
#define kAttr_esiz              (__bridge id)kSecAttrEffectiveKeySize
#define kAttr_encr              (__bridge id)kSecAttrCanEncrypt
#define kAttr_decr              (__bridge id)kSecAttrCanDecrypt
#define kAttr_drve              (__bridge id)kSecAttrCanDerive
#define kAttr_sign              (__bridge id)kSecAttrCanSign
#define kAttr_vrfy              (__bridge id)kSecAttrCanVerify
#define kAttr_wrap              (__bridge id)kSecAttrCanWrap
#define kAttr_unwp              (__bridge id)kSecAttrCanUnwrap

// new
//@constant kSecAttrProtocolFTP.
//@constant kSecAttrProtocolFTPAccount.
//@constant kSecAttrProtocolHTTP.
//@constant kSecAttrProtocolIRC.
//@constant kSecAttrProtocolNNTP.
//@constant kSecAttrProtocolPOP3.
//@constant kSecAttrProtocolSMTP.
//@constant kSecAttrProtocolSOCKS.
//@constant kSecAttrProtocolIMAP.
//@constant kSecAttrProtocolLDAP.
//@constant kSecAttrProtocolAppleTalk.
//@constant kSecAttrProtocolAFP.
//@constant kSecAttrProtocolTelnet.
//@constant kSecAttrProtocolSSH.
//@constant kSecAttrProtocolFTPS.
//@constant kSecAttrProtocolHTTPS.
//@constant kSecAttrProtocolHTTPProxy.
//@constant kSecAttrProtocolHTTPSProxy.
//@constant kSecAttrProtocolFTPProxy.
//@constant kSecAttrProtocolSMB.
//@constant kSecAttrProtocolRTSP.
//@constant kSecAttrProtocolRTSPProxy.
//@constant kSecAttrProtocolDAAP.
//@constant kSecAttrProtocolEPPC.
//@constant kSecAttrProtocolIPP.
//@constant kSecAttrProtocolNNTPS.
//@constant kSecAttrProtocolLDAPS.
//@constant kSecAttrProtocolTelnetS.
//@constant kSecAttrProtocolIMAPS.
//@constant kSecAttrProtocolIRCS.
//@constant kSecAttrProtocolPOP3S.
//kSecAttrAuthenticationTypeNTLM.
//@constant kSecAttrAuthenticationTypeMSN.
//@constant kSecAttrAuthenticationTypeDPA.
//@constant kSecAttrAuthenticationTypeRPA.
//@constant kSecAttrAuthenticationTypeHTTPBasic.
//@constant kSecAttrAuthenticationTypeHTTPDigest.
//@constant kSecAttrAuthenticationTypeHTMLForm.
//@constant kSecAttrAuthenticationTypeDefault.
//kSecAttrKeyClassPublic
//kSecAttrKeyClassPrivate
//kSecAttrKeyClassSymmetric
//kSecAttrKeyTypeEC

typedef NS_ENUM(NSInteger, FwiSecStatus) {
    kSec_Success               = errSecSuccess,                    // No error.
    kSec_Unimplemented         = errSecUnimplemented,              // Function or operation not implemented.
    kSec_InvalidParam          = errSecParam,                      // One or more parameters passed to a function where not valid.
    kSec_FailToAllocate        = errSecAllocate,                   // Failed to allocate memory.
    kSec_KeychainNotAvailable  = errSecNotAvailable,               // No keychain is available. You may need to restart your computer.
    kSec_KeychainDuplicateItem = errSecDuplicateItem,              // The specified item already exists in the keychain.
    kSec_ItemNotFound          = errSecItemNotFound,               // The specified item could not be found in the keychain.
    kSec_InteractionNotAllowed = errSecInteractionNotAllowed,      // User interaction is not allowed.
    kSec_UnableToDecode        = errSecDecode,                     // Unable to decode the provided data.
    kSec_InvalidAuth           = errSecAuthFailed,                 // The user name or passphrase you entered is not correct.
};


#endif
