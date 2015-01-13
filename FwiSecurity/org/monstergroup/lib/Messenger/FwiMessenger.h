//  Project name: FwiSecurity
//  File name   : FwiMessenger.h
//
//  Author      : Phuc, Tran Huu
//  Created date: 5/15/13
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

#import <Foundation/Foundation.h>


@interface FwiMessenger : NSObject {

@private
    NSString       *_peerHostname;
    NSMutableArray *_validateStructures;
}


- (FwiJson *)decodeMessage:(FwiJson *)message;
- (FwiJson *)encodeMessage:(FwiJson *)message messageType:(FwiMessageType)messageType;

/**
 * Add validation structures for response message.
 */
- (void)addValidStructures:(FwiJson *)structure, ... NS_REQUIRES_NIL_TERMINATION;

@end


@interface FwiMessenger (FwiMessengerCreation)

// Class's static constructors
+ (FwiMessenger *)messengerWithPeerHostname:(NSString *)peerHostname;

// Class's constructors
- (id)initWithPeerHostname:(NSString *)peerHostname;

@end