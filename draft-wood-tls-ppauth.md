---
title: Privacy Pass Client Authentication for TLS
abbrev: Privacy Pass Client Authentication for TLS
docname: draft-wood-tls-ppauth
date:
category: std

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: T. Pauly
    name: Tommy Pauly
    org: Apple, Inc.
    email: tpauly@apple.com
 -
    ins: C. A. Wood
    name: Christopher A. Wood
    org: Cloudflare
    email: caw@heapingbits.net

--- abstract

This document describes a mechanism for lightweight client authentication in TLS
using Privacy Pass, an anonymous authentication protocol. Clients may use Privacy
Pass to obtain tokens, or anonymous credentials, that may be used at most once as
an authenticator. Issuance of Privacy Pass tokens is outside the scope of this 
document.

--- middle

# Introduction

TLS supports pre-shared key (PSK) and certificate-based authentication. Both clients
and servers may use either form of authentication during connection establishment. 
Unless otherwise negotiated, these mechanisms are mutually exclusive. Servers may not 
authenticate using both a PSK and certificate unless otherwise negotiated with the 
"tls_cert_with_extern_psk" extension from {{!RFC8773}}. As a result, clients that wish 
to authenticate using an external PSK while additionally authenticating the server with 
a certificate MUST use the "tls_cert_with_extern_psk" extension.

Beyond PSKs and certificates, there exist other forms of authenticators that endpoints
may wish to use for TLS authentication. Privacy Pass is one form of authentication 
technology, which uses "anonymous credentials" as lightweight client authenticators. 
Privacy Pass authenticators are anonymous as they do not reveal any information about
the client during the authentication phase. 

Unfortunately, the "tls_cert_with_extern_psk" extension is limited to traditional external
PSKs in TLS. {{!I-D.draft-group-tls-extensible-psks}} specifies an extensible PSK format
that may be used for introducing new types of PSKs with different properties. This
document specifies one such PSK for lightweight client authentication based on Privacy Pass.

[[TODO: should we also specify a way of using Privacy Pass authenticators with Exported Authenticators?]]

## Requirements

{::boilerplate bcp14}

# Preliminaries {#prelim}

## Privacy Pass Overview

Privacy Pass {{!I-D.draft-davidson-pp-protocol}} is a protocol for authenticating clients that have been 
authenticated in some out-of-band channel. At a high level, the protocol works as follows. First, 
clients obtain one or more tokens, encoded in RedemptionToken structures, from a server during a 
"issuance" phase. Later, when the client wishes to re-authenticate, it "redeems" the token to the 
server by sending a ClientRedemptionRequest. Importantly, the redeemed token is unlinkable to the 
previously issued token. This unlinkability property is what makes Privacy Pass a form of anonymous 
authentication protocol. Clients MUST NOT use the same RedemptionToken across more than one 
ClientRedemptionRequest, as doing would violate this unlinkability property.

Token issuance may require or involve some form of application-specific logic before sending tokens.
For example, clients may be required to pay some monetary value for a single token. As a result, 
we assume issuance is an offline protocol run out-of-band to prime clients with RedemptionToken values.

## Use Cases

Traditional PSK and certificate authenticators for clients are useful if servers need strong assurance
of the client's identity. However, there are some use cases wherein servers may wish to perform
a weaker check. For example, consider a server that wishes to check whether any client from a set of
previously authenticated clients. Servers need only a way to check that the client was previously 
authenticated, yet do not need to know any more information about the client. 

Cases where this functionality may be important are HTTPS CONNECT and CONNECT-UDP proxies. Specifically, 
these proxy servers may wish to restrict access to "previously authenticated" clients, rather than
any client on the network.

# Privacy Pass Client Authentication

This document specifies a new PSK type called "anonymous_token" using the "extended_psk" structure.
The ExtendedPSKIdentity value of "anonymous_token" is as follows:

~~~
enum {
    anonymous_token(TBD),
    (255)
} ExtendedPskIdentityType;
~~~

The structure of an "anonymous_token" PSK is as follows:

~~~
struct {
  opaque data<1..2^32-1>;
  opaque aux<1..2^16-1>;
} AnonymousToken;
~~~

data
: The input used by the server to verify the token.

aux
: Additional auxiliary data provided by the application protocol using this anonymous token.

Clients use Privacy Pass RedemptionToken values to create AnonymousToken PSK identities and 
PSK values. Specifically, given a RedemptionToken `T` structure, additional auxiliary data `aux`,
and a Privacy Pass client configuration `config`, clients first compute a ClientRedemptionRequest
value `request` as follows:

~~~
request = Redeem(config, T, aux)
~~~

Then clients create an AnonymousToken value such that AnonymousToken.data = RedemptionToken.data
and AnonymousToken.aux = aux. The corresponding PSK K is set to request.tag. Clients use K to compute
a binder as specified in {{!TLS13=RFC8446}}. Clients MUST also include the "tls_cert_with_extern_psk"
extension in the ClientHello. Clients MUST NOT re-use a RedemptionToken in multiple ClientHello messages.

Upon receipt of a ClientHello with an AnonymousToken PSK identity, a server does the following:

1. If the ClientHello does not also contain the "tls_cert_with_extern_psk" extension, abort 
the connection with an "invalid_parameter" alert.
2. Otherwise, servers use the contents of AnonymousToken to reconstruct the PSK and verify 
the binder value as per 4.2.11. of {{!TLS13}}. If the binder fails to verify, the server 
MUST abort the handshake.

[[OPEN ISSUE: What alert should the server return if the binder fails? The standard value?]]

[[OPEN ISSUE: The PrivacyPass API currently doesn't one recompute the PSK given `data` and `aux`, so we
need to modify it to permit that]]

# Deployment Considerations

[[TODO: double spend prevention state at the server]]

[[TODO: token issuance out of band]]

# IANA Considerations

[[TODO]]

# Security Considerations

## Authentication Guarantees

AnonymousToken authentication does not give servers strong assurance of the client identity. Rather, it
only gives servers assurance that the client had previously authenticated with the server. This is 
a subtle yet important difference from traditional TLS authentication mechanisms, wherein servers learn
the identity of the client and possibly make application decisions based on that identity. By definition,
AnonymousTokens reveal no identifying information, and therefore cannot be used for such purposes.

## On-Path Attacker Considerations

As AnonymousToken values are sent in the clear, on-path attackers may hijack these tokens and replay
them in their own connections. However, this is not a problem because any change in the ClientHello,
such as replacing the the KeyShare values, will cause the server binder check to fail.

Attackers may also use the cleartext `data` field of the AnonymousToken field to execute the issuance 
phase of the Privacy Pass protocol and derive the client's corresponding PSK. This does not compromise 
the target connection since servers must also authenticate to clients using a certificate. 

Use of EncryptedClientHello {{!ECH=I-D.ietf-tls-esni}} can help deter these on-path attacks by encrypting 
the contents of the ClientHello under the server's public key.

# Acknowledgments

This document was inspired by the work Privacy Pass and {{!I-D.draft-sullivan-tls-anonymous-tickets}}.
