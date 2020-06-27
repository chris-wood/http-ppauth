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
the client during the authentication phase. Therefore, these authenticators are not
traditional PSKs, nor are they traditional certificates.

This document specifies a new extension clients may use to redeem Privacy Pass authentication
tokens. It also specifies a way of using Privacy Pass authenticators with Exported Authenticators
{{!I-D.ietf-tls-exported-authenticators}} if encryption of these values is desired.

## Requirements

{::boilerplate bcp14}

# Preliminaries {#prelim}

## Privacy Pass Overview

Privacy Pass {{!I-D.davidson-pp-protocol}} is a protocol for authenticating clients that have been
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

# Anonymous Token Extension

This document specifies a new structure for carrying anonymous tokens called AnonymousToken,
defined as follows:

~~~
struct {
  select (Handshake.msg_type) {
    case client_hello, certificate: {
      opaque config<1..2^8-1>;
      RedemptionMessage request;
    }
    case encrypted_extensions: {
      RedemptionResponse response;
    }
} AnonymousToken;
~~~

config
: Identifier of the client's Privacy Pass ClientConfig structure.

request
: Client's Privacy Pass RedemptionRequest message.

response
: Server's Privacy Pass RedemptionResponse message.

# Inline Privacy Pass Authentication

Clients can use Privacy Pass authentication tokens by sending them to servers in
an "anonymous_token" extension, defined as follows:

~~~
enum {
  anonymous_token(0xff03), (65535)
} ExtensionType;
~~~

The contents of this extension are a AnonymousToken structure. Clients use Privacy Pass
RedemptionToken values to create AnonymousToken structures. Specifically, given a RedemptionToken
`T`, additional auxiliary data `aux`, and a Privacy Pass client configuration `client_config`, clients
first compute a ClientRedemptionRequest value `request` as follows:

~~~
request = Redeem(client_config, T, aux)
~~~

Then clients create an AnonymousToken value such that AnonymousToken.message contains `request`
and AnonymousToken.config contains the identifier of `client_config`. In this document, the
identifier of `client_config` is the SHA-256 digest of the ClientConfig structure.

Upon receipt of a ClientHello with an AnonymousToken extension, servers verify it as follows.
First, if AnonymousToken.config does not match a known server configuration, the server replies
with an AnonymousToken extension in EncryptedExtensions with `success` field set to 0
and empty `additional_data`.

Otherwise, the server computes a RedemptionResponse message with the matching server config
`server_config` as follows:

~~~
response = Verify(server_config, AnonymousToken.request)
~~~

The server then replies with an AnonymousToken extension in EncryptedExtensions carrying `response`.

The server is said to accept the anonymous token if the value of the RedemptionResponse success
field is 0x01.

Similar to 0-RTT data, AnonymousToken values can be replayed both by clients and by on-path
attackers. Servers SHOULD build mechanisms to prevent AnonymousToken replays. Servers MAY
abort connections upon replay detection if desired for a given application use case or deployment.
See {{sec-considerations}} for discussion about possible attacks on this behavior.

# Privacy Pass Authentication with Exported Authenticators

Clients can also authenticate using Privacy Pass with Exported Authenticators.
This requires introduction of new "signature" scheme values, listed below:

~~~
enum {
  sig_pp_p256_sha512(0x0A01),
  sig_pp_p384_sha512(0x0A02),
  sig_pp_p521_sha512(0x0A03),
  sig_pp_x52219_sha512(0x0A04),
  sig_pp_x448_sha512(0x0A05),
} SignatureScheme;
~~~

Each of these correspond to the available Privacy Pass ciphersuites.
We also define a new Certificate message type for Privacy Pass
authentication, called AnonymousTokenAuthenticator, and defined below.

~~~
enum {
  AnonymousTokenAuthenticator(TBD),
  (255)
} CertificateType;
~~~

Certificates of this type have CertificateEntry structures of the form:

~~~
struct {
  Extension extensions<0..2^16-1>;
} CertificateEntry;
~~~

Given a client with a RedemptionToken `T`, additional auxiliary data
`aux`, and a Privacy Pass client configuration `config`, this mechanism
works as follows.

First, a server creates an Authenticator Request (CertificateRequest) with
randomly generated `certificate_request_context`, empty
"anonymous_token" extension, and "signature_algorithms" extension
listing one or more of the SignatureScheme values defined in this
document.

Upon receipt of this request, a client first checks to see if the list
of supported signature algorithms matches that in `config`. If not, the client
replies with an Empty Authenticator as described in
{{!I-D.ietf-tls-exported-authenticators}}. If there is a match, then
the client creates an Authenticator response by first constructing a
Certificate with an empty `certificate_list` and AnonymousTokenAuthenticator
CertificateEntry. The CertificateEntry contains an AnonymousToken value
such that AnonymousToken.data = T.data and AnonymousToken.aux = aux.

The client then creates a CertificateVerify message with a SignatureScheme
value that matches that of `config` and presented in the CertificateRequest.
To produce the signature value, the client first computes a ClientRedemptionRequest
value `request` as follows:

~~~
request = Redeem(config, T, aux)
~~~

Then, the client uses request.tag as an HMAC key to compute the signature
over the input defined in {{!I-D.ietf-tls-exported-authenticators}}.

Finally, the client produces a Finished message as described in
{{!I-D.ietf-tls-exported-authenticators}}, and sends the entire
Authenticator to the server.

Upon receipt, the server verifies the Authenticator by using the contents of
the AnonymousToken CertificateEntry extension to reconstruct the HMAC key,
verify the Authenticator CertificateVerify message signature, and then
verify the Finished message. If any of these verification steps fail, the
Authenticator is deemed invalid.

Support for Exported Authenticators is negotiated at the application
layer. For example, this might be done with an HTTP/2 or HTTP/3 SETTINGS
parameter.

# IANA Considerations

[[TODO: list all new types allocated here]]

# Security Considerations {#sec-considerations}

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
the target connection since servers must also authenticate to clients using a certificate. However,
if the attacker can execute the issuance phase, derive the PSK, and then send its own ClientHello
to the server. If servers abort connections upon detection of a double spend event, this may cause
the legitimate client's connection to fail.

Use of EncryptedClientHello {{!ECH=I-D.ietf-tls-esni}} can help deter these on-path attacks by encrypting
the contents of the ClientHello under the server's public key. Moreover, the Exported Authenticator
authentication flow protects against this attack, albeit at the cost of additional round trip.

# Acknowledgments

This document was inspired by the work Privacy Pass and {{!I-D.sullivan-tls-anonymous-tickets}}.
