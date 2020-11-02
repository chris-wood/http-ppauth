---
title: Privacy Pass Authentication for HTTP
abbrev: Privacy Pass Authentication for HTTP
docname: draft-wood-httpbis-ppauth
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

This document describes new HTTP authentication mechanisms based on Privacy Pass,
an anonymous authentication protocol. Clients may use Privacy Pass to obtain tokens,
or anonymous credentials, that may be used at most once as an authenticator. Issuance
of Privacy Pass tokens is outside the scope of this document.

--- middle

# Introduction

The HTTP authentication header allows clients to authenticate requests to servers and proxies
{{!RFC7235}}. Current authentication schemes include Basic, Digest, and OAuth.
There is no anonymous authentication scheme currently defined.

Privacy Pass an anonymous authentication protocol which uses "anonymous credentials"
as lightweight client authenticators. Privacy Pass authenticators are anonymous as
they do not reveal any information about the client during the authentication phase.
Clients may use these authenticators to prove to a server that it had previously
authenticated or engaged in a protocol to acquire an authenticator.

This document specifies a way by which clients may redeem Privacy Pass tokens to
servers for HTTP requests. This mechanism uses a new HTTP authentication scheme
based on Privacy Pass. It updates the IANA Hypertext Transfer Protocol (HTTP)
Authentication Scheme Registry with this new scheme and its details.

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

Traditional HTTP authentication schemes are useful if servers need strong assurance of the client's
identity. However, there are some use cases wherein servers may wish to perform a weaker check.
For example, consider a server that wishes to check whether any client from a set of previously
authenticated clients. Servers need only a way to check that the client was previously authenticated,
yet do not need to know any more information about the client.

Cases where this functionality may be important are HTTPS CONNECT and CONNECT-UDP proxies. Specifically,
these proxy servers may wish to restrict access to "previously authenticated" clients, rather than
any client on the network.

# PrivacyPassToken Authentication

This document specifies a new HTTP authentication scheme called "PrivacyPassToken". Servers may request
clients to authenticate using an anonymous token by issuing a challenge (WWW-Authenticate or
Proxy-Authenticate) with the following information:

- The scheme name is "PrivacyPassToken".
- The authentication parameter 'realm' is REQUIRED ({{!RFC7235}}, Section 2.2).
- The authentication parameter 'pp-config' is REQUIRED. (Section {{config-param}}).
- No other authentication parameters are defined -- unknown parameters MUST be ignored by
  recipients, and new parameters can only be defined by revising this specification.

Clients use the contents of an "PrivacyPassToken" challenge to create an authorization response.
Specifically, given a RedemptionToken `T` matching the configuration identified by the challenge,
and additional auxiliary data `aux`, clients first compute a ClientRedemptionRequest value
`request` as follows:

~~~
request = Redeem(T, aux)
~~~

`Redeem` is as specified in {{!I-D.davidson-pp-protocol}}. Clients then convert `request`
to a base64-encoded string and provide it as the Authorization value:

~~~
Proxy-Authorization: PrivacyPassToken <encoded-request>
~~~

Clients MAY send the "Proxy-Authorization" header without a corresponding challenge.

Clients MUST NOT re-use a given token `T` more than once across HTTP connections.

## PrivacyPassToken Configuration Parameter {#config-param}

In challenges, servers can use the 'pp-config' authentication parameter to indicate the
Privacy Pass server configuration that clients should use in generating an Authorization
response. The value of this parameter is a base64-encoded `ServerUpdate` structure;
see {{I-D.davidson-pp-protocol}}.

~~~
Proxy-Authenticate: PrivacyPassToken realm="MASQUE", pp-config="<encoded-config>"
~~~

# IANA Considerations

This document updates the Hypertext Transfer Protocol (HTTP) Authentication Scheme Registry as follows.

- Authentication Scheme Name: PrivacyPassToken
- Reference: This document.

# Security Considerations {#sec-considerations}

Privacy Pass tokens are designed to be unlinkable. Clients that spend tokens more than
once across tokens forfeit this property. Clients that spend tokens more than once within
the same connection may not forfeit this property, since servers can already link connection
requests to the same client via other means.

# Acknowledgments

This document was inspired by the work Privacy Pass.
