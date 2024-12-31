# oauth2client

An RFC 6749 OAuth2 Client implemented as a Lazarus Package.

The client is intended to be fully featured and supports the following grant types:

* Authorization Code Grant
* Implicit Grant
* Resource Owner Password Credentials Grant
* Client Credentials Grant.

Attention has also been paid to extensibility. The client also provides:

* A means of implementing an Extension Grant, including new grant types.
* Support for new token types
* Support for New Endpoint Parameters, and
* Support for additional error codes.

This OAuth2 Client uses an external User Agent - the System Web Browser - and incorporates in internal http server for handling redirect responses from an Authorization Server.

The package uses the Indy Component library for both an http/https client and an http server. When the https protocol is used the OpenSSL library must also be installed and available for use.

Multithreading support is required for Authorization Code and Implicit Grants.

The package is written in Object Pascal and is made available under the Lesser GPL.

The package requires the Indy package for http/https protocol support. It has been configured for
use with the MWA Software Indy.ProposedUpdate fork of IndySockets.
