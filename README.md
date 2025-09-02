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

The package can still be used with the 10.6 version of Indy. However, you will be limited to using the unsupported OpenSSL 1.0.2 library (current is OpenSSL 3.x) and TLS 1.2.

In order to use the package with Indy 10.6, you must compile with the "USING_INDY10_6" defined symbol and change the oauth2_laz package dependency from indyopenssl to indylaz.

Note: you do not have to install Indy into your IDE in order to use Indy units with oauth2. It is sufficient to open, in the IDE, the packages

indysystem,
indycore,
indyprotocols,
indyopenssl

in the above order. Lazarus then knows where to find them when compiling with oauth2_laz.
