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

For those wanting to evaluate the examples, there is a test authentication server available. To use this server with the examples, simply provide a new environment variable AUTHSERVER with the value:

https://test.mwasoftware.co.uk

in the example program's environment. 

Note. when running under the IDE, an environment variable is set by going to Run->Run Parameters and clicking on the "Environment" tab.

The package uses the Indy Component library for both an http/https client and an http server. When the https protocol is used the OpenSSL library must also be installed and available for use. This version of the package has also been configured for use with the MWA Software IndySecOpenSSL package and the Indy Component Library.

Multithreading support is required for Authorization Code and Implicit Grants.

The package is written in Object Pascal and is made available under the Lesser GPL.

A separate branch (Indy106Compat) is also available. This will work with the Indy Component library on its own. However, you will be limited to using the unsupported OpenSSL 1.0.2 library (current is OpenSSL 3.x) and TLS 1.2. 

For installation instructions please refer to the User Guide.


