# openssl-pkcs8

## Obsolete

> *NOTE*: This is no longer required as Ruby 3.x includes native PKCS8 support
in the form of the [`private_to_pem`](https://rubyapi.org/3.3/o/openssl/pkey/pkey#method-i-private_to_pem)
method.

This adds PKCS8 compliant key export to the OpenSSL::PKey::RSA library that
is part of standard Ruby distributions.

Example:

    key = OpenSSL::PKey::RSA.new(1024)
    
    key.to_pem_pkcs8
    # => "-----BEGIN PRIVATE KEY----- ..."

This will export the private key in PKCS8 format, and will export public keys
in the PUBKEY format used by OpenSSL. Note the absence of "RSA" in both of
the headers.
  
## Installation

Using the Gem distribution is probably easiest:

    gem install openssl_pkcs8

## Copyright

The contents of openssl_pkcs8.c is mostly taken from the Ruby distribution and
is licensed under exactly the same terms as the original.

The remainder is (C) 2012 Scott Tadman under the MIT License.
