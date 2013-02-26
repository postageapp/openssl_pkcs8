require_relative 'helper'

class TestOpensslPkcs8 < Test::Unit::TestCase
  def test_rsa_key
    key = OpenSSL::PKey::RSA.new(1024)
    
    assert key.respond_to?(:to_pem_pkcs8), "Extension method not defined"
    
    encoded = key.to_pem_pkcs8

    puts key.to_pem
    puts encoded
    
    assert encoded

    encoded_public = key.public_key.to_pem_pkcs8
    
    puts key.public_key.to_pem
    puts encoded_public

    assert encoded_public
    assert encoded_public.match(/BEGIN PUBLIC KEY/)
  end
end
