require 'test/unit'

$LOAD_PATH.concat([
  File.join(File.dirname(__FILE__), '..', 'lib'),
  File.join(File.dirname(__FILE__), '..', 'ext'),
  File.dirname(__FILE__)
])

require 'openssl_pkcs8'

class Test::Unit::TestCase
  # ...
end
