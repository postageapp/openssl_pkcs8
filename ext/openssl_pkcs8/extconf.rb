require 'mkmf'

extension_name = 'openssl_pkcs8'

dir_config(extension_name)

have_header("openssl/ssl.h")
%w[crypto libeay32].any? {|lib| have_library(lib, "OpenSSL_add_all_digests")}
%w[ssl ssleay32].any? {|lib| have_library(lib, "SSL_library_init")}

create_makefile(extension_name)
