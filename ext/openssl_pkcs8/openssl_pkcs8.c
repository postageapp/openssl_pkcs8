#include "ruby.h"

#include <openssl/err.h>
#include <openssl/ossl_typ.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/asn1_mac.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/conf_api.h>

VALUE mOSSL;
VALUE mPKey;
VALUE cRSA;
VALUE eRSAError;
VALUE ePKeyError;
VALUE eOSSLError;
VALUE cCipher;

extern const rb_data_type_t ossl_evp_pkey_type;

#define GetPKey(obj, pkey) do {\
    TypedData_Get_Struct((obj), EVP_PKEY, &ossl_evp_pkey_type, (pkey)); \
    if (!pkey) { \
    	rb_raise(rb_eRuntimeError, "PKEY wasn't initialized!");\
    } \
} while (0)
#define GetPKeyRSA(obj, pkey) do { \
    GetPKey(obj, pkey); \
    if (EVP_PKEY_type(pkey->type) != EVP_PKEY_RSA) { /* PARANOIA? */ \
    	ossl_raise(rb_eRuntimeError, "THIS IS NOT A RSA!") ; \
    } \
} while (0)
#define OSSL_PKEY_SET_PRIVATE(obj) rb_iv_set((obj), "private", Qtrue)
#define OSSL_PKEY_SET_PUBLIC(obj)  rb_iv_set((obj), "private", Qfalse)
#define OSSL_PKEY_IS_PRIVATE(obj)  (rb_iv_get((obj), "private") == Qtrue)
#define RSA_HAS_PRIVATE(rsa) ((rsa)->p && (rsa)->q)
#define GetCipher(obj, ctx) do { \
    Data_Get_Struct(obj, EVP_CIPHER_CTX, ctx); \
    if (!ctx) { \
    	ossl_raise(rb_eRuntimeError, "Cipher not inititalized!"); \
    } \
} while (0)
#define SafeGetCipher(obj, ctx) do { \
    OSSL_Check_Kind(obj, cCipher); \
    GetCipher(obj, ctx); \
} while (0)

VALUE ossl_membio2str0(BIO *bio)
{
    VALUE ret;
    BUF_MEM *buf;

    BIO_get_mem_ptr(bio, &buf);
    ret = rb_str_new(buf->data, buf->length);

    return ret;
}

VALUE ossl_protect_membio2str(BIO *bio, int *status)
{
    return rb_protect((VALUE(*)_((VALUE)))ossl_membio2str0, (VALUE)bio, status);
}

VALUE ossl_membio2str(BIO *bio)
{
    VALUE ret;
    int status = 0;

    ret = ossl_protect_membio2str(bio, &status);
    BIO_free(bio);
    if(status) rb_jump_tag(status);

    return ret;
}

const EVP_CIPHER* GetCipherPtr(VALUE obj)
{
    EVP_CIPHER_CTX* ctx;

    SafeGetCipher(obj, ctx);

    return EVP_CIPHER_CTX_cipher(ctx);
}

static VALUE openssl_pkcs8_pem_passwd_cb0(VALUE flag)
{
    VALUE pass;

    pass = rb_yield(flag);
    SafeStringValue(pass);

    return pass;
}

int openssl_pkcs8_pem_passwd_cb(char *buf, int max_len, int flag, void *pwd)
{
  int len, status = 0;
  VALUE rflag, pass;

  if (pwd || !rb_block_given_p())
    return PEM_def_callback(buf, max_len, flag, pwd);

  while (1) {
    /*
    * when the flag is nonzero, this passphrase
    * will be used to perform encryption; otherwise it will
    * be used to perform decryption.
    */
    rflag = flag ? Qtrue : Qfalse;
    pass  = rb_protect(openssl_pkcs8_pem_passwd_cb0, rflag, &status);
    if (status) return -1; /* exception was raised. */
    len = (int) RSTRING_LEN(pass);
    if (len < 4) { /* 4 is OpenSSL hardcoded limit */
      rb_warning("password must be longer than 4 bytes");
      continue;
    }
    if (len > max_len) {
      rb_warning("password must be shorter then %d bytes", max_len-1);
      continue;
    }
    memcpy(buf, RSTRING_PTR(pass), len);
    break;
  }
  return len;
}

static VALUE openssl_rsa_to_pem_pkcs8(int argc, VALUE *argv, VALUE self)
{
  EVP_PKEY *pkey;
  BIO *out;
  const EVP_CIPHER *ciph = NULL;
  char *passwd = NULL;
  VALUE cipher, pass;

  GetPKeyRSA(self, pkey);

  rb_scan_args(argc, argv, "02", &cipher, &pass);

  if (!NIL_P(cipher))
  {
    ciph = GetCipherPtr(cipher);
    if (!NIL_P(pass))
    {
      passwd = StringValuePtr(pass);
    }
  }

  if (!(out = BIO_new(BIO_s_mem())))
  {
    ossl_raise(eRSAError, NULL);
  }

  if (RSA_HAS_PRIVATE(pkey->pkey.rsa))
  {
    if (!PEM_write_bio_PKCS8PrivateKey(
      out, pkey, ciph,
      NULL, 0, openssl_pkcs8_pem_passwd_cb, passwd))
    {
      BIO_free(out);
      ossl_raise(eRSAError, NULL);
    }
  }
  else
  {
    if (!PEM_write_bio_PUBKEY(out, pkey))
    {
      BIO_free(out);
      ossl_raise(eRSAError, NULL);
    }
  }

  return ossl_membio2str(out);
}

void Init_openssl_pkcs8()
{
  mOSSL = rb_const_get(rb_cObject, rb_intern("OpenSSL"));
  mPKey = rb_const_get(mOSSL, rb_intern("PKey"));
  cRSA = rb_const_get(mPKey, rb_intern("RSA"));
  cCipher = rb_const_get(mOSSL, rb_intern("Cipher"));

  eOSSLError = rb_const_get(mOSSL,rb_intern("OpenSSLError"));
  ePKeyError = rb_const_get(mPKey, rb_intern("PKeyError"));
  eRSAError = rb_const_get(mPKey, rb_intern("RSAError"));

  rb_define_method(cRSA, "to_pem_pkcs8", openssl_rsa_to_pem_pkcs8, -1);
}
