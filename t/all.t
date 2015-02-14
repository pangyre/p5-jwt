#!/usr/bin/env perl
use strictures;
use utf8;
use open qw( :encoding(UTF-8) :std );
use Test::More;
use Test::Exception;
use MIME::Base64 "encode_base64url","decode_base64url";
use Digest::SHA "hmac_sha256_base64";
use Encode;

require_ok("JWT");

subtest "draft-ietf-oauth-json-web-token-08" => sub {
    my $ex_jwt_header = encode_base64url qq|{"typ":"JWT",\015\012 "alg":"HS256"}|;
    my $base64_header = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9';
    is $ex_jwt_header, $base64_header,
       "Spec header encodes to base64";

    my $ex_jwt_claims = 
        encode_base64url qq|{"iss":"joe",\015\012 "exp":1300819380,\015\012 "http://example.com/is_root":true}|;
    my $base64_claims = 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ';

    #use charnames ':full';
    #note charnames::viacode(ord$_), " -> ", ord($_) for split //, decode_utf8 decode_base64url $base64_claims;

    is $ex_jwt_claims, $base64_claims, "Spec claims encodes to base64";

    # Computing the HMAC of the JWS Signing Input ASCII(BASE64URL(UTF8(JWS
    # Protected Header)) || '.' || BASE64URL(JWS Payload)) with the HMAC
    # SHA-256 algorithm using the key specified in Appendix A.1 and
    # base64url encoding the result yields this BASE64URL(JWS Signature) value:
    subtest "draft-ietf-jose-json-web-signature-41" => sub {
        my $base64_sig = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
        # If previous tests passed, then this is fine compared to
        # constructing it from raw strings.
        my $key = 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow';
        # $key = encode_base64url qq|{"kty":"oct",\015\012 "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}|;
#        $key = qq|{"kty":"oct",\015\012 "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}|;

        my $payload = join ".", $base64_header, $base64_claims;
        is $payload, 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ', "Payload looks right";

        my $digest = hmac_sha256_base64($payload, $key);
        is $digest, $base64_sig, "Signature matches computed digest";

        $digest = Digest::SHA::sha256_base64($payload, $key);
        is $digest, $base64_sig, "Signature matches computed digest";
        # $digest = sha256_base64($data, $key);
        # join ".", $base64_header, $base64_claims;
        #{"kty":"oct",
        # "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}


    };

    done_testing();
};


done_testing();

__DATA__
