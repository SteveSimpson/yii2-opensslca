<?php

namespace ssimpson\opensslca;

use Yii;
use yii\base\Component;

/**
 * This is just an example.
 */
class Opensslca extends Component
{
    public function generateCetificateAuthority()
    {
        $pkey = $this->generatePrivateKey();
        openssl_pkey_export_to_file($pkey, $outfilename, $password);


    }


    public function generateCertificateRevocationList()
    {

    }


    public function revokeCertificate($cert)
    {

    }


    public function signCertificate($csr)
    {
        openssl_csr_sign();
    }


    public function createCertificatSigningRequest()
    {

        openssl_csr_export($csr, $out);
    }


    public function generatePrivateKey($configargs = null)
    {
        if (is_null($configargs)) {
            $configargs = [
            "digest_alg" => "sha512",
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
            ];
        }

        return openssl_pkey_new($configargs);
    }
}
