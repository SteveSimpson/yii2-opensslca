<?php

namespace ssimpson\opensslca;

use Yii;
use yii\base\Component;

/**
 * This module should give you all the low level functions run a simple CA.
 *
 */
class Opensslca extends Component
{
    public $errorText = '';

    public function generateCetificateAuthority($force = false)
    {

        if (! $force && file_exists($caKeyFile)) {
            $this->errorText = 'CA Key Exists, force not set';
            return false;
        }

        if (! $force && file_exists($caCertFile)) {
            $this->errorText = 'CA Key Exists, force not set';
            return false;
        }

        $pkey = $this->generatePrivateKey();
        openssl_pkey_export_to_file($pkey, $cafilename, $password);

        return true;
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

    public function run()
    {
        return "Hello!";
    }
}
