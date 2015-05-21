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
    /**
     * from config
     * Password for encrypting the CA Key
     * @var string
     */
    public $password;

    /**
     * from config
     * Directory for storing CA Files
     * use getCaDir() instead
     *
     * @var string
     */
    public $ca_dir;

    /**
     * from config
     * The Base Subject for our Certificate Authority
     * @var string
     */
    public $base_subj;


    public $caKeyFile;


    public $caCertFile;


    public $serialFile;


    public function generateCetificateAuthority($force = false)
    {
        if (! is_dir($this->ca_dir)) {
            if (! mkdir($this->ca_dir,'0700')) {
                \Yii::error('Unable to create CA Directory','opensslca');
                return false;
            }
        }

        $caKeyFile  = $this->ca_dir . "ca_key.pem";
        $caCertFile = $this->ca_dir . "ca_cert.pem";

        $sbject = $this->base_subj . "/CN=Root Certificate Authority";

        if (! $force && file_exists($caKeyFile)) {
            \Yii::error('CA Key Exists, force not set','opensslca');
            return false;
        }

        if (! $force && file_exists($caCertFile)) {
            \Yii::error('CA Key Exists, force not set','opensslca');
            return false;
        }

        $pkey = $this->generatePrivateKey();

        if (! openssl_pkey_export_to_file($pkey, $caKeyFile, $this->password)) {
            \Yii::error('Unable to write CA Key','opensslca');
            return false;
        }

        if (!file_put_contents($this->serialFile, '1001', LOCK_EX)) {
            \Yii::error('Unable to write serial file.','opensslca');
            return false;
        }

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

    public function getca_dir()
    {
        return str_replace('@app', \Yii::$app->basePath, $this->ca_dir);
    }

    public function getcaKeyFile()
    {
        if (!isset($this->caKeyFile)) {
            $this->caKeyFile = $this->ca_dir . "ca_key.pem";
        }
        return $this->caKeyFile;
    }

    public function getcaCertFile()
    {
        if (!isset($this->caCertFile)) {
            $this->caCertFile = $this->ca_dir . "ca_cert.pem";
        }
        return $this->caCertFile;
    }

    public function getserialFile()
    {
        if (!isset($this->serialFile)) {
            $this->serialFile = $this->ca_dir . "ca_serial";
        }
        return $this->serialFile;
    }
}
