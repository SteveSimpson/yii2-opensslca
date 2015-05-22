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
    public $dn_base;

    /**
     * from config
     * The Common Name of the Certificate Authority
     * @var string
     */
    public $ca_cn;


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

        if (! file_put_contents($this->serialFile, '1001', LOCK_EX)) {
            \Yii::error('Unable to write serial file.','opensslca');
            return false;
        }

        $configargs = [
            "digest_alg" => "sha512",
            'x509_extensions' => 'v3_ca',
        ];

        $dn = ['commonName'=>$this->ca_cn ];

        $csr = $this->createCertificatSigningRequest($dn, $pkey, $configargs);

        // this is slightly different since this is a self-signed cert; cacert is null
        // use a 10 year CA
        $cacert = openssl_csr_sign($csr, null, $pkey, 3650, $configargs, '1001');

        openssl_x509_export_to_file($cacert, $this->caCertFile);

        return true;
    }



    public function generateCertificateRevocationList()
    {

    }


    public function revokeCertificate($cert)
    {

    }


    public function signCertificate($csr, $days)
    {
        $pkey = openssl_pkey_get_private("file://".$this->caKeyFile,$this->password);

        $configargs['config'] = $this->getSslConfig();

        //openssl_csr_sign($csr, );
    }


    public function createCertificatSigningRequest($dn, $pkey, $configargs = null)
    {
        if (is_null($configargs)) {
            $configargs = [
            "digest_alg" => "sha512",
            ];
        }
        $configargs['config'] = $this->getSslConfig();

        $signDn = $this->dn_base;

        foreach ($dn as $key=>$value){
            $signDn[$key] = $value;
        }

        return openssl_csr_new($dn, $pkey, $configargs);
    }


    public function generatePrivateKey($configargsIn = [])
    {

        $configargs = [
            "digest_alg" => "sha512",
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
            'config' => $this->getSslConfig(),
        ];

        foreach ($configargsIn as $key=>$value) {
            $configargs[$key] = $value;
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

    public function getSslConfig()
    {
        return dirname(__FILE__) . "/openssl.cnf";
    }

    public function getSerial()
    {

    }
}
