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


    public $caKey;


    public $caCert;


    public function generateCetificateAuthority($force = false)
    {
        if (! is_dir($this->getCaDir())) {
            if (! mkdir($this->getCaDir())) {
                \Yii::error('Unable to create CA Directory','opensslca');
                return false;
            } else {
                mkdir($this->getCaDir() . "/keys");
                mkdir($this->getCaDir() . "/certs");
            }
        }

        if (! $force && file_exists($this->getCaKeyFile())) {
            \Yii::error('CA Key Exists, force not set','opensslca');
            return false;
        }

        if (! $force && file_exists($this->getCaCertFile())) {
            \Yii::error('CA Cert Exists, force not set','opensslca');
            return false;
        }

        $pkey = $this->generatePrivateKey('1001');

        //print_r($pkey); die();

        if (! openssl_pkey_export_to_file($pkey, $this->getcaKeyFile(), $this->password)) {
            \Yii::error('Unable to write CA Key','opensslca');
            return false;
        }
        chmod($this->getCaKeyFile(), 0400);


        if (! file_put_contents($this->getSerialFile(), '1001', LOCK_EX)) {
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
        openssl_x509_export_to_file($cacert, $this->getCaDir() . "/certs/1001" );

        openssl_x509_export_to_file($cacert, $this->caCertFile);

        while (($e = openssl_error_string()) !== false) {
            \Yii::warning($e,'Opensslca::generateCetificateAuthority');
        }

        return true;
    }



    public function generateCertificateRevocationList()
    {

    }


    public function revokeCertificate($cert)
    {

    }


    public function signCertificate($csr, $serial, $days, $configargs = null)
    {
       if (is_null($configargs)) {
            $configargs = [
                "digest_alg" => "sha512",
                'x509_extensions' => 'v3_req',
            ];
        }

        $cacert = openssl_csr_sign($csr, $this->getCaCert(), $this->getCaKey(), $days, $configargs, intval($serial));

        openssl_x509_export_to_file($cacert, $this->getCaDir() . "/certs/" . $serial);

        return $cacert;
    }


    public function createCertificatSigningRequest($dn, $pkey, $configargs = null)
    {
        if (is_null($configargs)) {
            $configargs = [
                "digest_alg" => "sha512",
                'x509_extensions' => 'v3_req',
            ];
        }
        //$configargs['config'] = $this->getSslConfig();

        $signDn = $this->dn_base;

        foreach ($dn as $key=>$value){
            $signDn[$key] = $value;
        }

        while (($e = openssl_error_string()) !== false) {
            \Yii::warning($e,'Opensslca::createCertificatSigningRequest');
        }

        return openssl_csr_new($signDn, $pkey, $configargs);
    }


    public function generatePrivateKey($sn, $configargsIn = [])
    {
        $configargs = [
            "digest_alg" => "sha512",
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ];
        //echo $this->getSslConfig();

        foreach ($configargsIn as $key=>$value) {
            $configargs[$key] = $value;
        }

        $pkey = openssl_pkey_new($configargs);

        if (! openssl_pkey_export_to_file($pkey, $this->getCaDir() . "/keys/" . $sn, $this->password)) {
            \Yii::error('Unable to write key '.$sn,'opensslca');
        }
        chmod($this->getCaDir() . "/keys/" . $sn, 0400);

        while (($e = openssl_error_string()) !== false) {
            \Yii::warning($e,'Opensslca::generatePrivateKey');
        }

        return $pkey;
    }


    public function privateKeyToString($pkey, $password = null)
    {
        $ouput = false;
        if (!openssl_pkey_export($pkey, $output, $password)) {
            while (($e = openssl_error_string()) !== false) {
                \Yii::warning($e,'Opensslca::privateKeyToString');
            }
        }
        return $output;
    }

    public function certificateToString($cert, $notext = true)
    {
        $ouput = false;
        if (!openssl_x509_export($cert, $output, $notext)) {
            while (($e = openssl_error_string()) !== false) {
                \Yii::warning($e,'Opensslca::privateKeyToString');
            }
        }
        return $output;
    }


    public function getCaDir()
    {
        return str_replace('@app', \Yii::$app->basePath, $this->ca_dir);
    }

    public function getCaKeyFile()
    {
        if (!isset($this->caKeyFile)) {
            $this->caKeyFile = $this->getCaDir() . "/ca_key.pem";
        }
        return $this->caKeyFile;
    }

    public function getCaCertFile()
    {
        if (!isset($this->caCertFile)) {
            $this->caCertFile = $this->getCaDir() . "/ca_cert.pem";
        }
        return $this->caCertFile;
    }

    public function getSerialFile()
    {
        if (!isset($this->serialFile)) {
            $this->serialFile = $this->getCaDir() . "/ca_serial";
        }
        return $this->serialFile;
    }

    public function getSslConfig()
    {
        if (file_exists($this->getCaDir() . "/openssl.cnf")) {
            return $this->getCaDir() . "/openssl.cnf";
        }
        return dirname(__FILE__) . "/openssl.cnf";
    }

    public function getNextSerial()
    {
        $sn = (int) file_get_contents($this->getSerialFile());
        $sn++;
        if (! file_put_contents($this->getSerialFile(), $sn, LOCK_EX)) {
            \Yii::error('Unable to write serial file.','opensslca');
            return false;
        }
        return $sn;
    }

    public function getCaKey()
    {
        if (! $this->caKey) {
            $this->caKey = openssl_pkey_get_private("file://".$this->getCaKeyFile(), $this->password);
        }

        while (($e = openssl_error_string()) !== false) {
            \Yii::warning($e,'Opensslca::getCaKey');
        }

        return $this->caKey;
    }

    public function getCaCert()
    {
        if (! $this->caCert) {
            $this->caCert = openssl_x509_read("file://".$this->getCaCertFile());
        }

        while (($e = openssl_error_string()) !== false) {
            \Yii::warning($e,'Opensslca::getCaCert');
        }

        return $this->caCert;
    }


    public function getCaSubject()
    {
        if (file_exists($this->getCaCertFile())) {
            $cert = $this->getCaCert();
            $fields = openssl_x509_parse($cert);
            return $fields['name'];
        } else {
            return "CA has not been created.";
        }
    }


    public function getCertSubject($file)
    {
        if (
            (file_exists($file)) &&
            ($cert = openssl_x509_read("file://".$this->getCaCertFile())) &&
            ($fields = openssl_x509_parse($cert))
        ) {
            return $fields['name'];
        } else {
            return "*** unable to get subect from file ***";
        }
    }
}
