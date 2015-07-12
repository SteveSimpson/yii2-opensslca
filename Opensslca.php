<?php

namespace ssimpson\opensslca;

use Yii;
use yii\base\Component;
use yii\validators\BooleanValidator;

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

    /**
     * from config
     * Remake the CRL when revoking a certificate.
     * @var bool
     */
    public $crlWhenRevoke;

    /**
     * from config
     * Days until the CRL should expire
     * @var int
     */
    public $crlValidDays;

    /**
     * from config
     * Path to openssl binary
     * @var string
     */
    public $caOpensslBin;

    public $caKeyFile;

    public $caCertFile;

    public $crlFile;

    public $serialFile;

    public $caKey;

    public $caCert;

    public static $crlStates = array('revoke'=>'Revoked', 'hold'=>'Hold');

    public static $crlReasons = array(0=>'unspecified', 1=>'keyCompromise',
        2=>'CACompromise', 3=>'affiliationChanged', 4=>'superseded',
        5=>'cessationOfOperation',6=>'certificateHold',8=>'removeFromCRL',
        9=>'privilegeWithdrawn',10=>'AACompromise');

    /**
     *
     * @var array [cert_index] = ['state'=>$crlStates[?],  'reason'=>$crlReasons[], 'revokedDate'=>date]
     */
    private $crlSource = false;

    /**
     *
     * @var mixed false or array [cert_index] = ['issueDate'=>'', 'subject'=>'']
     */
    private $certSource = false;

    /**
     * The Local Time Zone, all functions here use GMT, but we don't want to change what is displayed to the user
     * @var string
     */
    private $localTz;


    public function init()
    {
        $this->localTz = date_default_timezone_get();
    }

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

    /**
     * @param int
     */
    public function generateCertificateRevocationList($daysCrlValid=null)
    {
        $this->updateIndexTxt();

        $cwd = $this->getCaDir();

        $tempFile = tempnam("/tmp", "ca_");

        $descriptorspec = array(
            0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
            1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
            2 => array("file", $tempFile, "w")   // stderr is a file to write to
        );

        if (is_null($daysCrlValid) or inval($daysCrlValid) == 0) {
            $daysCrlValid = intval($this->crlValidDays);
        } else {
            $daysCrlValid = intval($daysCrlValid);
        }

        $crlFile = escapeshellarg($this->getCrlFile());
        $keyFile = escapeshellarg($this->getCaKeyFile());
        $certFile = escapeshellarg($this->getCaCertFile());
        $confFile = escapeshellarg($this->getSslConfig());
        // generate CRL, needs cakey.pem password if cakey.pem has one

        $bin = 'openssl';
        if ($this->caOpensslBin != '') {
            $bin = escapeshellcmd($this->caOpensslBin);
        }

        $command = "$bin ca -gencrl -crldays $daysCrlValid -config $confFile -out $crlFile ".
            "-keyfile $keyFile -cert $certFile  -passin stdin";

        $pipes = [];

        $env = [];

        $process = proc_open($command, $descriptorspec, $pipes, $cwd, $env);
        if (is_resource($process)) {
            $written = fwrite($pipes[0], $this->password);
            fclose($pipes[0]);

            $stdout = stream_get_contents($pipes[1]);
            if ($stdout && $stdout != '') {
                \Yii::warning($stdout, 'Opensslca');
            }

            fclose($pipes[1]);

            //fclose($pipes[2]);

            $stdError = file_get_contents($tempFile);
            if ($stdError && $stdError != '') {
                \Yii::error('Process could not be started [' . $stdError . ']', 'Opensslca');
            }

            $return_value = proc_close($process);
        }

        if (file_exists($tempFile)) {
            unlink($tempFile);
        }

        return $stdout . ":" . $stdError . ":" . $return_value;
    }

    public function revokeCertificate($serialArray, $reason=0, $state='revoke', $date=null)
    {
        $this->loadCrlSource();

        if((! array_key_exists($reason, $this::$crlReasons)) || (! array_key_exists($state, $this::$crlStates))) {
            return false;
        }

        if (array_key_exists($sn, $this->crlSource) == false) {
            if (is_null($date)) {
                $date = date('D, d M Y H:i:s O');
            } else {
                $date = date('D, d M Y H:i:s O', strtotime($date));
            }
            foreach ($serialArray as $sn) {
                $this->crlSource[$sn]=['state'=>$state,'reason'=>$reason,'date'=>$date];
            }
        }
        if ($this->saveCrlSource()) {
            if ($this->crlWhenRevoke) {
                $this->generateCertificateRevocationList();
            }
            return true;
        } else {
            return false;
        }
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
        // realpath is required for proc_open in $this->generateCertificateRevocationList()
        return realpath(str_replace('@app', \Yii::$app->basePath, $this->ca_dir));
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

    public function getCrlSerialFile()
    {
        if (!isset($this->serialFile)) {
            $this->serialFile = $this->getCaDir() . "/crl_serial";
        }
        return $this->serialFile;
    }

    public function getCrlFile()
    {
        if (!isset($this->serialFile)) {
            $this->serialFile = $this->getCaDir() . "/crl.pem";
        }
        return $this->serialFile;
    }

    public function getSslConfig()
    {
        if (file_exists($this->getCaDir() . "/openssl.conf")) {
            return $this->getCaDir() . "/openssl.conf";
        }
        return dirname(__FILE__) . "/openssl.conf";
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

    public function getNextCrlSerial()
    {
        $sn = (int) @file_get_contents($this->getCrlSerialFile());
        $sn++;
        if (! file_put_contents($this->getCrlSerialFile(), $sn, LOCK_EX)) {
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


    public function getCertInfo($file)
    {
        if (
            (file_exists($file)) &&
            ($cert = openssl_x509_read("file://".$file)) &&
            ($fields = openssl_x509_parse($cert))
        ) {
            return $fields;
        } else {
            return "*** unable to get subect from file ***";
        }
    }


    /**
     * This could be a lot more complicated
     * ['id'=>cert_index, 'state'=>$crlStates[?],  'reason'=>$crlReasons[], 'revokedDate'=>date]
     */
    public function loadCrlSource()
    {
        date_default_timezone_set('UTC');
        $this->crlSource = [];
        $crlSource = $this->getCaDir() . "/crl_source";
        if (($handle = @fopen($crlSource, "r")) !== FALSE) {
            while (($data = fgetcsv($handle)) !== FALSE) {
                $this->crlSource[$data[0]] = [
                    'state'  => $data[1],
                    'reason' => $data[2],
                    'date'   => $data[3],
                ];
            }
            fclose($handle);
        }
        date_default_timezone_set($this->localTz);
    }


    /**
     * [cert_index] = ['issueDate'=>'', 'name'=>'']
     * might cache in a csv file: cert_index,issueDate,subject
     */
    public function loadCertSource()
    {
        date_default_timezone_set('UTC');

        $this->certSource = [];
        foreach (glob($this->getCaDir() . "/certs/*") as $certFile) {
            $cert = $this->getCertInfo($certFile);
            if ($cert) {
                $this->certSource[basename($certFile)] = ['name' => $cert['name'], 'expireDate' => $cert['validTo']];
            } else {
                \Yii::error("Cert source error with: $certFile", 'Opensslca::loadCertSource');
            }
        }

        date_default_timezone_set($this->localTz);
    }

    public function saveCrlSource()
    {
        $crlSource = $this->getCaDir() . "/crl_source";

        if (!$this->crlSource) { return false; }
        date_default_timezone_set('UTC');

        try {
            $tmpfname = tempnam($this->getCaDir(), "tmpcrl_");
            if (($handle = fopen($tmpfname, "w")) !== FALSE) {
                foreach ($this->crlSource as $id=>$v) {
                    $fields=[$id, $v['state'], $v['reason'], $v['date']];
                    fputcsv($handle, $fields);
                }
                fclose($handle);
                if(!rename($tmpfname,$crlSource)) {
                    \Yii::error("CRL Source not updated. Could not rename: $tmpfname to: $crlSource", 'Opensslca::saveCrlSource');
                }
            } else {
                \Yii::error("CRL Source not updated. Could not open: $tmpfname", 'Opensslca::saveCrlSource');
            }
        } catch (Exception $e) {
            \Yii::error("Exception: ". $e, 'Opensslca');
            date_default_timezone_set($this->localTz);
            return false;
        }
        date_default_timezone_set($this->localTz);
        return true;
    }

    public function updateIndexTxt()
    {
        date_default_timezone_set('UTC');
        $this->loadCertSource();
        $this->loadCrlSource();

        $output = [];
        foreach ($this->certSource as $id => $cert) {
            if (array_key_exists($id, $this->crlSource)) {
                $status = "R";
                if (array_key_exists($this->crlSource[$id]['reason'],$this::$crlReasons)) {
                    $revokedReason = $this::$crlReasons[$this->crlSource[$id]['reason']];
                } else {
                    $revokedReason = "";
                }
                $revokedDate = date("ymdHis\Z",strtotime($this->crlSource[$id]['date']));
                if ($revokedReason != '') {
                    $revokedDate .= "," . $revokedReason;
                }

            } else {
                $status = "V";
                $revokedDate = "";
            }
            $output[] = $status . "\t" . $cert['expireDate']  . "\t" . $revokedDate . "\t" . $id . "\tunknown\t" . $cert['name'] . "\n";
        }

        $indexFile = $this->getCaDir() . "/index.txt";
        try {
            $tmpfname = tempnam($this->getCaDir(), "tmpindex_");
            if (($handle = fopen($tmpfname, "w")) !== FALSE) {
                foreach ($output as $line) {
                    fwrite($handle, $line);
                }
                fclose($handle);
                if(!rename($tmpfname,$indexFile)) {
                    \Yii::error("index.txt not updated. Could not rename: $tmpfname to: $indexFile", 'Opensslca::updateIndexTxt');
                }
            } else {
                \Yii::error("index.txt not updated. Could not open: $tmpfname", 'Opensslca::updateIndexTxt');
            }
        } catch (Exception $e) {
            \Yii::error("Exception: ". $e, 'Opensslca::updateIndexTxt');
            date_default_timezone_set($this->localTz);
            return false;
        }
        date_default_timezone_set($this->localTz);
        return true;
    }


}
