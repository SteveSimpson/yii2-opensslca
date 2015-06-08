<?php

namespace app\commands;

use yii\console\Controller;
use \app\models\core\Migration as CoreMigration;
use \app\models\rt\Migration as RtMigration;
use \app\models\sc\Migration as ScMigration;
use ssimpson\opensslca\Opensslca;

/**
 * This implements a minimal Certificate Authority using Opensslca
 *
 * @author Steve Simpson
 * @since 2.0
 */
class CaController extends Controller
{
    function __construct($id, $module, $config = []) {
        parent::__construct($id, $module, $config);
    }

    /**
     * This command imports the
     * @param string $path the path to file to import
     */
    public function actionIndex()
    {
        $ca = \Yii::$app->opensslca;

        echo "Current CA: " . $ca->getCaSubject() ."\n\n";
        echo "Usage:\n";
        echo " ./yii ca/create         -- create the initial Certificate Authority\n";
        echo " ./yii ca/create --force -- create & overwritie the existing Certificate Authority\n";
        echo "\n";
        echo " ./yii ca/cert-with-key <common name>  [<days> = 365]  -- create a private key & certificate in a single file sent to stdout\n";
        echo "\n";
        echo " ./yii ca/list           -- list certs that have been created.\n";
        echo " ./yii ca/crl            -- Generates a CRL in ca/crl.pem.\n";

        echo "\n";
    }

    public function actionCreate($opts=null)
    {
        $ca = \Yii::$app->opensslca;

        $force = false;
        if ($opts == "--force") {
            $force = true;
        }

        if ($ca->generateCetificateAuthority($force)) {
            echo "CA Created\n";
        } else {
            echo "Error creating CA, check logs.\n";
        }
    }

    public function actionCertWithKey($cn, $days=365)
    {
        if ($cn=='') {
            echo "Please specifiy the cn for usage with this function.\n";
            return;
        }

        /* @var $ca Opensslca */
        $ca = \Yii::$app->opensslca;


        $sn = $ca->getNextSerial();

        $pkey = $ca->generatePrivateKey($sn);

        $dn = ['commonName'=>$cn ];

        $csr = $ca->createCertificatSigningRequest($dn, $pkey);

        $cert = $ca->signCertificate($csr, $sn, $days);

        echo $ca->privateKeyToString($pkey);
        echo $ca->certificateToString($cert);
    }

    public function actionRevoke()
    {
        $argv=$_SERVER['argv'];

        $ca = \Yii::$app->opensslca;

        if ((count($argv) == 4) ||  (count($argv) == 5)) {
            $sn = $argv[2];
            $reason = $argv[3];

            if (count($argv) == 4) {
                $success = $ca->revokeCertificate($sn,$reason,'revoke');
            } else {
                $success = $ca->revokeCertificate($sn,$reason,'revoke',$argv[4]);
            }
        } else {
            echo "Usage: \n";
            echo "  ./yii ca/revoke <sn> <reason> <date=now>\n";

            echo "\n  Reasons:\n";
            foreach ($ca::$crlReasons as $id=>$reason) {
                echo "    $id => $reason\n";
            }

            echo "\n";
        }
    }

    public function actionHold()
    {
        $argv=$_SERVER['argv'];

        $ca = \Yii::$app->opensslca;

        if ((count($argv) == 3) ||  (count($argv) == 4)) {
            $sn = $argv[2];

            if (count($argv) == 3) {
                $success = $ca->revokeCertificate($sn,6,'hold');
            } else {
                $success = $ca->revokeCertificate($sn,6,'hold',$argv[3]);
            }
        } else {
            echo "Usage: \n";
            echo "  ./yii ca/hold <sn> <date=now>\n";

            echo "\n";
        }
    }

    public function actionList()
    {
        $ca = \Yii::$app->opensslca;

        echo "Certificates Issued: \n";
        foreach (glob($ca->getCaDir() . "/certs/*") as $cert) {
            echo "  " . basename($cert) . ": " . $ca->getCertInfo($cert)['name'] ."\n";
        }
    }

    public function actionCrl()
    {
        $ca = \Yii::$app->opensslca;

        $crl = $ca->generateCertificateRevocationList();
        echo $crl . "\n";
    }
}
