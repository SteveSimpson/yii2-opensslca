Yii2 OpenSSL CA
===============
This extension provides an easy interface to implement your own CA in the Yii2 framework.

Installation
------------

The preferred way to install this extension is through [composer](http://getcomposer.org/download/).

Either run

```
php composer.phar require --prefer-dist ssimpson/yii2-opensslca "*"
```

or add

```
"ssimpson/yii2-opensslca": "*"
```

to the require section of your `composer.json` file.


Usage
-----

Once the extension is installed, simply use it in your code by adding the following line to 
the components section of your @app/config/web.php or console.php :

```
'opensslca' => require(__DIR__ . '/opensslca.php'),
```

Then add the following detailed configuration : 

```
<?php
// @app/config/opensslca.php
return [
    'class'    => 'ssimpson\opensslca\Opensslca',
    'password' => 'secret',
    'ca_dir'   => '@app/ca',
];
```