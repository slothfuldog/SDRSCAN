<?php
$db_password = getenv('DB_PASSWORD');
$password = '';
define('APP_NAME', 'sdrscan-demo');
$config = ['name' => 'demo', 'secret' => getenv('APP_SECRET')];
$token = 'x';
