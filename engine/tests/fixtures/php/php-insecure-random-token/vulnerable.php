<?php
$token = mt_rand();
$csrf_token = md5(uniqid());
$resetCode = rand(1000, 9999);
