<?php
$hash = password_hash($password, PASSWORD_DEFAULT);
$etag = md5($content);
$sum = sha1_file($path);
