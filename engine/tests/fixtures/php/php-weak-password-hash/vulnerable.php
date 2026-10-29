<?php
$hash = md5($password);
$h2 = sha1($_POST['pass']);
$h3 = md5($user_pwd . $salt);
