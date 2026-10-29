<?php
$data = unserialize($_COOKIE['prefs']);
$raw = $_POST['blob'];
$obj = unserialize($raw);
