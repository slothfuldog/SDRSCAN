<?php
$f = basename($_GET['file']);
$data = file_get_contents('/var/data/' . $f);
$h = fopen('/var/log/app.log', 'r');
