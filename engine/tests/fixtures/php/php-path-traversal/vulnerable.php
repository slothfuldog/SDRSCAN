<?php
$f = $_GET['file'];
$data = file_get_contents('/var/data/' . $f);
unlink($_POST['path']);
$h = fopen($f, 'r');
