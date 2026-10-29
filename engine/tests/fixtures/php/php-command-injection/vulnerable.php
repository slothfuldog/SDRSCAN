<?php
$host = $_GET['host'];
system("ping -c 1 " . $host);
$out = shell_exec("ls " . $_POST['dir']);
$r = `nslookup $host`;
