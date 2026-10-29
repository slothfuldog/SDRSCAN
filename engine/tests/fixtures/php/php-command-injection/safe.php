<?php
$host = escapeshellarg($_GET['host']);
system("ping -c 1 " . $host);
system("uptime");
$r = `uptime`;
