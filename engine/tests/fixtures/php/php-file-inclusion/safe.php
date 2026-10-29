<?php
include 'header.php';
$p = basename($_GET['p']);
require_once 'pages/' . $p . '.php';
