<?php
include $_GET['page'];
$p = $_POST['p'];
require_once 'pages/' . $p . '.php';
