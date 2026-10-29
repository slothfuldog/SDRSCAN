<?php
function a($conn) {
    $id = $_GET['id'];
    mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
}
function b($db) {
    $db->query("SELECT * FROM t WHERE n = '" . $_POST['n'] . "'");
}
function c($conn) {
    $q = "SELECT * FROM t WHERE x = ";
    $q .= $_GET['x'];
    mysql_query($q);
}
