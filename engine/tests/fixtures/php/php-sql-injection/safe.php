<?php
function a($conn) {
    $id = (int) $_GET['id'];
    mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
}
function b($db) {
    $n = mysqli_real_escape_string($db, $_POST['n']);
    $db->query("SELECT * FROM t WHERE n = '" . $n . "'");
}
function c($conn) {
    mysqli_query($conn, "SELECT 1");
}
