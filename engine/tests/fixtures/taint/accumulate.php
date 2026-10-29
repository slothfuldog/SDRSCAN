<?php
function a() {
    $q = "x";
    $q = $q . $_GET['v'];
    echo $q;
    $r = "a";
    $r .= $_GET['b'];
    echo $r;
}
