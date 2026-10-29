<?php
header('Location: /home.php');
header('Content-Type: text/plain');
header('X-Next: ' . $_GET['n']);
