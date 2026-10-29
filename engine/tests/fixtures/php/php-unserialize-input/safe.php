<?php
$data = unserialize(file_get_contents('/etc/app/config.ser'));
$j = json_decode($_POST['blob'], true);
