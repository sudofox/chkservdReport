#!/usr/bin/env php
<?php

// A test for reading chkservd log files block by block in an efficient manner.


$filename = $argv[1];

$logfile = fopen($filename,"r");

$log_entries = array();

while (!feof($logfile)) {
	$chunk = "";

	$line = fgets($logfile);
	if (preg_match("/Service\ Check\ (Started|Interrupted|Finished)/", $line)
	if (strpos($chunk,"Service Check Started")) echo "Service Check Finished";

sleep(1);
}
