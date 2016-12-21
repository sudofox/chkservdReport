#!/usr/bin/env php
<?php

/*
*  Chkservd/Tailwatch log parser by aburk (aburk@liquidweb.com)
*  Parses a chkservd.log file and returns a pretty timeline of service failures and related details
*
*/

// If you pass a large chkservd logfile to the script, it can hit the memory limit. The following function runs when the script exits.
// If it exited due to reaching the memory limit, it will print a friendly message explaining how to set a custom memory limit.

function shutdown_handler() {

	$memory_limit = ini_get("memory_limit");
	ini_set("memory_limit", (preg_replace("/[^0-9]/","",ini_get("memory_limit")+2)."M")); // Allocate a small amount of additional memory so the shutdown function can complete. Works with +1M but I've set it to 3M just in case.
	gc_collect_cycles();
	$error = error_get_last();
	if (preg_match("/Allowed memory size of/",$error["message"])) {
		if (posix_isatty(STDOUT)) {
			echo(exec("tput setaf 1")."Memory limit of ".$memory_limit." has been reached before parsing could be completed. Try setting the memory_limit manually with the -m flag (e.g. -m128M).". exec("tput sgr0")."\n");
		} else {
		echo("Memory limit of ".$memory_limit." has been reached before parsing could be completed. Try setting the memory_limit manually with the -m flag (e.g. -m128M).\n");
                }
	}

}
register_shutdown_function("shutdown_handler");

// Begin main class

// End main class
