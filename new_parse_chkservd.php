#!/usr/bin/env php
<?php
/*
*  Chkservd/Tailwatch log parser by aburk (aburk@liquidweb.com)
*  Parses a chkservd.log file and returns a pretty timeline of service failures and related details
*
*/

date_default_timezone_set("America/New_York");

// If you pass a large chkservd logfile to the script, it can hit the memory limit. The following function runs when the script exits.
// If it exited due to reaching the memory limit, it will print a friendly message explaining how to set a custom memory limit.

function shutdown_handler()
{
	$memory_limit = ini_get("memory_limit");
	ini_set("memory_limit", (preg_replace("/[^0-9]/", "", ini_get("memory_limit") + 2) . "M")); // Allocate a small amount of additional memory so the shutdown function can complete. Works with +1M but I've set it to 3M just in case.
	gc_collect_cycles();
	$error = error_get_last();
	if (preg_match("/Allowed memory size of/", $error["message"])) {
		if (posix_isatty(STDOUT)) {
			echo (exec("tput setaf 1") . "Memory limit of " . $memory_limit . " has been reached before parsing could be completed. Try setting the memory_limit manually with the -m flag (e.g. -m128M)." . exec("tput sgr0") . "\n");
		}
		else {
			echo ("Memory limit of " . $memory_limit . " has been reached before parsing could be completed. Try setting the memory_limit manually with the -m flag (e.g. -m128M).\n");
		}
	}
}

register_shutdown_function("shutdown_handler");

// Begin main class

class chkservdParser

{

                var $monitoredServices = array();       // array of the names of monitored services. Used for detecting when monitoring for a service is disabled.
                var $firstCheck = true;                 // Used to check if we are processing our first service check or not
                public $systemState = array();          // List of unresolved down services, used for comparison between previous and next check
                public $timeline = array();             // This timeline will be directly formatted into the final report of service failures and recoveries.
                public $eventList = array();            // A list of when things happen: services gone down, back up, restart attempts, service monitoring settings changes, etc.
                public $servicesList = array();         // list of services, the names being in the same order as $serviceCheckResults
                public $serviceCheckResults = array();
		public $interriptedChecks = array();



}

// End main class
// Usage

$usage = <<<EOD
Usage: ./parse_chkservd.php -f <filename> [<additional arguments>]

If you wish to pass the arguments in any order, you must omit the space after the flag letter.

(e.g. -fchkservd.log -m500M -n100000)

Required arguments
-f	filename of chkservd logfile

Optional arguments
-n	number of lines to read from the end of the file
-m	manually set the memory_limit - be careful with this! ( e.g. -m128M )

Verbosity and visual options (these are optional arguments)

-vt	Show timeline event explanations
-vp	Show when we reach each step in script execution.
-vc	Colorize output regardless of whether it is entering a pipe to a file/second program or not.


EOD;
$options = getopt("f:n::m::v:");
$parser = new chkservdParser;

// Argument validation
// Manual memory limit

if (isset($options["m"])) {
	if (!preg_match("/^[0-9]{1,}M$/", $options["m"])) {
		exit("Error: -m flag must be in format -m###M (e.g. -m128M)");
	}

	ini_set("memory_limit", $options["m"]);
}

// Filename

if (!isset($options["f"])) {
	exit($usage);
}

if (is_array($options["f"])) {
	exit("Error: You may only specify one file to read.\n\n$usage");
} // if multiple -f arguments are passed

if (!file_exists($options["f"])) {
	exit("Error: Could not open file {$options["f"]}\n");
} // if file does not exist

// Verbosity/visual options

if (isset($options["v"])) {

	// if there's just one verbosity flag

	if (!is_array($options["v"]) && is_string($options["v"])) {
		$flag = $options["v"];
		unset($options["v"]);
		$options["v"][$flag] = true;
	}
	else { // if there's multiple verbosity flags
		$verbosityFlags = array();
		foreach($options["v"] as $key => $flag) {
			$verbosityFlags[$flag] = true;
		}

		unset($options["v"]);
		foreach($verbosityFlags as $key => $flag) {
			$options["v"][$key] = true;
		}
	}
}

// if it's not set, set it to false (return value of isset)

$options["v"]["t"] = (isset($options["v"]["t"]));
$options["v"]["p"] = (isset($options["v"]["p"]));
$options["v"]["c"] = (isset($options["v"]["c"]));

// Should we force colorization of output?

$options["colorize"] = $options["v"]["c"] ? $options["v"]["c"] : posix_isatty(STDOUT);

if ($options["colorize"]) {
	$fmt["blue"] = exec("tput setaf 4");
	$fmt["yellow"] = exec("tput setaf 3");
	$fmt["green"] = exec("tput setaf 2");
	$fmt["red"] = exec("tput setaf 1");
	$fmt["bold"] = exec("tput bold");
	$fmt["dim"] = exec("tput dim");
	$fmt["reset"] = exec("tput sgr0");
}
else {
	$fmt["blue"] = "";
	$fmt["yellow"] = "";
	$fmt["green"] = "";
	$fmt["red"] = "";
	$fmt["bold"] = "";
	$fmt["dim"] = "";
	$fmt["reset"] = "";
}

// -n for number of lines from end to seek

$logdata = "";

if (isset($options["n"])) {
	if (!is_numeric($options["n"]) && $options["n"] > 0) {
		exit("Error: -n must be numeric and more than 0.\n\n$usage");
	}

	exec("tail -n" . escapeshellarg($options["n"]) . " " . escapeshellarg($options["f"]) , $logtail);
	foreach($logtail as $line) {
		$logdata.= $line . "\n";
	}
}
else {

	// TODO: <(cat file1.log file2.log) as a file descriptor only seems to make the script read the second file, find out if this can be compensated for in PHP

	if (preg_match("/^\/dev\/(fd\/[0-9]{1,})$/", $options["f"])) { // in case we're using a file descriptor instead of a real file
		preg_match("/^\/dev\/(fd\/[0-9]{1,})$/", $options["f"], $log_load_fd);
		$logdata = file_get_contents("php://" . $log_load_fd[1]);
	}
	else {
		$logdata = file_get_contents($options["f"]);
	}
}


if ($options["v"]["p"]) {	error_log("DEBUG: Loading log file...");	} // TODO: Debug

preg_match_all("/Service\ Check\ Started.*?Service\ Check\ (Interrupted|Finished)/sm", $logdata, $splitLogEntries); // parse input data into unique elements with one raw chkservd entry per element


// Interrupted service checks will mess up inter-check service state tracking within the parser.
// Mark services checks that were interrupted (with a boolean value)

foreach(current($splitLogEntries) as $index => $entry) {

	if ($splitLogEntries[1][$index] == "Interrupted") {
		$parser->interruptedServiceChecks[$index] = true;
		continue;
	}

}

unset($splitLogEntries[1]);

// This is where the parsing of each check starts
foreach ($splitLogEntries[0] as $index => $entry) {

}


