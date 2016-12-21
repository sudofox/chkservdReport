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
	ini_set("memory_limit", (preg_replace("/[^0-9]/", "", ini_get("memory_limit") + 2) . "M")); // Allocate a small amount of additional memory so the shutdown function can complete.
	gc_collect_cycles();
	$error = error_get_last();
	if (preg_match("/Allowed memory size of/", $error["message"])) {
		if (posix_isatty(STDOUT)) {
			echo (exec("tput setaf 1") . "Memory limit of $memory_limit has been reached before parsing could be completed. Try setting the memory_limit manually with the -m flag (e.g. -m128M)." . exec("tput sgr0") . "\n");
		}
		else {
			echo ("Memory limit of $memory_limit has been reached before parsing could be completed. Try setting the memory_limit manually with the -m flag (e.g. -m128M).\n");
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
	public $interruptedChecks = array();

	// -- Function Name : loadEntry
	// -- Params : $input
	// -- Purpose : parses all data out of a single chkservd log entry.
	// -- Currently returns false if it is presented with an invalid service check. otherwise, returns entryData array
	function loadEntry($input) {

		// Should be given only one chkservd log section, will chop off rest if more is given.
		// Pull out our Chkservd log block entry...pull first one if more than one are provided for some reason

		preg_match_all("/Service\ Check\ Started.*?Service\ Check\ (Interrupted|Finished)/sm", $input, $entries);
		$entry = current(current($entries));

		// TODO: Remove
		// old check to make absolutely sure that this is a service check that has completed in its entirety
		// Commented out for now as we will now accept interrupted service checks
		// if (strpos($entry, "Service Check Interrupted") !== false): return false; endif; // return false, this check is invalid as it was interrupted

		// If our VERY FIRST check is an interrupted one, then we will throw it out. We need a full services list to use, which an interrupted check cannot always provide.

		$interrupted = false;

		if (strpos($entry, "Service Check Interupted") !== false) {
			if ($this->firstCheck) {
				return false; // First service check was interrupted. Ignore this one and count the next as the real first service check.
			} else {
				$interrupted = true;
			}
		}

		// get timestamp of service check
		preg_match_all("/(?<=\[)[0-9]{4}\-.+?(?=\] Service\ check)/", $entry, $entry_timestamp);
		$entry_timestamp = strtotime(current(current($entry_timestamp)));

		// Pull out the service check results
		preg_match_all("/Service\ check\ \.(.*)Done/smi", $entry, $this->serviceCheckResults);
		preg_match_all("/[^\.\.\.][_\-a-zA-Z0-9]{1,}\ \[(too\ soon\ after\ restart\ to\ check|(\[|).+?(?=\]\])\])\]/smi", current(array_pop($this->serviceCheckResults)), $this->serviceCheckResults);

		$this->serviceCheckResults = current($this->serviceCheckResults);
		// Generate array of service names in same order as $serviceCheckResults
		$servicesList = array();
		foreach($this->serviceCheckResults as $entry) {
			$entry = explode(" ", $entry);
			$servicesList[] =  $entry[0];
		}

		$this->servicesList = $servicesList;

		// Parse service checks into associative array

		$serviceChecks_assoc = array();

		foreach($this->serviceCheckResults as &$serviceCheckResult) {
			$serviceName = explode(" ", $serviceCheckResult);
			$serviceName = $serviceName[0];
			$serviceChecks_assoc[$serviceName] = $this->explodeServiceCheckLine($serviceCheckResult);
		}

		foreach ($serviceChecks_assoc as $service) {
			$serviceInfo =  $this->analyzeServiceCheck($service);
			$entryData["services"][$serviceInfo["service_name"]] = $serviceInfo;
		}

		// TODO: Move this elsewhere?
		// TODO: When faced with an interrupted service check, this will produce invalid results based on incomplete data.
		// TODO: May want to simply skip the monitoring settings check until we have a service check that finished.

		// TODO: If the very first service check is interrupted, we may want to just skip it entirely and throw it out

		// Detect if service monitoring has been disabled for a service

		if (!$interrupted) {

			if ($this->firstCheck) {
				$this->firstCheck = false;
				$this->monitoredServices = $servicesList; // fill $monitoredService and proceed as normal;
			} else {
				if (!(count(array_diff($servicesList, $this->monitoredServices)) == 0 && count(array_diff($this->monitoredServices, $servicesList)) == 0)) {
					$newServices = array_diff($servicesList, $this->monitoredServices);
					$removedServices = array_diff($this->monitoredServices, $servicesList);
					foreach ($newServices as $newService) {
						$entryData["services"][$newService]["monitoring_enabled"] = true;
					}
					foreach($removedServices as $removedService) {
						$entryData["services"][$removedService]["monitoring_disabled"] = true;
						$entryData["services"][$removedService]["service_name"] = $removedService;
					}
				}
			}
			$this->monitoredServices = $servicesList;
		}
	$entryData["timestamp"] = $entry_timestamp;
	$entryData["interrupted"] = $interrupted;
	return $entryData;

	}

	// -- Function Name : explodeServiceCheckLine
	// -- Params : $checkOutput
	// -- Purpose : Pull information from a service check line
	function explodeServiceCheckLine($checkOutput) {
		$serviceCheckRegex = "/(Restarting\ ([_\-a-zA-Z0-9]{1,})\.\.\.\.|TCP\ Transaction\ Log.+?(?=Died)Died(?!=\[)|\[check\ command:(\+|-|\?|N\/A)\]|\[socket\ connect:(\+|-|\?|N\/A)\]|\[socket\ failure\ threshold:[0-9]{1,}\/[0-9]{1,}\]|\[could\ not\ determine\ status\]|\[no\ notification\ for\ unknown\ status\ due\ to\ upgrade\ in\ progress\]|\[too\ soon\ after\ restart\ to\ check\]|\[fail\ count:[0-9]{1,}\]|\[notify:(unknown|recovered|failed)\ service:.+?(?=\])\]|\[socket_service_auth:1\]|\[http_service_auth:1\])/ms";
		preg_match_all($serviceCheckRegex, $checkOutput, $serviceCheckData);
		$serviceCheckData = current($serviceCheckData);
		$serviceCheckData["service_name"] = explode(" ", $checkOutput);
		// Not part of original chkservd output, added so we can later obtain the service name.
		$serviceCheckData["service_name"] =  "[service_name:".$serviceCheckData["service_name"][0]."]";
		return $serviceCheckData;
		}

	// -- Function Name : extractRelevantEvents
	// -- Params : $checkData, $checkNumber
	// -- Purpose : Extracts relevant events from a service check, most notably downed/restored services

	function extractRelevantEvents($checkData, $checkNumber) {

		$output = array();

		foreach ($checkData as $service) {

			if 	(
				(isset($service["check_command"]) && $service["check_command"]  == "down")	||
				(isset($service["socket_connect"]) && $service["socket_connect"] == "down")	||
				isset($service["notification"])							||
				isset($service["socket_failure_threshold"])					||
				isset($service["monitoring_enabled"])						||
				isset($service["monitoring_disabled"])
				) {
                                        $output[$service["service_name"]] = $service;
                                }
		}

	return $output;

	}

	// -- Function Name : analyzeServiceCheck
	// -- Params : $checkOutput
	// -- Purpose : Pull information from a service check line
	function analyzeServiceCheck($serviceCheck) {

	$serviceBreakdown = array();
		foreach($serviceCheck as $attribute) {
			switch ($attribute) {
				case (preg_match("/\[check\ command:(\+|-|\?|N\/A)\]/ms", $attribute) ? $attribute : !$attribute) :
					preg_match("/\[check\ command:(\+|-|\?|N\/A)\]/ms", $attribute, $attributeData);
					if ($attributeData[1] == "+") {
					$serviceBreakdown["check_command"] = "up";
					} elseif ($attributeData[1] == "-") {
						$serviceBreakdown["check_command"] = "down";
					} elseif ($attributeData[1] == "?") {
						$serviceBreakdown["check_command"] = "unknown";
					} elseif ($attributeData[1] == "N/A") {
						$serviceBreakdown["check_command"] = "other";
					}
				break;

                               	case (preg_match("/\[socket\ connect:(\+|-|\?|N\/A)\]/ms", $attribute) ? $attribute : !$attribute) :

					preg_match("/\[socket\ connect:(\+|-|\?|N\/A)\]/ms", $attribute, $attributeData);

					 if ($attributeData[1] == "+") {
                                                $serviceBreakdown["socket_connect"] = "up";
                                        } elseif ($attributeData[1] == "-") {
                                               	$serviceBreakdown["socket_connect"] = "down";
                                       	} elseif ($attributeData[1] == "?") {
                                               	$serviceBreakdown["socket_connect"] = "unknown";
                                        } elseif ($attributeData[1] == "N/A") {
                                                $serviceBreakdown["socket_connect"] = "other";
                                        }


				break;
                                case (preg_match("/\[socket\ failure\ threshold:([0-9]{1,})\/([0-9]{1,})\]/ms", $attribute) ? $attribute : !$attribute) :
					preg_match("/\[socket\ failure\ threshold:([0-9]{1,})\/([0-9]{1,})\]/ms", $attribute, $attributeData);
					// Test if the socket failure threshold is equal to or more than 1. (e.g. 4/3). If for some reason we're dividing by zero, just mark it down.
					$serviceBreakdown["socket_failure_threshold"] = ($attributeData[2] == 0) ? 1 : ($attributeData[1] / $attributeData[2]);

				break;

				case (preg_match("/\[too\ soon\ after\ restart\ to\ check\]/", $attribute) ? $attribute: !$attribute):
					$serviceBreakdown["check_postponed_due_to_recent_service_restart"] = true;

				break;
				case (preg_match("/\[socket_service_auth:1\]/", $attribute) ? $attribute: !$attribute):

					$serviceBreakdown["socket_service_auth"] = true; // not entirely sure if this is logged when auth succeeds... eh.

				break;
				case (preg_match("/\[http_service_auth:1\]/", $attribute) ? $attribute: !$attribute):

					$serviceBreakdown["http_service_auth"] = true; // ?

				break;
				case (preg_match("/\[notify:(failed|recovered)\ service:.+?(?=\])\]/", $attribute) ? $attribute : !$attribute):
					preg_match("/\[notify:(failed|recovered)\ service:.+?(?=\])\]/", $attribute, $attributeData);
					if ($attributeData[1] == "failed") {
						$serviceBreakdown["notification"] = "failed";
					} elseif ($attributeData[1] == "recovered") {
						$serviceBreakdown["notification"] = "recovered";
					}

					break;
				case (preg_match("/Restarting\ ([_\-A-Za-z0-9]{1,})\.\.\.\./", $attribute) ? $attribute: !$attribute):
					$serviceBreakdown["restart_attempted"] = true;
				break;

				case (preg_match("/\[fail\ count:([0-9]{1,})\]/", $attribute) ? $attribute: !$attribute):
					preg_match("/\[fail\ count:([0-9]{1,})\]/", $attribute, $attributeData);
					$serviceBreakdown["fail_count"] = $attributeData[1];

				break;
				case (preg_match("/\[service_name:([_\-A-Za-z0-9\,]{1,})\]/", $attribute) ? $attribute: !$attribute):
					preg_match("/\[service_name:([_\-A-Za-z0-9\,]{1,})\]/", $attribute, $attributeData);
					$serviceBreakdown["service_name"] = $attributeData[1];
				break;
				case ((preg_match_all("/TCP\ Transaction\ Log.+?(?=Died)Died(?!=\[)/ms", $attribute) > 0) ? $attribute: !$attribute):
					preg_match_all("/TCP\ Transaction\ Log.+?(?=Died)Died(?!=\[)/ms", $attribute, $attributeData);
					$attributeData = current($attributeData);
					$serviceBreakdown["tcp_transaction_log"] = $attributeData[0];
				break;
				default:

				// echo	exec("tput setaf 1");
					echo "Unhandled attribute:  \"$attribute\"\n";
				// echo	exec("tput sgr0");
				break;


			}
	}

$serviceBreakdown = array("service_name" => $serviceBreakdown["service_name"]) + $serviceBreakdown; // shift the service_name attribute to the beginning of the array

return $serviceBreakdown;
}	// end function





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

// Parse input data into unique elements with one raw service check per element:
preg_match_all("/Service\ Check\ Started.*?Service\ Check\ (Interrupted|Finished)/sm", $logdata, $splitLogEntries);


// Interrupted service checks will mess up inter-check service state tracking within the parser.
// Mark services checks that were interrupted (with a boolean value)

foreach(current($splitLogEntries) as $index => $entry) {

	if ($splitLogEntries[1][$index] == "Interrupted") {
		$parser->interruptedChecks[$index] = true;
		continue;
	}

}

unset($splitLogEntries[1]);

// This is where the parsing of each check starts
foreach ($splitLogEntries[0] as $index => $entry) {
	$check = $parser->loadEntry($entry);
	if ($check === false) { continue; } // loadEntry returning false means that the check must be thrown out.
	$parser->eventList[$check["timestamp"]]["services"] = $parser->extractRelevantEvents($check["services"], $index);
	$parser->eventList[$check["timestamp"]]["interrupted"] = (isset($this->interruptedChecks[$index]) && $this->interruptedChecks[$index]);
	$parser->eventList[$check["timestamp"]]["timestamp"] = $check["timestamp"];
	$parser->eventList[$check["timestamp"]]["formatted_timestamp"] = strftime("%F %T %z", $check["timestamp"]);
}

unset($splitLogEntries);

// TODO: We now have our parsed entries, and know whether or not the check was interrupted. Service monitoring changes are not checked for with
// TODO: interrupted service checks. When parsing events into the timeline, we'll iterate over the systemState to check for inconsistencies
// TODO: if the previous check was interrupted.

// TODO: Unsure whether the data within the interrupted check is usable or not, we might be able to update the systemState partially from what's
// TODO: there, and fill in the rest from the next *completed* service check



var_export($parser->eventList);
