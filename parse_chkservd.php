#!/usr/bin/env php
<?php

	// by aburk
	// parse chkservd log and return a pretty summary of service failures and whatnot
	// chkservd entry parser
	class chkservdParser {
		var $checkTime;
		var $entryData;		// current log entry being processed.
		public $systemState = array();	// unresolved down services, used for comparison between previous and next check
		public $timeline = array();	// this is what will be directly formatted into the final report of service failures and recoveries.
		public $eventList = array();	// a list of when things happen: services gone down, back up, restart attempts, etc.
		public $servicesList = array();
		// list of services, the names being in the same order as $serviceCheckResults
		public $serviceCheckResults = array();

		// -- Function Name : loadEntry
		// -- Params : $input
		// -- Purpose : parses all data out of a single chkservd log entry.
		// -- Currently returns false if it is presented with an invalid service check. otherwise, returns entryData array.
		function loadEntry($input) {
			// Should be given only one chkservd log section, will chop off rest if more is given.
			// Pull out our Chkservd log block entry...pull first one if more than one are provided for some reason

			preg_match_all("/Service\ Check\ Started.*?Service\ Check\ (Interrupted|Finished)/sm", $input, $entries);
			$entry = current(current($entries));

			// check to make absolutely sure that this is a service check that has completed in its entirety
			if (strpos($entry, "Service Check Interrupted") !== false): return false; endif; // return false, this check is invalid as it was interrupted

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

			// Parse service checks into associative array of service data
			$serviceChecks_associative = array();

		foreach($this->serviceCheckResults as &$serviceCheckResult) {
			$serviceName = explode(" ", $serviceCheckResult);
			$serviceName = $serviceName[0];
			$serviceChecks_associative[$serviceName] = $this->explodeServiceCheckLine($serviceCheckResult);

		}



		foreach ($serviceChecks_associative as $service) {
			$serviceInfo =	$this->analyzeServiceCheck($service);
			$this->entryData["services"][$serviceInfo["service_name"]] = $serviceInfo;

		}
		$this->entryData["timestamp"] = $entry_timestamp; // unix timestamp from service check

	return $this->entryData;

}

		// -- Function Name : extractRelevantEvents
		// -- Params : $checkData (one of the elements within the entryData array)
		// -- Purpose : Extracts relevant events from a service check, most notably downed/restored services

		function extractRelevantEvents($checkData) {

		$output = array();

		foreach($checkData as $service) {

		if (	(isset($service["check_command"]) && $service["check_command"] == "down") ||
			(isset($service["socket_connect"]) && $service["socket_connect"] == "down") ||
			 isset($service["notification"]) || isset($service["socket_failure_threshold"]) ) {
				$output[$service["service_name"]] = $service;

				}
			}

	return $output;

		}

		// -- Function Name : explainServiceCheckResult
		// -- Params :	$check
		// -- Purpose : Produces an array with human-readable information and color information about a particular service check. Does not do comparison.
		function explainServiceCheckResult($check) {

		// $fmt array is "format"
		$fmt["yellow"]	= exec("tput setaf 3");
		$fmt["green"]	= exec("tput setaf 2");
		$fmt["red"]	= exec("tput setaf 1");
		$fmt["bold"]	= exec("tput bold");
		$fmt["dim"]	= exec("tput dim");
		$fmt["reset"]	= exec("tput sgr0");

		// Several categories of information:
		// META: 	(blue, bold)	used for an unhandled attribute
		// INFO: 	(white, bold)	TCP Transaction logs and stuff, or the service's name
		// FAIL: 	(red)		Regarding something that contributes to the decision that a service should be marked as down by chkservd
		// PASS:	(green)		Regarding something that contributes to the decision that a service should be marked as up by chkservd
		// DOWN: 	(red, bold)	Service has been marked as down
		// RECOVERED:	(green, bold)	Service has been marked as recovered
		// UP:		(green, bold)	Service has conditionally passed the service check. (e.g. socket failure threshold not exceeded)
		// ACTION:	(yellow, bold)	Action has been taken (email notification sent, service restart attempted, etc)

		// We can determine whether ChkServd.pm determined a service as down by checking the notification attribute, as that logic is one with the "should we notify?/notification type" logic

                echo($fmt["bold"] . "INFO: Service name: {$check["service_name"]}{$fmt["reset"]}\n");
		unset($check["service_name"]);



		// Is the service failed, recovered, or yet to be determined (in case of tests involving multiple required checks, such as socket_failure_threshold)?
		$serviceFailureStatus = (isset($check["notification"])) ? $check["notification"] : "none";

		switch($serviceFailureStatus) {

			case "failed":
				echo( $fmt["bold"] . $fmt["red"] . "DOWN:" . $fmt["reset"] . $fmt["red"] ." The service {$fmt["bold"]}failed{$fmt["reset"]}{$fmt["red"]} the service check and was marked as down." . $fmt["reset"] . "\n");
				break;
			case "recovered";
				echo( $fmt["bold"] . $fmt["green"] . "RECOVERED:" . $fmt["reset"] . $fmt["green"] ." The service {$fmt["bold"]}passed{$fmt["reset"]}{$fmt["green"]} the service check and was marked as having recovered from the previous failure." . $fmt["reset"] . "\n");
				break;
			default:
			case "none":
				echo( $fmt["bold"] . $fmt["green"] . "UP:" . $fmt["reset"] . $fmt["green"] ." The service {$fmt["bold"]}conditionally passed{$fmt["reset"]}{$fmt["green"]} the service check, and has not been marked as down." . $fmt["reset"] . "\n");
				break;

			}


		foreach($check as $attribute => $value) {

			switch($attribute) {

			case "fail_count":
				echo($fmt["red"] . "FAIL:" .$fmt["reset"] . " The service has failed ".$fmt["bold"]. $value . $fmt["reset"]. " consecutive service check(s).". "\n");
				break;
                        case "check_command": {
                                switch ($value) {
                                        case "other": {
                                                echo($fmt["bold"] . "INFO:" .$fmt["reset"] . " The check_command test did not produce a decisive result (status: \"other\")." . $fmt["reset"]. "\n");
                                                break; }
                                        case "down": {
                                                echo($fmt["red"] . "FAIL:" .$fmt["reset"] . " The service has failed the check_command test." . $fmt["reset"]. "\n");
                                                break; }
                                        case "unknown": {
                                                echo($fmt["bold"] . "INFO:" .$fmt["reset"] . " The check_command test did not produce a decisive result (status: \"unknown\")." . $fmt["reset"]. "\n");
                                                break; }
                                        case "up": {
                                                echo($fmt["green"]. "PASS:" .$fmt["reset"] . " The service has passed the check_command test." . $fmt["reset"]. "\n");
                                                break; }
                                        }
                                break; }

			case "socket_connect": {
				switch ($value) {
					case "other": {
						echo($fmt["bold"] . "INFO:" .$fmt["reset"] . " The socket_connect test did not produce a decisive result (status: \"other\")." . $fmt["reset"]. "\n");
						break; }
					case "down": {
						echo($fmt["red"] . "FAIL:" .$fmt["reset"] . " The service has failed the socket_connect test." . $fmt["reset"]. "\n");
						break; }
					case "unknown": {
						echo($fmt["bold"] . "INFO:" .$fmt["reset"] . " The socket_connect test did not produce a decisive result (status: \"unknown\")." . $fmt["reset"]. "\n");
						break; }
					case "up": {
						echo($fmt["green"]. "PASS:" .$fmt["reset"] . " The service has passed the socket_connect test." . $fmt["reset"]. "\n");
						break; }
					}
				break; }

			case "notification":
				$statusColor = ($value == "recovered") ? $fmt["green"] : $fmt["red"];
				echo($fmt["bold"] . $fmt["yellow"] . "ACTION:" . $fmt["reset"] . $fmt["yellow"] . " A notification has been sent regarding the service status (" . $fmt["bold"] . $statusColor . $value . $fmt["reset"] . $fmt["yellow"] .")." .$fmt["reset"]. "\n");
				break;

			case "restart_attempted":
				// TODO: color-code the $value
				echo($fmt["bold"] . $fmt["yellow"] . "ACTION:" . $fmt["reset"] . $fmt["yellow"] . " A service restart has been attempted." . $fmt["reset"] . "\n");
				break;

			case "socket_failure_threshold":

				if ($value < 1) {

	                                echo($fmt["green"] . "PASS:" . $fmt["reset"] . " The service failed the socket_connect check, but has not exceeded the socket failure threshold." . $fmt["reset"] . "\n");
				} elseif ($value >=1) {

					echo($fmt["red"] . "FAIL:" .$fmt["reset"] . " The service has failed the socket_connect check and has exceeded the socket failure threshold." . $fmt["reset"]. "\n");
				}
				break;

			case "tcp_transaction_log":
				echo( $fmt["bold"] . "INFO:" .$fmt["reset"] . " The service check produced a TCP Transaction Log:\n" . $fmt["dim"] . $value . $fmt["reset"] . "\n");
				break;

			case "http_service_auth":
				// this line is logged immediately _before_ Chkservd sends a request to the relevant service (GET /.__cpanel__service__check__./serviceauth?sendkey= with a key at the end)
				// therefore, it does not indicate whether that was successful or not
				echo ( $fmt["bold"] . "INFO:" . $fmt["reset"] . " An HTTP request was made to the service to test service authentication.\n");
				break;
			case "socket_service_auth":
				echo ( $fmt["bold"] . "INFO:" . $fmt["reset"] . " A TCP-based (socket) request was made to the service to test service authentication.\n");
				break;
			default:
				echo($fmt["red"] . "META: The attribute $attribute has no explanation." . $fmt["reset"] ."\n");
				break;

				}

			}
	}


		// -- Function Name : explodeServiceCheckLine
		// -- Params : $checkOutput
		// -- Purpose : Pull information from a service check line
		function explodeServiceCheckLine($checkOutput) {

			$serviceCheckRegex = "/(Restarting\ ([_\-a-zA-Z0-9]{1,})\.\.\.\.|TCP\ Transaction\ Log.+?(?=Died)Died(?!=\[)|\[check\ command:(\+|-|\?|N\/A)\]|\[socket\ connect:(\+|-|\?|N\/A)\]|\[socket\ failure\ threshold:[0-9]{1,}\/[0-9]{1,}\]|\[could\ not\ determine\ status\]|\[no\ notification\ for\ unknown\ status\ due\ to\ upgrade\ in\ progress\]|\[too\ soon\ after\ restart\ to\ check\]|\[fail\ count:[0-9]{1,}\]|\[notify:(unknown|recovered|failed)\ service:.+?(?=\])\]|\[socket_service_auth:1\]|\[http_service_auth:1\])/ms";
			preg_match_all($serviceCheckRegex, $checkOutput, $serviceCheckData);
			$serviceCheckData = current($serviceCheckData);
			$serviceCheckData["service_name"] = explode(" ", $checkOutput);
			$serviceCheckData["service_name"] =  "[service_name:".$serviceCheckData["service_name"][0]."]"; // not part of the original chkservd log output but syntactically similar so we can parse it out with regex
			return $serviceCheckData;
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
/*
array (
  0 => '[socket failure threshold:1/3]',
  1 => '1',
  2 => '3',
)
*/
					// We can test if the socket failure threshold is equal to or more than 1... (I've seen "4/3" before)
					if ($attributeData[2] == 0) { // just in case this happens, to avoid divide by zero
						$serviceBreakdown["socket_failure_threshold"] = 1; // mark as down 
					} else {
	                                        $serviceBreakdown["socket_failure_threshold"] = $attributeData[1] / $attributeData[2]; // will return 
					}
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
				case (preg_match("/\[service_name:([_\-A-Za-z0-9]{1,})\]/", $attribute) ? $attribute: !$attribute):
					preg_match("/\[service_name:([_\-A-Za-z0-9]{1,})\]/", $attribute, $attributeData);
					$serviceBreakdown["service_name"] = $attributeData[1];
				break;
				case ((preg_match_all("/TCP\ Transaction\ Log.+?(?=Died)Died(?!=\[)/ms", $attribute) > 0) ? $attribute: !$attribute):
					preg_match_all("/TCP\ Transaction\ Log.+?(?=Died)Died(?!=\[)/ms", $attribute, $attributeData);
					$attributeData = current($attributeData);
					$serviceBreakdown["tcp_transaction_log"] = $attributeData[0];
				break;
				default:

echo					exec("tput setaf 1");
					echo "Unhandled attribute:  \"$attribute\"\n";
echo					exec("tput sgr0");
				break;


			} // end switch case
	}	// end foreach

$serviceBreakdown = array("service_name" => $serviceBreakdown["service_name"]) + $serviceBreakdown; // shift the service_name attribute to the beginning of the array

return $serviceBreakdown;
}	// end function


function parseIntoTimeline($event, $timestamp) {

//var_export($event);

/*

If this exists, the service is down:

	$systemState["down"]["exim"]

This is the number of times a restart has been attempted:

	$systemState["down"]["exim"]["restart_attempts"] = 10;

This is the unix timestamp of when the service went down

	$systemState["down"]["exim"]["down_since"] = 1477500323;

*/

/*


Timeline draft:


Types of events to be passed to $timeline handler:

- Service marked as down
- Service marked as recovered

During processing, there is a $systemState array that contains $systemState["down_services"] with $systemState["down_services"]["example_service"]["unix_timestamp_when_service_went_down"]


Pseudocode:

if ($service is marked as down) {
	if ($service was already down) do nothing;
	if ($service was not previously marked down) add to $timeline; update $systemState;
	}
if ($service is marked as recovered) {
	if ($service was not previously down) do nothing; // probably at the beginning of the log excerpt read by the script
	if ($service was previously marked as down) add to $timeline with $downtime_duration; update $systemState;
}


$timeline structure:

Organized by ["timestamp"]

$service has gone down
$service has recovered (total downtime: $downtime_duration)


Output will be something like this:

2015-11-04 16:47:33 -0500 == lfd has gone down
2015-11-10 08:46:47 -0500 == lfd has recovered, total downtime: 5 days, 15 hours, 59 minutes, 14 seconds
2016-01-25 05:44:34 -0500 == httpd has gone down
2016-01-25 06:03:53 -0500 == httpd has recovered, total downtime: 19 minutes, 19 seconds




*/

if (isset($event["notification"])) {
	switch ($event["notification"]) {
		case "failed":
			if( isset($this->systemState["down"][$event["service_name"]])) {
				if ($event["restart_attempted"]) {
					$this->systemState["down"][$event["service_name"]]["restart_attempts"]++;
				}
				return;
			}
			else {
				$this->systemState["down"][$event["service_name"]]["down_since"] = $timestamp;
				$this->systemState["down"][$event["service_name"]]["restart_attempts"] = 1;

				$this->timeline[$timestamp][$event["service_name"]]["status"] = "failed";
				}
			return;
			break;
		case "recovered":
			if (!isset($this->systemState["down"][$event["service_name"]])) {
				return; // ignore this - input data does not include when the service first went down
			 }

			elseif (isset($this->systemState["down"][$event["service_name"]])) {

				$this->timeline[$timestamp][$event["service_name"]]["status"] = "recovered";
				$this->timeline[$timestamp][$event["service_name"]]["down_since"] = $this->systemState["down"][$event["service_name"]]["down_since"];
				$this->timeline[$timestamp][$event["service_name"]]["restart_attempts"] = $this->systemState["down"][$event["service_name"]]["restart_attempts"];
				$this->timeline[$timestamp][$event["service_name"]]["downtime"] = ($timestamp - $this->systemState["down"][$event["service_name"]]["down_since"]);

				unset($this->systemState["down"][$event["service_name"]]);

				return;
				}
			break;
		default:
			return;
			break;

		}
	}
}








} // end class


	$usage = <<<EOD
Usage: ./parse_chkservd.php <filename> [<number of lines to parse, counting back from last entry>]

EOD;


	if (!isset($argv[1]) || !file_exists($argv[1])) {
		exit($usage);
	}
	date_default_timezone_set("America/New_York"); // for later calls to strftime

	$parser = new chkservdParser;

	// note:
	// We might want to check the size of the chkservd log to ensure we don't run out of memory
	// not implemented yet tho

	if (exec("head -n1 ".escapeshellarg($argv[1])) != "Service Check Started") {
		exit("ERROR: This does not appear to be a chkservd log file.\n");
	}

	$logdata = "";

	if (isset($argv[2]) && is_numeric($argv[2]) && $argv[2] > 0) {
		exec("tail -n".escapeshellarg($argv[2])." ".escapeshellarg($argv[1]),$logtail);
		foreach($logtail as $line) {
			$logdata .= $line."\n";
		}

	} else {

		// TODO: <(cat file1.log file2.log) as a file descriptor only seems to make the script read the second file, find out if this can be compensated for in PHP

		if (preg_match("/^\/dev\/(fd\/[0-9]{1,})$/", $argv[1])) { // in case we're using a file descriptor instead of a real file
			preg_match("/^\/dev\/(fd\/[0-9]{1,})$/", $argv[1], $log_load_fd);
 			$logdata = file_get_contents("php://".$log_load_fd[1]);
		} else {
			$logdata = file_get_contents($argv[1]);
		}

}

//	$parser->loadEntry($logdata);

// Parse out all chkservd log entries into individual array elements.

error_log("DEBUG: Loading log file..."); // DEBUGLINE

preg_match_all("/Service\ Check\ Started.*?Service\ Check\ (Interrupted|Finished)/sm", $logdata, $splitLogEntries);	// parse input data into unique elements with one raw chkservd entry per element

// We need to throw away interrupted service checks (which abruptly end with "Service Check Interrupted\n")
foreach (current($splitLogEntries) as $index => $entry) {
	if ($splitLogEntries[1][$index] == "Interrupted") { unset($splitLogEntries[0][$index]); unset($splitLogEntries[1][$index]); continue; } // throw away service checks that have the capturing group returned as "Interrupted"
}

// Now we can go over each service check one-by-one.

error_log("DEBUG: Extracting relevant events..."); // DEBUGLINE

foreach (current($splitLogEntries) as $index => $entry) {

$check = $parser->loadEntry($entry);

$parser->eventList[$check["timestamp"]]["services"] = $parser->extractRelevantEvents($check["services"]);

// Just a note, we convert the timestamps into UNIX timestamps, which frees us to convert them back into a formatted time string with our desired Timezone, by default, America/New_York
$parser->eventList[$check["timestamp"]]["timestamp"] = $check["timestamp"];

$parser->eventList[$check["timestamp"]]["formatted_timestamp"] = strftime("%F %T %z", $check["timestamp"]);

}


// Explain each attribute in each service check

// TODO: We may consider omitting service checks in which nothing happened from the eventList for efficiency's sake, depending on how the eventList ends up being handled
error_log("DEBUG: Parsing events into timeline..."); // DEBUGLINE

foreach($parser->eventList as $point) {
	if (!empty($point["services"])) { // skip if nothing happened for this check

//		echo(exec("tput bold; tput setaf 6") . "Service check at ". $point["formatted_timestamp"] . exec("tput sgr0") . "\n");


		foreach($point["services"] as $service) {
//			echo "\n";
//			$parser->explainServiceCheckResult($service);

			// feed into timeline event generator function here
			$parser->parseIntoTimeline($service, $point["timestamp"]);
			}
//			echo "\n";

		}

}

error_log("DEBUG: Timeline:");

var_export($parser->timeline);

error_log("DEBUG: systemState:");

var_dump($parser->systemState);


// output timeline

foreach($parser->timeline as $timestamp => $timelineEntry) {

	foreach($timelineEntry as $entry["service_name"] => $entry) {

		switch ($entry["status"]) {

			case "failed":
				echo strftime("%F %T %z", $timestamp) . " - Service {$entry["service_name"]} has gone down.\n";
				break;

			case "recovered":
				echo strftime("%F %T %z", $timestamp) . " - Service {$entry["service_name"]} has recovered. Downtime: {$entry["downtime"]} seconds. Restart attempts: {$entry["restart_attempts"]}.\n";
				break;

			default:
				break;
		}


	}

}


// output system state for currently-down services

var_dump($parser->systemState);
