#!/usr/bin/env php
<?php

	// by aburk
	// parse chkservd log and return a pretty summary of service failures and whatnot
	// chkservd entry parser
	class chkservdParser {
		var $checkTime;
		var $downServices;	// unresolved down services, used for comparison between previous and next check
		var $entryData;		// current log entry being processed.
		public $timeline = array();		// a timeline of when things happen: services gone down, back up, restart attempts, currently down, etc.
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
		// ACTION:	(yellow, bold)	Action has been taken (email notification sent, service restart attempted, etc)
		foreach($check as $attribute => $value) {

			switch($attribute) {

			case "service_name":
				echo($fmt["bold"] . "INFO: Service name: $value" . $fmt["reset"] . "\n");
				break;
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
				// TODO: color-code the $value
				echo($fmt["bold"] . $fmt["yellow"] . "ACTION:" . $fmt["reset"] . $fmt["yellow"] . " A notification has been sent regarding the service status (" . $fmt["bold"] . $value . $fmt["reset"] .")." . "\n");
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


preg_match_all("/Service\ Check\ Started.*?Service\ Check\ (Interrupted|Finished)/sm", $logdata, $splitLogEntries);	// parse input data into unique elements with one raw chkservd entry per element

// We need to throw away interrupted service checks (which abruptly end with "Service Check Interrupted\n")
foreach (current($splitLogEntries) as $index => $entry) {
	if ($splitLogEntries[1][$index] == "Interrupted") { unset($splitLogEntries[0][$index]); unset($splitLogEntries[1][$index]); continue; } // throw away service checks that have the capturing group returned as "Interrupted"
}

// Now we can go over each service check one-by-one.
foreach (current($splitLogEntries) as $index => $entry) {

$check = $parser->loadEntry($entry);

$parser->timeline[$check["timestamp"]]["services"] = $parser->extractRelevantEvents($check["services"]);

// Just a note, we convert the timestamps into UNIX timestamps, which frees us to convert them back into a formatted time string with our desired Timezone, by default, America/New_York
$parser->timeline[$check["timestamp"]]["timestamp"] = $check["timestamp"];

$parser->timeline[$check["timestamp"]]["formatted_timestamp"] = strftime("%F %T %z", $check["timestamp"]);

}


foreach($parser->timeline as $point) {

// var_export($parser->timeline);

	foreach($point["services"] as $service) {
		echo "\n";
		$parser->explainServiceCheckResult($service);
	}

}
