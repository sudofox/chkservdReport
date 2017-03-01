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
	ini_set("memory_limit", (preg_replace("/[^0-9]/", "", ini_get("memory_limit")) + 2 . "M")); // Allocate a small amount of additional memory so the shutdown function can complete.
	gc_collect_cycles();
	$error = error_get_last();
	if (preg_match("/Allowed memory size of/", $error["message"])) {
		if (posix_isatty(STDOUT)) {
			echo (exec("tput setaf 1; tput bold") . "Memory limit of $memory_limit has been reached before log parsing could be completed. Try setting the memory_limit manually with the -m flag (e.g. -m128M)." . exec("tput sgr0") . "\n");
		}
		else {
			echo ("Memory limit of $memory_limit has been reached before log parsing could be completed. Try setting the memory_limit manually with the -m flag (e.g. -m128M).\n");
		}
	}
}

register_shutdown_function("shutdown_handler");

// Begin main class

class chkservdParser

{

	var $monitoredServices = array();       // array of the names of monitored services. Used for detecting when monitoring for a service is disabled.
	var $firstCheck = true;                 // Used to check if we are processing our first service check or not
	public $systemState = array("down" => array());          // List of unresolved down services, used for comparison between previous and next check
	public $timeline = array();             // This timeline will be directly formatted into the final report of service failures and recoveries.
	public $eventList = array();            // A list of when things happen: services gone down, back up, restart attempts, service monitoring settings changes, etc.
	public $servicesList = array();         // list of services, the names being in the same order as $serviceCheckResults
	public $serviceCheckResults = array();
	public $interruptedChecks = array();

	// -- Function Name : loadEntry
	// -- Params : $input
	// -- Purpose : parses all data out of a single chkservd log entry.
	// -- Currently returns false if it is presented with an invalid service check. otherwise, returns entryData array
	function loadEntry($input, $index) {

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
		if (isset($this->interruptedChecks[$index]) && $this->interruptedChecks[$index]) {
			$interrupted = true;
			if ($this->firstCheck) {
				return false; // First service check was interrupted. Ignore this one and count the next as the real first service check.
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
			$servicesList[] =  trim($entry[0]);
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
						$entryData["services"][$removedService]["service_name"] = trim($removedService);
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
		$serviceCheckData["service_name"] =  "[service_name:".trim($serviceCheckData["service_name"][0])."]";
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
				isset($service["monitoring_disabled"])						||
				isset($service["check_postponed_due_to_recent_service_restart"])
				) {
                                        $output[$service["service_name"]] = $service;
                                }
		}

	return $output;

	}

	// -- Function Name : analyzeServiceCheck
	// -- Params : $checkOutput
	// -- Purpose : Pull information from a service check entry
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


                // -- Function Name : explainServiceCheck
                // -- Params :  $check (a full entry from the parser's eventList), $colorize
                // -- Purpose : Produces an array with human-readable information and color information about a particular service check. Does not do comparison.
		function explainServiceCheck($check, $colorize) {

		// $fmt array is "format"

		if ($colorize) {
                        $fmt["blue"]    = exec("tput setaf 4");
			$fmt["yellow"]	= exec("tput setaf 3");
			$fmt["green"]	= exec("tput setaf 2");
			$fmt["red"]	= exec("tput setaf 1");
			$fmt["bold"]	= exec("tput bold");
			$fmt["dim"]	= exec("tput dim");
			$fmt["reset"]	= exec("tput sgr0");
		} else {
                        $fmt["blue"]    = "";
	                $fmt["yellow"]  = "";
	                $fmt["green"]   = "";
	                $fmt["red"]     = "";
	                $fmt["bold"]    = "";
	                $fmt["dim"]     = "";
	                $fmt["reset"]   = "";
		}

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

	echo($fmt["bold"] . $fmt["blue"] . "Service check at {$check["formatted_timestamp"]}:" . $fmt["reset"] . "\n");

	if ($check["interrupted"]) {
		echo ($fmt["bold"] . $fmt["red"] . "This service check was interrupted before it was able to complete." . $fmt["reset"] . "\n");
	}

	if (isset($check["services"]) && !empty($check["services"])) {
	foreach($check["services"] as $service) {

                echo($fmt["bold"] . "INFO: Service name: {$service["service_name"]}{$fmt["reset"]}\n");


		// Is the service failed, recovered, or yet to be determined (in case of tests involving multiple required checks, such as socket_failure_threshold)?
		$serviceFailureStatus = (isset($service["notification"])) ? $service["notification"] : "none";

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


		foreach($service as $attribute => $value) {

			switch($attribute) {
			case "service_name":
				break; // not displayed
			case "monitoring_enabled":
				echo ($fmt["bold"] . "INFO:" . $fmt["reset"] . " Monitoring was enabled for the service prior to this service check.\n");
				break;
			case "monitoring_disabled":
				echo ($fmt["bold"] . "INFO:" . $fmt["reset"] . " Monitoring was disabled for the service prior to this service check.\n");
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
				$statusColor = ($value == "recovered") ? $fmt["green"] : $fmt["red"];
				echo($fmt["bold"] . $fmt["yellow"] . "ACTION:" . $fmt["reset"] . $fmt["yellow"] . " A notification has been sent regarding the service status (" . $fmt["bold"] . $statusColor . $value . $fmt["reset"] . $fmt["yellow"] .")." .$fmt["reset"]. "\n");
				break;

			case "restart_attempted":
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

			case "check_postponed_due_to_recent_service_restart":
				echo( $fmt["bold"] . "INFO:" .$fmt["reset"] . " The service was restarted recently, so the service check was skipped. " . $fmt["reset"] . "\n");
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
			} // end iteration over single service

			echo "\n";

		} // end iteration over services
		} // end if
	} // end function


	// -- Function Name : parseIntoTimeline
	// -- Params :  $check (a full entry from the parser's eventList)
	// -- Purpose : processes each service check into the final timeline, and accounts for inconsistencies between service checks by comparing systemState with what's in the check


	function parseIntoTimeline($check) {

	$timestamp = $check["timestamp"];

	$this->timeline[$timestamp]["interrupted"] = $check["interrupted"];
	if (!$this->timeline[$timestamp]["interrupted"]) {
		foreach($check["services"] as $service) {
			// Monitoring changes
		        if (isset($service["monitoring_enabled"])) {
					$this->timeline[$timestamp]["services"][$service["service_name"]]["monitoring_enabled"] = true;
		        	}

				if (isset($service["monitoring_disabled"])) {

					$this->timeline[$timestamp]["services"][$service["service_name"]]["monitoring_disabled"] = true;

					if( isset($this->systemState["down"][$service["service_name"]])) {
						$this->timeline[$timestamp]["services"][$service["service_name"]]["status_changed_due_to_disabled_monitoring"] = true;
						$this->timeline[$timestamp]["services"][$service["service_name"]]["down_since"] = $this->systemState["down"][$service["service_name"]]["down_since"];
						$this->timeline[$timestamp]["services"][$service["service_name"]]["restart_attempts"] = $this->systemState["down"][$service["service_name"]]["restart_attempts"];
						$this->timeline[$timestamp]["services"][$service["service_name"]]["downtime"] = ($timestamp - $this->systemState["down"][$service["service_name"]]["down_since"]);
						unset($this->systemState["down"][$service["service_name"]]); // Service is no longer monitored, so we should not mark it as down any longer.
					}

				}

		if (isset($service["notification"])) {
			switch ($service["notification"]) {
				case "failed":
					if( isset($this->systemState["down"][$service["service_name"]])) { // if service already marked down
						if ($service["restart_attempted"]) {
							$this->systemState["down"][$service["service_name"]]["restart_attempts"]++;
						}
						continue;
					}
					else { // mark as down
						$this->systemState["down"][$service["service_name"]]["down_since"] = $timestamp;
						$this->systemState["down"][$service["service_name"]]["restart_attempts"] = 1;
						$this->timeline[$timestamp]["services"][$service["service_name"]]["status"] = "failed";
					}
						continue;
					break;

				case "recovered":
					if (!isset($this->systemState["down"][$service["service_name"]])) {
						continue; // ignore this - input data does not include when the service first went down
					}

					elseif (isset($this->systemState["down"][$service["service_name"]])) {

						$this->timeline[$timestamp]["services"][$service["service_name"]]["status"] = "recovered";
						$this->timeline[$timestamp]["services"][$service["service_name"]]["down_since"] = $this->systemState["down"][$service["service_name"]]["down_since"];
						$this->timeline[$timestamp]["services"][$service["service_name"]]["restart_attempts"] = $this->systemState["down"][$service["service_name"]]["restart_attempts"];
						$this->timeline[$timestamp]["services"][$service["service_name"]]["downtime"] = ($timestamp - $this->systemState["down"][$service["service_name"]]["down_since"]);

						unset($this->systemState["down"][$service["service_name"]]);

                		                continue;
        	                        }

        		                break;
		                default:
        		                continue;
        	        	        break;

				} // end switch
			} // end if(isset)
		} // end foreach


	// Check systemState to see if anything has changed after interrupted check

	foreach($this->systemState["down"] as $service_name => $service) { //bookmark

		if (!isset($this->timeline[$timestamp]["services"][$service_name]) && isset($this->timeline[$timestamp]["services"]) && in_array($service_name, $this->monitoredServices)) {

			$this->timeline[$timestamp]["services"][$service_name]["status_changed_due_to_inconsistency"] = true;
			$this->timeline[$timestamp]["services"][$service_name]["down_since"] = $this->systemState["down"][$service_name]["down_since"];
			$this->timeline[$timestamp]["services"][$service_name]["restart_attempts"] = $this->systemState["down"][$service_name]["restart_attempts"];
			$this->timeline[$timestamp]["services"][$service_name]["downtime"] = ($timestamp - $this->systemState["down"][$service_name]["down_since"]);
			unset($this->systemState["down"][$service_name]);

			}
		}

	} // end 'if check not interrupted'

} // End function


        // -- Function Name : validateSystemState
        // -- Params :  $check (a full entry from the parser's eventList)
        // -- Purpose : This is run instead of parseIntoTimeline when there's unresolved down services, but parseIntoTimeline was not run.
	// parseIntoTimeline has a similar check at the end, but it checks against the timeline entry that it's processing as well.

        function validateSystemState($check) {

	$timestamp = $check["timestamp"];

        foreach($this->systemState["down"] as $service_name => $service) {

                if (in_array($service_name, $this->monitoredServices)) {

                        $this->timeline[$timestamp]["services"][$service_name]["status_changed_due_to_inconsistency"] = true;
                        $this->timeline[$timestamp]["services"][$service_name]["down_since"] = $this->systemState["down"][$service_name]["down_since"];
                        $this->timeline[$timestamp]["services"][$service_name]["restart_attempts"] = $this->systemState["down"][$service_name]["restart_attempts"];
                        $this->timeline[$timestamp]["services"][$service_name]["downtime"] = ($timestamp - $this->systemState["down"][$service_name]["down_since"]);
                        unset($this->systemState["down"][$service_name]);

                        }

                }

	}

} // end class

// Usage

$scriptName = basename(__FILE__);

$usage = <<<EOD
Usage: ./{$scriptName} -f<filename> [<additional arguments>]

If you wish to pass the arguments in any order, you must omit the space after the flag letter.

(e.g. -fchkservd.log -m500M -n100000)

By default, -n is set to 10000 (this will go back several days).

Required arguments
-f	filename of chkservd logfile

Optional arguments
-n	number of lines to read from the end of the file (default 10000, pass 0 for unlimited)
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
	$fmt["blue"]	=	exec("tput setaf 4");
	$fmt["yellow"]	=	exec("tput setaf 3");
	$fmt["green"]	=	exec("tput setaf 2");
	$fmt["red"]	=	exec("tput setaf 1");
	$fmt["bold"]	=	exec("tput bold");
	$fmt["dim"]	=	exec("tput dim");
	$fmt["reset"]	=	exec("tput sgr0");
}
else {
	$fmt["blue"]	= "";
	$fmt["yellow"]	= "";
	$fmt["green"]	= "";
	$fmt["red"]	= "";
	$fmt["bold"]	= "";
	$fmt["dim"]	= "";
	$fmt["reset"]	= "";
}

// -n for number of lines from end to seek

$logdata = "";

if (!isset($options["n"])) {
	$options["n"] = 10000;
}

if (!is_numeric($options["n"]) || $options["n"] < 0) {
	exit("Error: -n must be a positive number.\n\n$usage");
}

if ($options["n"] == 0) {

	// TODO: <(cat file1.log file2.log) as a file descriptor only seems to make the script read the second file, find out if this can be compensated for in PHP

	if (preg_match("/^\/dev\/(fd\/[0-9]{1,})$/", $options["f"])) { // in case we're using a file descriptor instead of a real file
		preg_match("/^\/dev\/(fd\/[0-9]{1,})$/", $options["f"], $log_load_fd);
		$logdata = file_get_contents("php://" . $log_load_fd[1]);
	}
	else {
		$logdata = file_get_contents($options["f"]);
	}
}

else {

	exec("tail -n" . escapeshellarg($options["n"]) . " " . escapeshellarg($options["f"]) , $logtail);
	foreach($logtail as $line) {
		$logdata.= $line . "\n";
	}

	unset($logtail);
}


if ($options["v"]["p"]) {	error_log("Loading log file...");	} // TODO: Debug

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
	$check = $parser->loadEntry($entry, $index);
	if ($check === false) { continue; } // loadEntry returning false means that the check must be thrown out.
	if(isset($check["services"])) { // TODO: An interrupted service check doesn't have this
		$parser->eventList[$check["timestamp"]]["services"]	=	$parser->extractRelevantEvents($check["services"], $index);

	}

	$parser->eventList[$check["timestamp"]]["interrupted"]		=	(isset($parser->interruptedChecks[$index]) && $parser->interruptedChecks[$index]);
	$parser->eventList[$check["timestamp"]]["timestamp"]		=	$check["timestamp"];
	$parser->eventList[$check["timestamp"]]["formatted_timestamp"]	=	strftime("%F %T %z", $check["timestamp"]);
	$parser->eventList[$check["timestamp"]]["iterator"]		=	$index; // TODO: in case we need to reference the original order of the checks later
}

unset($splitLogEntries);

// TODO: We now have our parsed entries, and know whether or not the check was interrupted.

if ($options["v"]["p"]) { error_log("Parsing events into timeline..."); } //TODO: Debug

foreach($parser->eventList as $key=>$point) {
	// TODO: We may want to keep an empty service check if it comes _after_ an interrupted service check. We aren't currently doing this.
	// TODO: see http://stackoverflow.com/a/4792770 to reference previous array element

	if (!(empty($point["services"]) && !$point["interrupted"])) { // TODO: tweak this to make parseIntoTimeline run if there's unresolved down services

		if ($options["v"]["t"]) { echo "\n"; $parser->explainServiceCheck($point, $options["colorize"]); echo "\n"; }
 		$parser->parseIntoTimeline($point);

	} else if (isset($parser->systemState["down"]) && count($parser->systemState["down"]) > 0 ) {
		// There are down services, but parseIntoTimeline was not run.
		$parser->validateSystemState($point);

	}

unset($parser->eventList[$key]);

}  // TODO: end foreach

unset($parser->eventList); // TODO: No longer needed?

// Timeline Output

echo $fmt["bold"] . "Timeline: {$fmt["reset"]}\n";

foreach($parser->timeline as $timestamp => $timelineEntry) {


	if (isset($timelineEntry["interrupted"]) && $timelineEntry["interrupted"] == true) {
		echo $fmt["bold"] .strftime("%F %T %z", $timestamp) . "{$fmt["reset"]} - {$fmt["dim"]}{$fmt["red"]}The service check was interrupted before it could complete.{$fmt["reset"]}\n";
	} else {

	if(isset($timelineEntry["services"])) { // May be empty or not set if the only thing entering parseIntoTimeline is a check that hasn't exceeded the socket_failure_threshold or smth
	foreach($timelineEntry["services"] as $entry["service_name"] => $entry) {

                if (isset($entry["monitoring_enabled"])) {
			echo $fmt["bold"] . strftime("%F %T %z", $timestamp) . "{$fmt["reset"]} - {$fmt["dim"]}Monitoring was {$fmt["reset"]}{$fmt["green"]}enabled{$fmt["reset"]}{$fmt["dim"]} for {$entry["service_name"]}.{$fmt["reset"]}\n";
		}

		if (isset($entry["status_changed_due_to_inconsistency"])) {
			echo $fmt["bold"] . strftime("%F %T %z", $timestamp) . "{$fmt["reset"]} - {$fmt["dim"]}{$fmt["green"]}Service {$entry["service_name"]} has recovered. Downtime: {$fmt["bold"]}{$entry["downtime"]} seconds.{$fmt["reset"]}{$fmt["green"]}{$fmt["dim"]} Restart attempts: {$fmt["bold"]}{$entry["restart_attempts"]} (Already marked as up - can occur after an interrupted check){$fmt["reset"]}\n";

		}

		if (isset($entry["monitoring_disabled"])) {
			if (isset($entry["status_changed_due_to_disabled_monitoring"])) {
				echo $fmt["bold"] . strftime("%F %T %z", $timestamp) . "{$fmt["reset"]} - {$fmt["dim"]}{$fmt["green"]}Monitoring was {$fmt["reset"]}{$fmt["red"]}disabled{$fmt["reset"]}{$fmt["dim"]}{$fmt["green"]} for {$entry["service_name"]}, so it is no longer marked down. Downtime: {$fmt["bold"]}{$entry["downtime"]} seconds.{$fmt["reset"]}{$fmt["green"]}{$fmt["dim"]} Restart attempts: {$fmt["bold"]}{$entry["restart_attempts"]}{$fmt["reset"]}\n";
			}
			else {
				echo $fmt["bold"] . strftime("%F %T %z", $timestamp) . "{$fmt["reset"]} -{$fmt["dim"]} Monitoring was {$fmt["reset"]}{$fmt["red"]}disabled{$fmt["reset"]}{$fmt["dim"]} for {$entry["service_name"]}.{$fmt["reset"]}\n";
			}
		}

		if(isset($entry["status"])) {
			switch ($entry["status"]) {
					case "failed":
						echo $fmt["bold"] . strftime("%F %T %z", $timestamp) . "{$fmt["reset"]} - {$fmt["bold"]}{$fmt["red"]}Service {$entry["service_name"]} has gone down.{$fmt["reset"]}\n";
					break;
					case "recovered":
						echo $fmt["bold"] . strftime("%F %T %z", $timestamp) . "{$fmt["reset"]} - {$fmt["green"]}Service {$entry["service_name"]} has recovered. Downtime: {$entry["downtime"]} seconds. Restart attempts: {$entry["restart_attempts"]}.{$fmt["reset"]}\n";
					break;
					default:
						break;
					}
				}
			}
		}
	}

}


// output system state for currently-down services

if (isset($parser->systemState["down"]) && count($parser->systemState["down"]) > 0 ) {
	echo "\nServices currently marked down:\n";

	foreach($parser->systemState["down"] as $name=>$service) {
		echo $name.": \t down since ".strftime("%F %T %z", $service["down_since"]) .", {$service["restart_attempts"]} restart attempt(s).\n";
		}
} else {
	echo "\nServices currently marked down: none\n";
}

