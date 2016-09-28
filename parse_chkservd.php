#!/usr/bin/env php
<?php

	// by aburk
	// parse chkservd log and return a pretty summary of service failures and whatnot
	// chkservd entry parser
	class chkservdParser {
		var $checkTime;
		var $downServices;	// unresolved down services, used for comparison between previous and next check
		var $entryData;		// current log entry being processed.
		var $timeline;		// a timeline of when things happen: services gone down, back up, restart attempts, currently down, etc. 
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


return $serviceBreakdown;
}	// end function

} // end class


	$usage = <<<EOD
Usage: ./parse_chkservd.php <filename> [<number of lines to parse, counting back from last entry>]

EOD;

	
	if (!isset($argv[1]) || !file_exists($argv[1])) {
		exit($usage);
	}

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
		$logdata = file_get_contents($argv[1]);
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

//	$parser->loadEntry($entry);
var_dump($parser->loadEntry($entry));
}


