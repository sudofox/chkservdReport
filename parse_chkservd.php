#!/usr/local/bin/php
<?php

// NOTE TO SELF:
/*
*		the regex matching pairs for certain numbers might not match > 1 chara so check that you have a bounds of {1,} for them
*
*
*/
	// by aburk
	// parse chkservd log and return a pretty summary of service failures and whatnot
	// chkservd entry parser
	class chkservdParser {
		var $checkTime;
		var $downServices;
		// unresolved down services, used for comparison between previous and next check
		var $entryData;
		// current log entry being processed.
		public $servicesList = array();
		// list of services, the names being in the same order as $serviceCheckResults
		public $serviceCheckResults = array();

		// -- Function Name : loadEntry
		// -- Params : $input
		// -- Purpose :
		function loadEntry($input) {
			// Should be given only one chkservd log section, will chop of rest if more is given.
			// $chkservd_entry should Start with "Service Check Started" and end with "Service Check Finished"
			// Pull out our Chkservd log block entry...pull first one if more is provided for some reason

			preg_match_all("/Service\ Check\ Started.*?Service\ Check\ Finished/ism", $input, $entries);
			$entry = current(current($entries));
			// Pull out the service check results
			preg_match_all("/Service\ check\ \.(.*)Done/smi", $entry, $this->serviceCheckResults);
			preg_match_all("/[^\.\.\.][a-zA-Z0-9]{1,}\ \[(\[|).+?(?=\]\])\]\]/smi", current(array_pop($this->serviceCheckResults)), $this->serviceCheckResults);
			$this->serviceCheckResults = current($this->serviceCheckResults);
			var_export($this->serviceCheckResults);
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


		var_export($serviceChecks_associative);
		foreach ($serviceChecks_associative as $service) {
			$this->analyzeServiceCheck($service);
	}
}

		// -- Function Name : explodeServiceCheckLine
		// -- Params : $checkOutput
		// -- Purpose : Pull information from a service check line
		function explodeServiceCheckLine($checkOutput) {

//			$serviceCheckRegex = "/\[(TCP\ Transaction\ Log.+?(?=Died)Died\]|check\ command:(\+|-|\?|N\/A)\]|socket\ connect:(\+|-|\?|N\/A)\]|socket\ failure\ threshold:[0-9]{1,}\/[0-9]{1,}\]|could\ not\ determine\ status\]|no\ notification\ for\ unknown\ status\ due\ to\ upgrade\ in\ progress\]|too\ soon\ after\ restart\ to\ check\]|fail\ count:[0-9]{1,}\]|notify:(unknown|recovered|failed)\ service:.+?(?=\])\]|socket_service_auth:1\]|http_service_auth:1\])/ms";
			$serviceCheckRegex = "/(Restarting\ ([a-zA-Z0-9]{1,})\.\.\.\.|\[TCP\ Transaction\ Log.+?(?=Died)Died\]|\[check\ command:(\+|-|\?|N\/A)\]|\[socket\ connect:(\+|-|\?|N\/A)\]|\[socket\ failure\ threshold:[0-9]{1,}\/[0-9]{1,}\]|\[could\ not\ determine\ status\]|\[no\ notification\ for\ unknown\ status\ due\ to\ upgrade\ in\ progress\]|\[too\ soon\ after\ restart\ to\ check\]|\[fail\ count:[0-9]{1,}\]|\[notify:(unknown|recovered|failed)\ service:.+?(?=\])\]|\[socket_service_auth:1\]|\[http_service_auth:1\])/ms";
			preg_match_all($serviceCheckRegex, $checkOutput, $serviceCheckData);
			$serviceCheckData = current($serviceCheckData);
			$serviceCheckData["service_name"] = explode(" ", $checkOutput);
			$serviceCheckData["service_name"] =  $serviceCheckData["service_name"][0];
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

                                      //          $serviceBreakdown["socket_failure_threshold"] = "
				break;


			} // end switch case
	}	// end foreach

var_export($serviceBreakdown);

}	// end function

} // end class

	$parser = new chkservdParser;

	$usage = <<<EOD
Usage: ./parse_chkservd.php <filename> [<number of lines to parse, counting back from last entry>]

EOD;

	
	if (!isset($argv[1]) || !file_exists($argv[1])) {
		exit($usage);
	}

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

	//	echo($logdata);
	$parser->loadEntry($logdata);


