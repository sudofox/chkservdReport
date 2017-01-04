# Tailwatch Log Analysis Tool
(currently `parse_chkservd.php`)

cPanel's Tailwatch produces a strange log with details about service checks, formatted in an almost unreadable manner. 
My goal for this project is to have a tool that can parse through the log and produce a human-readable report of when services went down, how long they were down for, what it took to get them running again, and so forth.

To Do:

- Fix inconstencies caused by of interrupted service checks
- Process OOM check information as well as processes that are terminated due to OOMs
- Don't add timeline entries that don't have anything in them (e.g. when the only element in the services array passed to parseIntoTimeline is a service that has not exceeded the socket failure threshold)
