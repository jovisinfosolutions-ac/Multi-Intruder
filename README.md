# Multi-Intruder
Quickly Bruteforce in Burp Suite, multiple website with each website bruteforced alternatively, Small memory footprint which will help when testing multiple websites with Large Wordlist

The extension sends requests at a configurable rate, collects responses, and displays the results in a sortable table for easy analysis.

## Installation
Download the Jar file and add to your burp suite.

# Screenshots:

<img width="1110" height="700" alt="image" src="https://github.com/user-attachments/assets/305ccd1b-579e-4aaf-ad3c-c5e87532a78b" />

Attack Results
<img width="1093" height="690" alt="image" src="https://github.com/user-attachments/assets/c278d359-9e05-4ebb-a629-e45be05d3a7a" />

<img width="1082" height="753" alt="image" src="https://github.com/user-attachments/assets/e1601d44-c74b-400b-998f-279c07d04bdd" />

#Features
•	Directory and path discovery
•	API endpoint testing
•	Websites in tabs are bruteforced sequential, prevents overload of request to a website
•	Redirect analysis
•	Configurable requests-per-second rate limiting
•	Multiple concurrent attack sessions
•	Pause and resume functionality
•	Result export

# Steps to use
Step 1. Prepare the Request
Select one or more HTTP requests, then send to multi-intruder and mark the portion that should be fuzzed using the § marker.
Example:
GET /get/§user§ HTTP/1.1
The marked value will be replaced with every payload from the loaded wordlist.

Step 2. Load a Wordlist
Payloads can be loaded using any of the following methods:
**File Import**
Load payloads from a text file.
**Clipboard Paste**
Paste payloads directly from the system clipboard.
**Manual Entry**
Add individual payloads through the input field.
Each payload is displayed on a separate line and can be edited or removed before starting the attack.

Step 3. Configure Request Rate
The Request/s field controls how many requests are sent per second.
If no value is specified, Multi-Intruder uses:
1 request per second
Examples:
Value	Rate
1	1 request per second
5	5 requests per second
10	10 requests per second
________________________________________

Step 4. Start the Attack
Click Run to start the attack.

## Delete Requests
•	Delete removes selected requests.
•	Delete All removes all loaded requests.

## Copy URL
Right-click any result row and select:
Copy URL
The request URL is copied to the system clipboard.



