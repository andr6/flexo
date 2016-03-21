# flexo
DNS monitoring script written in Python

Evolution of a DNS monitoring script written by Mark Baggett at SANS
This script will monitor DNS queries and responses, and will alert if it sees any of the following:

Requested domain is not in the Alexa Top 1 million requested websites (requires Alexa file)

Excessively long hostname

TTL of the response is very low - indicative of fast flux

Requests for any domain that is put into the watchlist.

Unsolicited DNS requests

[*] Requires Python and Scapy [*]

Put domains to be watched for in watch.domains
Put noisy domains you don't care about into whitelist.domain
Download the Alexa top million domains list at http://s3.amazonaws.com/alexa-static/top-1m.csv.zip and unzip the file in the same directory as Flexo.

Change the interface name in the sniff command (last line of the script) to whatever interface you're using to sniff.
You can also set the TTL threshold for fast flux detection. It's a variable near the top.
