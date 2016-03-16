# flexo
DNS monitoring script written in Python

Evolution of a DNS monitoring script written by Mark Baggett at SANS
This script will monitor DNS queries and responses, and will alert if it sees any of the following:

Requested domain is not in the Alexa Top 1 million requested websites (requires Alexa file)
Excessively long hostname
TTL of the response is very low - indicative of fast flux
Requests for any domain that is put into the watchlist.

Requires Python and Scapy.
