# python-bitstamp-api
My version of the bitstamp-API made in python

This code handles the http calls. 
There are two functions one for the private API access (trading, balance...) and one for public access (like order book, ticker...)

.API(payload, url) Takes payload and url as arguments. 
Payload are sorting and limit options described in the Bitstamp API documentation.
URL is the url after "http://www.bitstamp.net", for the urls in the documentation.
.APIpublic(url) only takes url as an argument.
