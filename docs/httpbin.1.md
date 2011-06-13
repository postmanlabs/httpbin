httpbin(1): HTTP Client Testing Service
=======================================

## SYNOPSIS

`/` This page.  
`/ip` Returns Origin IP.  
`/user-agent` Returns user-agent.  
`/headers` Returns header dict.  
`/get` Returns GET data.  
`/post` Returns POST data.  
`/put` Returns PUT data.  
`/delete` Returns DELETE data.  


## DESCRIPTION

Testing an HTTP Library can become difficult sometimes. PostBin is fantastic
for testing POST requests, but not much else. This will cover everything.

Plans at the moment are to return JSON for all responses. Request storage
/ aggregation may or may not exist. We'll see.


## EXAMPLES

    $ curl http://httpbin.org/ip


## AUTHOR

A [Kenneth Reitz](http://kennethreitz.com/pages/open-projects.html)
Project.

## SEE ALSO

<http://python-requests.org>, <http://postbin.org>, <https://github.com/tml/postbin>
