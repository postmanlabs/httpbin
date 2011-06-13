httpbin(1): HTTP Client Testing Service
=======================================

## ENDPOINTS

`/` This page.  
`/ip` Returns Origin IP.  
`/user-agent` Returns user-agent.  
`/headers` Returns header dict.  
`/get` Returns GET data.  
`/post` Returns POST data.  
`/put` Returns PUT data.  
`/delete` Returns DELETE data.  
`/gzip` Returns GZip-encoded data.  
`/status/:code` Returns given HTTP Status code.  
`/redirect/:n` 302 Redirect loop *n* times.  


## DESCRIPTION

Testing an HTTP Library can become difficult sometimes. PostBin.org is fantastic
for testing POST requests, but not much else. This exists to cover all kinds of HTTP 
scenarios. Additional endpoints are being considered: `/basic-auth/`, `/deflate/`, *&c*.

All endpoint responses are JSON-encoded.


## EXAMPLES

    $ curl http://httpbin.org/get


## AUTHOR

A [Kenneth Reitz](http://kennethreitz.com/pages/open-projects.html)
Project.

## SEE ALSO

<https://github.com/kennethreitz/httpbin>, <http://python-requests.org>, <http://postbin.org>
