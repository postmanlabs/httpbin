html:
	cat README.md|sed 's/(http:\/\/httpbin.org\//(\//'|ronn -5 -f --style 80c --pipe > ./httpbin/templates/httpbin.1.html

deploy:
	 epio upload -a httpbin

run: html
	foreman start