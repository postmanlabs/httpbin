html:
	cat README.md|sed 's/(http:\/\/httpbin.org\//(\//'|ronn -5 -f --style 80c --pipe > ./httpbin/templates/httpbin.1.html

deploy:
	git push heroku master

stage:
	git push heroku-staging master

run: html
	foreman start