FROM ubuntu:trusty

ENV WEB_CONCURRENCY=4

ADD . /httpbin

RUN apt-get update -y && apt-get -y install python-pip && pip install gunicorn && pip install /httpbin

EXPOSE 8080

CMD gunicorn -b 0.0.0.0:8080 httpbin:app
