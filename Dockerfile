FROM ubuntu:trusty

ENV GUNICORN_WORKERS=4

ADD . /httpbin

RUN apt-get update -y && apt-get -y install python-pip && pip install gunicorn && pip install /httpbin

EXPOSE 8080

CMD gunicorn -w "$GUNICORN_WORKERS" -b 0.0.0.0:8080 httpbin:app
