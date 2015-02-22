FROM ubuntu:trusty

ADD . /httpbin

RUN apt-get update -y && apt-get -y install python-pip && pip install gunicorn && pip install /httpbin

EXPOSE 8080

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8080", "httpbin:app"]
