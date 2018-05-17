FROM ubuntu:18.04

ADD . /httpbin

RUN apt update -y
RUN apt install python3-pip -y
RUN pip3 install --no-cache-dir gunicorn /httpbin

EXPOSE 80

CMD ["gunicorn", "-b", "0.0.0.0:80", "httpbin:app", "-k", "gevent"]
