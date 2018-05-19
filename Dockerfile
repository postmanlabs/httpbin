FROM ubuntu:18.04

RUN apt update -y
RUN apt install python3-pip -y

ADD . /httpbin

RUN pip3 install --no-cache-dir gunicorn /httpbin

EXPOSE 80

CMD ["gunicorn", "-b", "0.0.0.0:80", "httpbin:app", "-k", "gevent"]
