FROM ubuntu:18.04

LABEL name="httpbin"
LABEL version="0.9.0"
LABEL description="A simple HTTP service."
LABEL org.kennethreitz.vendor="Kenneth Reitz"

RUN apt update -y && apt install python3-pip -y

EXPOSE 80

ADD . /httpbin

RUN pip3 install --no-cache-dir gunicorn /httpbin

CMD ["gunicorn", "-b", "0.0.0.0:80", "httpbin:app", "-k", "gevent"]
