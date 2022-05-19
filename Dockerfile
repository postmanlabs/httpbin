FROM ubuntu:18.04

LABEL name="httpbin-devops"
LABEL version="1.0"
LABEL description="A simple HTTP service."
LABEL org.abhishek.vendor="Abhishek Nallana"

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

RUN curl -fsSLO https://get.docker.com/builds/Linux/x86_64/docker-17.04.0-ce.tgz \
  && tar xzvf docker-17.04.0-ce.tgz \
  && mv docker/docker /usr/local/bin \
  && rm -r docker docker-17.04.0-ce.tgz
RUN apt update -y && apt install python3-pip git -y && pip3 install --no-cache-dir pipenv

ADD Pipfile Pipfile.lock /httpbin/
WORKDIR /httpbin
RUN /bin/bash -c "pip3 install --no-cache-dir -r <(pipenv lock -r)"

ADD . /httpbin-devops
RUN pip3 install --no-cache-dir /httpbin-devops

EXPOSE 90

CMD ["gunicorn", "-b", "0.0.0.0:90", "httpbin-devops:app", "-k", "gevent"]
