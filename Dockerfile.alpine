## Just the builder
FROM alpine:latest as builder

RUN apk add --no-cache git gcc libc-dev libffi-dev build-base python3 py3-pip py3-wheel python3-dev \
    && pip install --no-cache-dir pipenv gunicorn

ADD Pipfile Pipfile.lock /opt/httpbin/
WORKDIR /opt/httpbin
RUN /bin/sh -c "pip3 install --no-cache-dir -r <(pipenv lock -r)"

ADD . /httpbin
RUN pip3 install --no-cache-dir /httpbin

## Here comes the real container
##
##
FROM alpine:latest

LABEL name="httpbin"
LABEL version="0.9.2"
LABEL description="A simple HTTP service."
LABEL org.kennethreitz.vendor="Kenneth Reitz"

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

WORKDIR /opt/httpbin

RUN apk add --no-cache python3  py3-pip\
    && pip install --no-cache-dir gunicorn

COPY --from=builder /opt/httpbin /opt/
COPY --from=builder /usr/lib/python3.10/site-packages/ /usr/lib/python3.10/site-packages/


EXPOSE 8080

CMD ["gunicorn", "-b", "0.0.0.0:8080", "httpbin:app", "-k", "gevent"]
