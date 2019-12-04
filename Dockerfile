FROM python:alpine3.10

LABEL name="httpbin"
LABEL version="0.9.2"
LABEL description="A simple HTTP service."
LABEL org.kennethreitz.vendor="Kenneth Reitz"

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

ADD Pipfile Pipfile.lock /httpbin/
WORKDIR /httpbin

RUN apk add --update --no-cache bash && pip3 install --no-cache-dir pipenv \
    && apk add --no-cache --virtual .build-deps gcc build-base linux-headers ca-certificates python3-dev libffi-dev libressl-dev musl-dev git \
    && pip install cffi \
    && /bin/bash -c "pip3 install --no-cache-dir -r <(pipenv lock -r)" \
    && apk del .build-deps

ADD . /httpbin
RUN pip3 install --no-cache-dir /httpbin

EXPOSE 8080

CMD ["gunicorn", "-b", "0.0.0.0:8080", "httpbin:app", "-k", "gevent", "--worker-tmp-dir", "/dev/shm"]
