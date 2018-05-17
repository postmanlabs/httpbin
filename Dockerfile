FROM python:3-alpine

ADD . /httpbin

RUN apk add -U ca-certificates libffi libstdc++ && \
    apk add --virtual build-deps build-base libffi-dev && \
    # Pip
    pip install --no-cache-dir gunicorn /httpbin && \
    # Cleaning up
    apk del build-deps && \
    rm -rf /var/cache/apk/*

EXPOSE 80

CMD ["gunicorn", "-b", "0.0.0.0:80", "httpbin:app", "-k", "gevent"]
