FROM alpine:3.12

LABEL name="httpbin"
LABEL version="0.9.2"
LABEL description="A simple HTTP service."
LABEL org.kennethreitz.vendor="Kenneth Reitz"

ADD . /httpbin

RUN apk update && apk upgrade && apk add py-pip
# until we have precompiled gevent + brotli, we need this:
RUN apk add --no-cache --virtual .build-deps \
    build-base \
    gcc \
    g++ \
    musl-dev \
    python3-dev \
    libffi-dev \
    openssl-dev \
    libstdc++6

RUN pip install --no-cache-dir wheel
RUN pip install --no-cache-dir gunicorn /httpbin

EXPOSE 80

CMD ["gunicorn", "-b", "0.0.0.0:80", "httpbin:app", "-k", "gevent"]
