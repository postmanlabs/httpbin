FROM python:3-alpine

LABEL name="httpbin"
LABEL version="0.9.2"
LABEL description="A simple HTTP service."
LABEL org.kennethreitz.vendor="Kenneth Reitz"

WORKDIR /srv

# until we have precompiled gevent + brotli, we need this:
RUN apk add --no-cache --repository=http://nl.alpinelinux.org/alpine/v3.8/main \
    build-base \
    gcc \
    musl-dev

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 80

CMD ["gunicorn", "-b", "0.0.0.0:80", "httpbin:app", "-k", "gevent"]
