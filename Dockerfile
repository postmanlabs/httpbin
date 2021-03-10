FROM python:3.6-alpine

LABEL name="httpbin"
LABEL version="0.9.2"
LABEL description="A simple HTTP service."
LABEL org.kennethreitz.vendor="Kenneth Reitz"

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

ADD . /httpbin/
WORKDIR /httpbin
RUN apk add --no-cache git gcc musl-dev libffi-dev libstdc++ \
 && pip3 install --no-cache-dir pipenv \
 && pipenv lock -r > req.txt \
 && ln -s /usr/lib/libstdc++.so.6 /usr/lib/libstdc++.so \
 && pip3 install --no-cache-dir --upgrade pip setuptools==45.2.0 \
 && pip3 install --no-cache-dir -r req.txt \
 && pip3 install --no-cache-dir /httpbin

EXPOSE 80

CMD ["gunicorn", "-b", "0.0.0.0:80", "httpbin:app", "-k", "gevent"]
