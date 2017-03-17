FROM alpine:3.5

ENV WEB_CONCURRENCY=4

ADD . /httpbin

RUN apk add --update python python-dev py-pip build-base ca-certificates libffi-dev
RUN pip install --upgrade pip
RUN pip install gunicorn && pip install /httpbin

EXPOSE 8080

CMD gunicorn -b 0.0.0.0:8080 httpbin:app
