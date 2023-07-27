FROM python:3.8-alpine

RUN apk --update add --no-cache \
    gcc \
    python3-dev \
    build-base \
    libffi-dev \
    musl-dev \
    git

COPY . /httpbin/
WORKDIR /httpbin
RUN pip install -r requirements.txt

EXPOSE 8000

CMD ["gunicorn", "-b", "0.0.0.0:8000", "-w", "4", "-k", "gevent", "httpbin:app"]