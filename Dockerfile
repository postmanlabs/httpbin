# python:3.15-slim
FROM python@sha256:e97b88e416c3c01eb427b21fd8cd3ebf006e6ee38afcfcc3cae1c54ee2ab0a75 AS build

COPY requirements.txt /tmp/requirements.txt
RUN python -m venv /venv \
    && /venv/bin/pip install --no-cache-dir --disable-pip-version-check --require-hashes -r /tmp/requirements.txt \
    && /venv/bin/pip uninstall --yes --disable-pip-version-check pip

# python:3.15-slim
FROM python@sha256:e97b88e416c3c01eb427b21fd8cd3ebf006e6ee38afcfcc3cae1c54ee2ab0a75

LABEL name="httpbin"
LABEL version="0.9.2"
LABEL description="A simple HTTP service."
LABEL org.kennethreitz.vendor="Kenneth Reitz"

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV PATH=/venv/bin:$PATH

RUN pip uninstall --yes --disable-pip-version-check pip \
    && useradd --system --uid 10001 --user-group --no-create-home httpbin

COPY --from=build /venv /venv
COPY httpbin /app/httpbin
WORKDIR /app

USER httpbin

EXPOSE 80

CMD ["gunicorn", "-b", "0.0.0.0:80", "--no-control-socket", "httpbin:app", "-k", "gevent"]
