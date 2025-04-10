FROM python:3.11-slim-buster

LABEL name="httpbin"
LABEL version="0.9.3"
LABEL description="A simple HTTP service. It has a change from the original httpbin to add Server Logs for testing."
LABEL org.kennethreitz.vendor="Kenneth Reitz"
LABEL org.jsinnertech.vendor="Jose Gabriel Gonzalez"

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

RUN apt update -y && apt install python3-pip git -y && pip3 install --no-cache-dir pipenv
RUN apt install -y libpq-dev libffi-dev libssl-dev libxml2-dev libxslt1-dev zlib1g-dev
RUN pip3 install --no-cache-dir gunicorn gevent pytz

ADD Pipfile Pipfile.lock /httpbin/
WORKDIR /httpbin
RUN /bin/bash -c "pip3 install --no-cache-dir -r <(pipenv lock -r)"

ADD . /httpbin
RUN pip3 install --no-cache-dir /httpbin

EXPOSE 80

# Use the gevent worker for better performance
# and to avoid the "RuntimeError: main thread is not in main loop" error
# when using the default sync worker.
# gunicorn -b 0.0.0.0:80 httpbin:app -k gevent
CMD ["gunicorn", "-b", "0.0.0.0:8080", "httpbin:app", "-k", "gevent"]
