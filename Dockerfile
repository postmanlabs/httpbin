FROM python:3.10-slim AS build

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get -y update
RUN apt-get install -y \
    python3-pip \
    python3-venv

RUN python3 -m venv /opt/httpbin
RUN /opt/httpbin/bin/pip install -U pip

ADD requirements.txt /requirements.txt
RUN /opt/httpbin/bin/pip install --no-deps --requirement /requirements.txt

ADD . /httpbin
RUN /opt/httpbin/bin/pip install --no-deps /httpbin


# ----------------------------------------------------------------------------

FROM python:3.10-slim AS prod

ARG APP_VERSION
LABEL name="httpbin"
LABEL version=${APP_VERSION}
LABEL description="A simple HTTP service."
LABEL org.kennethreitz.vendor="Kenneth Reitz"

COPY --from=build /opt/httpbin /opt/httpbin
ADD httpbin.bash /opt/httpbin/bin
RUN chmod +x /opt/httpbin/bin/httpbin.bash
EXPOSE 80
CMD ["/opt/httpbin/bin/httpbin.bash"]
