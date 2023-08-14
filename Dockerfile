FROM python:3.10-slim

ARG APP_VERSION
LABEL name="httpbin"
LABEL version=${APP_VERSION}
LABEL description="A simple HTTP service."
LABEL org.kennethreitz.vendor="Kenneth Reitz"

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

RUN apt update -y && apt install python3-pip git -y

ADD requirements.txt /httpbin/
WORKDIR /httpbin
RUN /bin/bash -c "pip3 install --no-cache-dir -r requirements.txt"

ADD . /httpbin
RUN pip3 install --no-cache-dir --no-deps /httpbin
RUN chmod +x /httpbin/httpbin.bash
RUN pip3 list

EXPOSE 80

CMD ["/httpbin/httpbin.bash"]
