FROM python:3.11-bookworm

RUN apt-get update
RUN apt-get install -y gcc python3-dev libffi-dev musl-dev git

WORKDIR /httpbin
ADD ./requirements.txt /httpbin/requirements.txt
RUN pip install -r requirements.txt
RUN pip install pytest
COPY . /httpbin/

ENTRYPOINT ["pytest", "test_httpbin.py"]
