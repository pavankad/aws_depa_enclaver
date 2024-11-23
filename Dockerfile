FROM amazonlinux

RUN yum install python3 python3-pip net-tools -y

WORKDIR /app

COPY requirements.txt ./
RUN pip3 install -r /app/requirements.txt

COPY kmstool_enclave_cli ./
COPY libnsm.so /lib64
ENV LD_LIBRARY_PATH=/lib64:$LD_LIBRARY_PATH

COPY server.py ./

ENV FLASK_APP=/app/server.py
ENV PYTHONUNBUFFERED=1
ENV AWS_DEFAULT_REGION=us-east-1

EXPOSE 8000
ENTRYPOINT ["python3"]
CMD ["-m", "flask", "run", "--host=0.0.0.0", "--port=8000"]

