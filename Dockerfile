FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY traffic_checker_core.py traffic_checker_cli.py ./

CMD ["python", "traffic_checker_cli.py", "--duration", "60", "--interval", "5"]
