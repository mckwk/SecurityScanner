FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
WORKDIR /app

# copy requirements early for layer caching
COPY requirements-api.txt /app/requirements-api.txt

# install runtime deps + build deps, install python packages, then remove build deps
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      nmap \
      libffi-dev \
      libssl-dev \
      build-essential \
      python3-dev \
    && pip install --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -r /app/requirements-api.txt gunicorn \
    && apt-get purge -y --auto-remove build-essential python3-dev \
    && rm -rf /var/lib/apt/lists/* /root/.cache/pip

# copy project
COPY . /app

EXPOSE 5000

# run the Flask app via gunicorn (api:app)
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "api:app"]