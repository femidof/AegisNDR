FROM python:3.12-slim@sha256:646fb0bca3dd3ea1bcc6feb72c17ed16eed6e10cffc732fcc1478bd3e7f02d7b
WORKDIR /app
COPY infra/compose/python-requirements.txt /tmp/python-requirements.txt
RUN pip install --no-cache-dir --requirement /tmp/python-requirements.txt
COPY apps apps
COPY services services
COPY packages packages
RUN install -d -o 65532 -g 65532 -m 0700 /var/lib/hybrid-ndr \
 && install -d -o 65532 -g 65532 -m 0700 /var/lib/hybrid-ndr/connector \
 && install -d -o 65532 -g 65532 -m 0700 /var/lib/hybrid-ndr/identity \
 && install -d -o 65532 -g 65532 -m 0700 /var/lib/hybrid-ndr/updates
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
USER 65532:65532
