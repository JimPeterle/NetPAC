FROM ubuntu:26.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    NETPAC_DOCKER=1 \
    NETPAC_STATE_DIR=/home/netpac/state \
    APP_DIR=/home/netpac/bin/NetPAC

ARG APT_REFRESH=manual

RUN echo "Package refresh: $APT_REFRESH" \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 python3-venv \
        python3-flask python3-flask-login python3-flask-bcrypt python3-flask-limiter python3-flaskext.wtf \
        python3-pyrad python3-dotenv python3-pymysql python3-cryptography python3-markdown \
        python3-gunicorn python3-pyotp python3-qrcode python3-pil python3-apscheduler python3-sqlalchemy \
        python3-paramiko \
        ansible graphviz git openssh-client sshpass mariadb-client openssl \
        ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

RUN userdel --remove ubuntu 2>/dev/null || true \
    && useradd --create-home --uid 1000 --user-group --shell /bin/bash netpac

WORKDIR /home/netpac/bin/NetPAC
COPY --chown=netpac:netpac . .

RUN cp docker/gunicorn_config.py gunicorn_config.py \
    && chmod 755 docker/entrypoint.sh \
    && python3 -m venv venv \
    && venv/bin/pip install --no-cache-dir ansible-playbook-grapher \
    && mkdir -p /home/netpac/state /home/netpac/.ansible /home/netpac/.ssh /home/netpac/bin/netpac_backups \
    && chmod 700 /home/netpac/.ssh /home/netpac/state \
    && chown -R netpac:netpac /home/netpac

ENTRYPOINT ["/home/netpac/bin/NetPAC/docker/entrypoint.sh"]
CMD ["web"]
