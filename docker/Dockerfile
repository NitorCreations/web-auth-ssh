FROM python:3.7-alpine as base

FROM base as deps

RUN apk add openssl libffi

FROM deps as builder

RUN apk add build-base libffi-dev openssl-dev && \
    python -m pip install --no-cache-dir --install-option="--prefix=/pyinstall" -U nitor-vault==0.28 web-auth-ssh==0.15

FROM deps
ENV ENV prod
COPY --from=builder /pyinstall /usr/local

ENTRYPOINT ["/bin/sh", "-c", "vault -l keyserver-$ENV.yaml > /etc/web-auth-ssh.conf && wa-keyserver"]
