FROM python:alpine
MAINTAINER Craig J Smith <craig.j.smith@dell.com>

RUN apk upgrade --purge && \
    apk add --no-cache --virtual .pynacl_deps \
                                 libressl-dev \
                                 musl-dev \
                                 libffi-dev \
                                 build-base \
                                 openssl-dev \
                                 make \
                                 cmake \
                                 cargo \
                                 python3-dev && \
    pip install --upgrade --no-cache-dir pip && \
    pip install --no-cache-dir powerprotect && \
    apk del .pynacl_deps \
            libressl-dev \
            musl-dev \
            libffi-dev \
            build-base \
            openssl-dev \
            cargo
