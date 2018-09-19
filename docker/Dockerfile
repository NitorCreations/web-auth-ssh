FROM nitor/nitor-backend:1.15

USER root
RUN apt-get update && apt-get install -y python3-pip && \
    rm -rf /var/lib/apt/lists/* && \
    pip3 install --no-cache-dir nitor-vault web-auth-ssh==0.3

USER user
