FROM ubuntu
ENV PATH="/root/.local/bin:${PATH}"
RUN apt-get update \
&& apt-get -y install --no-install-recommends ca-certificates wget \
&& wget -qO- https://get.haskellstack.org/ | sh \
&& stack install qnap-decrypt
