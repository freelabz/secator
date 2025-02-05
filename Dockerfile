FROM alpine:latest

ENV PATH="${PATH}:/root/go/bin:/root/.local/bin"
RUN apk add --no-cache \
	bash \
	build-base \
	chromium \
	curl \
	gcc \
	git \
	go \
	linux-headers \
    openssl \
	pipx \
	proxychains-ng \
	python3 \
	python3-dev \
	py3-pip \
	ruby \
	ruby-dev \
	sudo \
	unzip
COPY . /code
WORKDIR /code
RUN pipx install . && \
	secator install addons worker && \
	secator install addons gdrive && \
	secator install addons gcs && \
	secator install addons mongodb && \
	secator install addons redis && \
	secator install addons dev
RUN secator config set security.force_source_install true
RUN secator install tools
ENTRYPOINT ["secator"]
