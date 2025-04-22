FROM alpine:latest AS builder

ENV PATH="${PATH}:/root/.local/bin"
RUN apk add --no-cache \
	flock \
	gcc \
	musl-dev \
	linux-headers \
	pipx \
	python3-dev
COPY . /code
WORKDIR /code

RUN pipx install --pip-args="--no-cache-dir" . && \
	secator install addons worker && \
	secator install addons gdrive && \
	secator install addons gcs && \
	secator install addons mongodb && \
	secator install addons redis && \
	secator install addons dev

FROM python:3.12-alpine
ARG flavor=full
ENV TERM="xterm-256color"
ENV PATH="${PATH}:/root/.local/bin"
ENV GOBIN="/root/.local/bin"
COPY --from=builder /root/.local /root/.local
RUN apk add --no-cache \
	flock \
	pipx \
	sudo
RUN if [ "$flavor" != "lite" ]; then secator install tools --cleanup; fi
ENTRYPOINT ["secator"]
