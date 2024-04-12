FROM alpine:latest

ENV PATH="${PATH}:/root/go/bin:/root/.local/bin"

RUN apk add --no-cache \
	curl \
	gcc \
	git \
	go \
    make \
	pipx \
	python3-dev \
	ruby \
	sudo \
	vim \
    wget \
	chromium \
    jq \
    openssl \
	proxychains-ng

# Install Metasploit framework
# RUN curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
# RUN chmod 755 msfinstall
# RUN ./msfinstall

# Copy code
WORKDIR /code
COPY . /code/

# Install secator
RUN pipx install .
RUN secator install tools
RUN secator install addons worker
RUN secator install addons google
RUN secator install addons mongodb
RUN secator install addons redis
RUN secator install addons dev

# Set entrypoint
ENTRYPOINT ["secator"]