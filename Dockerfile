FROM kalilinux/kali-rolling

# Non-interactive installation to avoid prompts
ENV DEBIAN_FRONTEND=noninteractive

# Update and install tools
RUN apt-get update && apt-get install -y \
    nmap \
    gobuster \
    hydra \
    exploitdb \
    tcpdump \
    ffuf \
    responder \
    iputils-ping \
    git \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Set working directory to /workdir (to be mounted)
WORKDIR /workdir

# Entrypoint allowing arbitrary commands
ENTRYPOINT ["/bin/bash", "-c"]

