# SaiRecon — Docker image
# Build:  docker build -t sairecon .
# Scan:   docker run --rm -v "$(pwd)/reports:/app/sairecon_output" sairecon scan example.com --yes

FROM python:3.11-slim-bookworm

LABEL maintainer="Sai Vishwaa <saivishwaaincloud@gmail.com>"
LABEL description="SaiRecon — full recon pipeline, no attack code"

ENV DEBIAN_FRONTEND=noninteractive
ENV GOVERSION=1.22.5
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

# System packages
RUN apt-get update -q && \
    apt-get install -y -q --no-install-recommends \
        whois dnsutils nmap git curl unzip wget \
        libpcap-dev ca-certificates && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Go
RUN curl -fsSL "https://go.dev/dl/go${GOVERSION}.linux-amd64.tar.gz" \
        -o /tmp/go.tar.gz && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz

# Go tools (required)
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/tomnomnom/assetfinder@latest && \
    go install github.com/tomnomnom/anew@latest && \
    go install github.com/tomnomnom/unfurl@latest && \
    go install github.com/tomnomnom/gf@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/sensepost/gowitness@latest

# gf patterns
RUN git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns /tmp/gf && \
    mkdir -p /root/.gf && cp /tmp/gf/*.json /root/.gf/ && rm -rf /tmp/gf

WORKDIR /app
COPY . /app

# Python deps + sairecon
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir wafw00f arjun && \
    pip install --no-cache-dir -e .

VOLUME ["/app/sairecon_output"]

ENTRYPOINT ["sairecon"]
CMD ["--help"]
