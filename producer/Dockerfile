FROM gcc:latest

WORKDIR /app

COPY . .

RUN apt-get update && apt-get install -y \
    librdkafka-dev \
    libpcap-dev \
    protobuf-c-compiler \
    pkg-config

RUN gcc -Wall -Wextra -Werror -o producer producer.c dns.pb-c.c main.pb-c.c -lrdkafka -lprotobuf-c -lpcap -lresolv

CMD ["./producer"]