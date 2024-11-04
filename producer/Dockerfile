FROM gcc:latest

WORKDIR /app

COPY . .

RUN apt-get update && apt-get install -y \
    librdkafka-dev \
    libpcap-dev \
    protobuf-compiler \
    libprotobuf-dev \
    pkg-config \
    autoconf \
    automake \
    libtool \
    make \
    git

RUN git clone "https://github.com/protobuf-c/protobuf-c.git" && \
    cd protobuf-c && \
    ./autogen.sh && \
    ./configure && \
    make && \
    make install

RUN gcc -Wall -Wextra -Werror -o producer producer.c dns.pb-c.c main.pb-c.c -lrdkafka -lprotobuf-c -lpcap -lresolv

CMD ["./producer"]