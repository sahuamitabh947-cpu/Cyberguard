FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake libssl-dev libpcap-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY CMakeLists.txt ./
COPY include ./include
COPY src ./src
RUN cmake -B build -DCMAKE_BUILD_TYPE=Release -DWITH_PCAP=ON && cmake --build build -j"$(nproc)" --target cyberguard_engine

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 libpcap0.8 ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/build/cyberguard_engine /app/cyberguard_engine
COPY models ./models
COPY data ./data
EXPOSE 5050
ENV ENGINE_PORT=5050 MODELS_DIR=/app/models PSL_PATH=/app/data/public_suffix_list.dat
CMD ["/app/cyberguard_engine"]
