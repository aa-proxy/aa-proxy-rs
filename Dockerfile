# syntax=docker/dockerfile:1-labs
FROM rust:latest AS stage-rust
# crosscompile stuff
RUN apt update && apt upgrade -y
RUN apt install -y gcc-arm-linux-gnueabihf
RUN rustup target add arm-unknown-linux-gnueabihf
# cloning and building
WORKDIR /usr/src/app
RUN git clone --branch bt-tryfix https://github.com/manio/aa-proxy-rs .
RUN cargo build --release
RUN arm-linux-gnueabihf-strip target/arm-unknown-linux-gnueabihf/release/aa-proxy-rs
# Pi Zero W needs special linking/building (https://github.com/manio/aa-proxy-rs/issues/3)
RUN git clone --depth=1 https://github.com/raspberrypi/tools
RUN CARGO_TARGET_DIR=pi0w CARGO_TARGET_ARM_UNKNOWN_LINUX_GNUEABIHF_LINKER="./tools/arm-bcm2708/arm-rpi-4.9.3-linux-gnueabihf/bin/arm-linux-gnueabihf-gcc" cargo build --release

# injecting aa-proxy-rs into all SD card images
FROM alpine AS stage-sdcards
RUN apk --no-cache add xz
WORKDIR /root
COPY --from=stage-rust /usr/src/app/target/arm-unknown-linux-gnueabihf/release/aa-proxy-rs .
COPY --from=stage-rust /usr/src/app/pi0w/arm-unknown-linux-gnueabihf/release/aa-proxy-rs ./aa-proxy-rs-0w
ADD contrib/injector.sh .
ADD contrib/S93aa-proxy-rs .
ADD contrib/config.toml .
RUN --security=insecure ./injector.sh

# copy the resulting binary out of container to local dir
FROM scratch AS custom-exporter
COPY --from=stage-rust /usr/src/app/target/arm-unknown-linux-gnueabihf/release/aa-proxy-rs .
COPY --from=stage-sdcards /root/raspberrypi0w-sdcard.img.xz .
COPY --from=stage-sdcards /root/raspberrypi3a-sdcard.img.xz .
COPY --from=stage-sdcards /root/raspberrypi4-sdcard.img.xz .
COPY --from=stage-sdcards /root/raspberrypizero2w-sdcard.img.xz .
