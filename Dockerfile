FROM alpine:3.22

RUN apk add --no-cache \
      build-base \
      lua5.4 \
      lua5.4-dev \
      luarocks \
  && luarocks-5.4 install busted

WORKDIR /work
COPY . .

CMD ["busted", "--verbose"]
