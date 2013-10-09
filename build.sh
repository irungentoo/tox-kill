CRYPTO_OPTS="-lsodium"

gcc -o s-attack-1 sybil-attack-1/DHT.c base/net_crypto.c base/network.c base/util.c base/ping.c base/Lossless_UDP.c base/attack.c $CRYPTO_OPTS
gcc -o s-attack-2 sybil-attack-2/DHT.c base/net_crypto.c base/network.c base/util.c base/ping.c base/Lossless_UDP.c base/attack.c $CRYPTO_OPTS
