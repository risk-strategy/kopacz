#!/usr/bin/env bash
# kopacz.sh — 100% Standalone Pure-CLI Client for Kopacz v3 DNS Tunnel
#
# ZERO Python / ZERO C / ZERO non-standard dependencies.
# Uses only standard POSIX/Linux CLI tools:
#   - openssl (X25519 ECDH, HKDF-SHA256, ChaCha20, Poly1305 MAC)
#   - dig (UDP/53 DNS TXT queries) or curl (RFC 8484 DoH JSON queries)
#   - base32, xxd, awk, tr, dd, date
#
# Supported commands:
#   ./clients/bash/kopacz.sh -d <domain> -k <64-hex-pubkey> [-r host[:port]] fetch <url>
#   ./clients/bash/kopacz.sh -d <domain> -k <64-hex-pubkey> [-r host[:port]] echo < file
#   ./clients/bash/kopacz.sh -d <domain> -k <64-hex-pubkey> [-r host[:port]] ssh
#   ./clients/bash/kopacz.sh keygen

set -euo pipefail

# Verify required standard CLI tools
for cmd in openssl base32 xxd awk tr dd date; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: required standard CLI utility '$cmd' not found in PATH" >&2
        exit 1
    fi
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

#ASN.1 DER prefixes for raw 32-byte X25519 keys (RFC 8410)
X25519_PKCS8_PREFIX="302e020100300506032b656e04220420"
X25519_SPKI_PREFIX="302a300506032b656e032100"
ZERO_NONCE_HEX="000000000000000000000000"

# Hex constants for protocol strings
HEX_SYN_INFO="6b6f7061637a2d76332d73796e"              # "kopacz-v3-syn"
HEX_SESSION_INFO="6b6f7061637a2d7633"                  # "kopacz-v3"
HEX_SYN_AAD="6b6f7061637a2d76332d73796e"               # "kopacz-v3-syn"
HEX_SYNACK_AAD_PREFIX="6b6f7061637a2d76332d73796e61636b3a" # "kopacz-v3-synack:"

# ── Base32 (RFC 4648 lowercase unpadded) ─────────────────────────

b32_encode_hex() {
    local hex="$1"
    if [[ -z "$hex" ]]; then
        return 0
    fi
    printf "%s" "$hex" | xxd -r -p | base32 -w 0 | tr '[:upper:]' '[:lower:]' | tr -d '=\n'
}

b32_decode_to_hex() {
    local b32
    b32="$(printf "%s" "$1" | tr -d '=" \t\r\n' | tr '[:lower:]' '[:upper:]')"
    if [[ -z "$b32" ]]; then
        return 0
    fi
    local rem=$(( ${#b32} % 8 ))
    case "$rem" in
        2) b32="${b32}======" ;;
        4) b32="${b32}====" ;;
        5) b32="${b32}===" ;;
        7) b32="${b32}=" ;;
    esac
    printf "%s" "$b32" | base32 -d 2>/dev/null | xxd -p -c 65536 | tr -d '\n'
}

# ── HKDF-SHA256 via openssl kdf ──────────────────────────────────

hkdf_sha256_hex() {
    local ikm_hex="$1"
    local salt_hex="$2"
    local info_hex="$3"
    local byte_len="$4"
    openssl kdf -keylen "$byte_len" \
        -kdfopt digest:SHA256 \
        -kdfopt "hexkey:${ikm_hex}" \
        -kdfopt "hexsalt:${salt_hex}" \
        -kdfopt "hexinfo:${info_hex}" \
        HKDF | tr -d ':\n ' | tr '[:upper:]' '[:lower:]'
}

# ── ChaCha20-Poly1305 AEAD (RFC 7539) via openssl enc + mac ──────

le64_hex() {
    local n="$1"
    awk -v n="$n" 'BEGIN {
        for (i = 0; i < 8; i++) {
            printf "%02x", int(n % 256)
            n = int(n / 256)
        }
    }'
}

pad16_zeros_hex() {
    local byte_len="$1"
    local rem=$(( byte_len % 16 ))
    if (( rem == 0 )); then
        return 0
    fi
    local pad=$(( 16 - rem ))
    printf "%0*d" $(( pad * 2 )) 0
}

aead_poly_tag_hex() {
    local key_hex="$1"
    local nonce_hex="$2"
    local aad_hex="$3"
    local ct_hex="$4"

    # Counter=0 block produces 32-byte Poly1305 one-time key
    local poly_key_hex
    poly_key_hex="$(dd if=/dev/zero bs=32 count=1 2>/dev/null | openssl enc -chacha20 -K "$key_hex" -iv "00000000${nonce_hex}" | xxd -p -c 64 | tr -d '\n')"

    local aad_len=$(( ${#aad_hex} / 2 ))
    local ct_len=$(( ${#ct_hex} / 2 ))
    local aad_pad
    aad_pad="$(pad16_zeros_hex "$aad_len")"
    local ct_pad
    ct_pad="$(pad16_zeros_hex "$ct_len")"
    local aad_len_le
    aad_len_le="$(le64_hex "$aad_len")"
    local ct_len_le
    ct_len_le="$(le64_hex "$ct_len")"

    local mac_input="${aad_hex}${aad_pad}${ct_hex}${ct_pad}${aad_len_le}${ct_len_le}"
    printf "%s" "$mac_input" | xxd -r -p | openssl mac -macopt "hexkey:${poly_key_hex}" POLY1305 | tr -d ':\n ' | tr '[:upper:]' '[:lower:]'
}

aead_seal_hex() {
    local key_hex="$1"
    local nonce_hex="$2"
    local aad_hex="$3"
    local pt_hex="$4"

    local ct_hex=""
    if [[ -n "$pt_hex" ]]; then
        ct_hex="$(printf "%s" "$pt_hex" | xxd -r -p | openssl enc -chacha20 -K "$key_hex" -iv "01000000${nonce_hex}" | xxd -p -c 65536 | tr -d '\n')"
    fi
    local tag_hex
    tag_hex="$(aead_poly_tag_hex "$key_hex" "$nonce_hex" "$aad_hex" "$ct_hex")"
    printf "%s%s" "$ct_hex" "$tag_hex"
}

aead_open_hex() {
    local key_hex="$1"
    local nonce_hex="$2"
    local aad_hex="$3"
    local blob_hex="$4"

    if (( ${#blob_hex} < 32 )); then
        return 1
    fi
    local ct_hex="${blob_hex:0:${#blob_hex}-32}"
    local tag_hex="${blob_hex:${#blob_hex}-32:32}"
    local expected_tag
    expected_tag="$(aead_poly_tag_hex "$key_hex" "$nonce_hex" "$aad_hex" "$ct_hex")"
    if [[ "${tag_hex,,}" != "${expected_tag,,}" ]]; then
        return 1
    fi
    if [[ -n "$ct_hex" ]]; then
        printf "%s" "$ct_hex" | xxd -r -p | openssl enc -d -chacha20 -K "$key_hex" -iv "01000000${nonce_hex}" | xxd -p -c 65536 | tr -d '\n'
    fi
}

# ── Pure-AWK LZ4 Frame Decompressor ──────────────────────────────

lz4_decompress_hex() {
    awk '
    function hex2byte(h,   i, c, v) {
        v = 0
        for (i = 1; i <= 2; i++) {
            c = substr(h, i, 1)
            v = v * 16 + index("0123456789abcdef", tolower(c)) - 1
        }
        return v
    }
    {
        hex = $0
        n = length(hex) / 2
        for (i = 0; i < n; i++) src[i] = hex2byte(substr(hex, i * 2 + 1, 2))
        if (src[0] != 4 || src[1] != 34 || src[2] != 77 || src[3] != 24) exit 1
        flg = src[4]
        b_chk = int(flg / 16) % 2
        c_sz  = int(flg / 8) % 2
        d_id  = flg % 2
        pos = 6
        if (c_sz) pos += 8
        if (d_id) pos += 4
        pos += 1
        olen = 0
        while (pos + 4 <= n) {
            bsz = src[pos] + src[pos+1]*256 + src[pos+2]*65536 + src[pos+3]*16777216
            pos += 4
            if (bsz == 0) break
            uncomp = 0
            if (bsz >= 2147483648) { uncomp = 1; bsz -= 2147483648 }
            bend = pos + bsz
            if (uncomp) {
                while (pos < bend) out[olen++] = src[pos++]
            } else {
                while (pos < bend) {
                    tok = src[pos++]
                    lit = int(tok / 16)
                    if (lit == 15) {
                        while (pos < bend) { b = src[pos++]; lit += b; if (b != 255) break }
                    }
                    for (i = 0; i < lit; i++) out[olen++] = src[pos++]
                    if (pos >= bend) break
                    off = src[pos] + src[pos+1]*256
                    pos += 2
                    mlen = (tok % 16) + 4
                    if (mlen == 19) {
                        while (pos < bend) { b = src[pos++]; mlen += b; if (b != 255) break }
                    }
                    mpos = olen - off
                    for (i = 0; i < mlen; i++) out[olen++] = out[mpos + i]
                }
            }
            if (b_chk) pos += 4
        }
        for (i = 0; i < olen; i++) printf "%02x", out[i]
    }'
}

# ── DNS Carrier & Query (dig UDP/53 or curl DoH) ─────────────────

build_qname() {
    local pkt_hex="$1"
    local b32
    b32="$(b32_encode_hex "$pkt_hex")"
    local labels=""
    local len=${#b32}
    local i=0
    while (( i < len )); do
        local sub="${b32:i:63}"
        labels="${labels}${sub}."
        i=$(( i + 63 ))
    done
    printf "%s%s.%s" "$labels" "$SESSION_TAG" "$DOMAIN"
}

dns_query_txt() {
    local fqdn="$1"
    if [[ "$RESOLVER" =~ ^https?:// ]]; then
        curl -sS --max-time 4 -H "Accept: application/dns-json" "${RESOLVER}?name=${fqdn}&type=TXT" \
            | awk -F'"data":' 'NF>1 { split($2, a, "}"); gsub(/[" \t\r\n]/, "", a[1]); print a[1]; exit }'
    else
        dig +short +time=2 +tries=2 @"$NS_HOST" -p "$NS_PORT" "$fqdn" TXT 2>/dev/null | tr -d '" \t\r\n'
    fi
}

# ── Session Protocol Helpers ─────────────────────────────────────

SEND_CTR=0
SEQ=0
POLL_SEQ=0
HAS_ACK=0
ACK_NUM=0
REASM_SEQ=-1
REASM_TOTAL=0
REASM_GOT=0
declare -A REASM_PARTS

pack_header_hex() {
    local flags="$1"
    local stream_id="$2"
    local seq="$3"
    local fidx="$4"
    local ftotal="$5"
    local rsv="$6"
    printf "%02x%04x%04x%02x%02x%02x" "$flags" "$stream_id" "$seq" "$fidx" "$ftotal" "$rsv"
}

sign_control_hex() {
    local hdr_hex="$1"
    # nonce = "ctrl" (6374726c) || hdr_hex
    local full_tag
    full_tag="$(aead_seal_hex "$C2S_KEY_HEX" "6374726c${hdr_hex}" "$hdr_hex" "")"
    printf "%s" "${full_tag:0:16}"
}

kopacz_connect() {
    # 1. Generate ephemeral X25519 keypair
    openssl genpkey -algorithm X25519 -out "${TMP_DIR}/c_eph.pem" >/dev/null 2>&1
    local c_eph_pub_hex
    c_eph_pub_hex="$(openssl pkey -in "${TMP_DIR}/c_eph.pem" -pubout -outform DER 2>/dev/null | tail -c 32 | xxd -p -c 64 | tr -d '\n')"

    # 2. Wrap server static public key in SPKI DER & compute es = X25519(c_eph, s_static)
    printf "%s%s" "$X25519_SPKI_PREFIX" "$SERVER_PUB_HEX" | xxd -r -p | openssl pkey -pubin -inform DER -out "${TMP_DIR}/s_static.pem" >/dev/null 2>&1
    local es_hex
    es_hex="$(openssl pkeyutl -derive -inkey "${TMP_DIR}/c_eph.pem" -peerkey "${TMP_DIR}/s_static.pem" | xxd -p -c 64 | tr -d '\n')"

    # 3. Derive syn_key and encrypt 8-byte UTC timestamp
    local syn_key_hex
    syn_key_hex="$(hkdf_sha256_hex "$es_hex" "${c_eph_pub_hex}${SERVER_PUB_HEX}" "$HEX_SYN_INFO" 32)"
    local ts_hex
    ts_hex="$(printf "%016x" "$(date +%s)")"
    local sealed_ts_hex
    sealed_ts_hex="$(aead_seal_hex "$syn_key_hex" "$ZERO_NONCE_HEX" "${HEX_SYN_AAD}${c_eph_pub_hex}" "$ts_hex")"

    # 4. Pack 8B SYN header (reserved=60 -> 480B MTU) + 56B SYN payload
    local syn_hdr_hex
    syn_hdr_hex="$(pack_header_hex 128 0 0 0 1 60)"
    local syn_pkt_hex="${syn_hdr_hex}${c_eph_pub_hex}${sealed_ts_hex}"

    local fqdn
    fqdn="$(build_qname "$syn_pkt_hex")"
    local txt
    txt="$(dns_query_txt "$fqdn")"
    if [[ -z "$txt" ]]; then
        echo "Error: No response to SYN from relay" >&2
        return 1
    fi

    local raw_hex
    raw_hex="$(b32_decode_to_hex "$txt")"
    if (( ${#raw_hex} != 112 )); then
        echo "Error: Invalid SYN-ACK length (${#raw_hex} hex chars)" >&2
        return 1
    fi

    local resp_flags=$(( 16#${raw_hex:0:2} ))
    if (( (resp_flags & 160) != 160 )); then
        echo "Error: Response is not SYN-ACK" >&2
        return 1
    fi

    local s_eph_pub_hex="${raw_hex:16:64}"
    local tag_hex="${raw_hex:80:32}"

    # 5. Compute ee = X25519(c_eph, s_eph) and derive session keys
    printf "%s%s" "$X25519_SPKI_PREFIX" "$s_eph_pub_hex" | xxd -r -p | openssl pkey -pubin -inform DER -out "${TMP_DIR}/s_eph.pem" >/dev/null 2>&1
    local ee_hex
    ee_hex="$(openssl pkeyutl -derive -inkey "${TMP_DIR}/c_eph.pem" -peerkey "${TMP_DIR}/s_eph.pem" | xxd -p -c 64 | tr -d '\n')"
    rm -f "${TMP_DIR}/c_eph.pem" # PFS: destroy ephemeral private key immediately

    local material_hex
    material_hex="$(hkdf_sha256_hex "${es_hex}${ee_hex}" "${c_eph_pub_hex}${s_eph_pub_hex}" "$HEX_SESSION_INFO" 96)"
    C2S_KEY_HEX="${material_hex:0:64}"
    S2C_KEY_HEX="${material_hex:64:64}"
    local synack_key_hex="${material_hex:128:64}"

    # 6. Verify SYN-ACK tag
    if ! aead_open_hex "$synack_key_hex" "$ZERO_NONCE_HEX" "${HEX_SYNACK_AAD_PREFIX}${c_eph_pub_hex}${s_eph_pub_hex}" "$tag_hex" >/dev/null; then
        echo "Error: SYN-ACK authentication failed" >&2
        return 1
    fi
    return 0
}

kopacz_ingest_hex() {
    INGESTED_HEX=""
    local raw_hex="$1"
    if (( ${#raw_hex} < 16 )); then
        return 0
    fi
    local flags=$(( 16#${raw_hex:0:2} ))
    local stream_id=$(( 16#${raw_hex:2:4} ))
    local seq=$(( 16#${raw_hex:6:4} ))
    local fidx=$(( 16#${raw_hex:10:2} ))
    local ftotal=$(( 16#${raw_hex:12:2} ))

    if (( (flags & 16) == 0 )); then
        return 0
    fi
    if (( ftotal < 1 || fidx >= ftotal )); then
        return 0
    fi

    if (( REASM_SEQ != seq || REASM_TOTAL != ftotal )); then
        REASM_SEQ=$seq
        REASM_TOTAL=$ftotal
        REASM_GOT=0
        REASM_PARTS=()
    fi
    if [[ -z "${REASM_PARTS[$fidx]:-}" ]]; then
        REASM_GOT=$(( REASM_GOT + 1 ))
    fi
    REASM_PARTS[$fidx]="${raw_hex:16}"

    if (( REASM_GOT < REASM_TOTAL )); then
        return 0
    fi

    local enc_hex=""
    for (( i = 0; i < REASM_TOTAL; i++ )); do
        enc_hex="${enc_hex}${REASM_PARTS[$i]}"
    done
    REASM_SEQ=-1

    if (( ${#enc_hex} < 56 )); then
        return 0
    fi
    local nonce_hex="${enc_hex:0:24}"
    local blob_hex="${enc_hex:24}"
    local comp_bit=$(( flags & 1 ))
    local aad_hex
    aad_hex="$(printf "%02x%04x%04x" "$comp_bit" "$stream_id" "$seq")"

    local dec_hex
    if ! dec_hex="$(aead_open_hex "$S2C_KEY_HEX" "$nonce_hex" "$aad_hex" "$blob_hex")"; then
        return 0
    fi

    HAS_ACK=1
    ACK_NUM=$seq

    if (( comp_bit == 1 )); then
        INGESTED_HEX="$(printf "%s\n" "$dec_hex" | lz4_decompress_hex)"
    else
        INGESTED_HEX="$dec_hex"
    fi
}

kopacz_send_hex() {
    local pt_hex="$1"
    local seq=$SEQ
    SEQ=$(( (SEQ + 1) & 65535 ))

    local nonce_hex
    nonce_hex="$(printf "00000000%016x" "$SEND_CTR")"
    SEND_CTR=$(( SEND_CTR + 1 ))

    local aad_hex
    aad_hex="$(printf "000000%04x" "$seq")"
    local sealed_hex
    sealed_hex="$(aead_seal_hex "$C2S_KEY_HEX" "$nonce_hex" "$aad_hex" "$pt_hex")"
    local enc_hex="${nonce_hex}${sealed_hex}"

    local max_frag_hex=192 # 96 bytes per fragment
    local enc_len=${#enc_hex}
    local total_frags=$(( (enc_len + max_frag_hex - 1) / max_frag_hex ))
    (( total_frags == 0 )) && total_frags=1

    local last_down_hex=""
    for (( idx = 0; idx < total_frags; idx++ )); do
        local fl=$(( 16 | (total_frags > 1 ? 4 : 0) | (HAS_ACK ? 32 : 0) ))
        local rsv=$(( HAS_ACK ? (ACK_NUM & 255) : 0 ))
        local hdr_hex
        hdr_hex="$(pack_header_hex "$fl" 0 "$seq" "$idx" "$total_frags" "$rsv")"
        local chunk_hex="${enc_hex:$(( idx * max_frag_hex )):$max_frag_hex}"
        local fqdn
        fqdn="$(build_qname "${hdr_hex}${chunk_hex}")"
        local txt
        txt="$(dns_query_txt "$fqdn")"
        if [[ -n "$txt" ]]; then
            local raw_hex
            raw_hex="$(b32_decode_to_hex "$txt")"
            kopacz_ingest_hex "$raw_hex"
            if [[ -n "$INGESTED_HEX" ]]; then
                last_down_hex="${last_down_hex}${INGESTED_HEX}"
            fi
        fi
    done
    SENT_DOWN_HEX="$last_down_hex"
}

kopacz_poll_hex() {
    local pseq=$POLL_SEQ
    POLL_SEQ=$(( (POLL_SEQ + 1) & 65535 ))
    local hdr_hex
    if (( HAS_ACK )); then
        hdr_hex="$(pack_header_hex 40 0 "$ACK_NUM" $(( (pseq >> 8) & 255 )) 1 $(( pseq & 255 )))"
    else
        hdr_hex="$(pack_header_hex 8 0 "$pseq" 0 1 0)"
    fi
    local tag8_hex
    tag8_hex="$(sign_control_hex "$hdr_hex")"
    local fqdn
    fqdn="$(build_qname "${hdr_hex}${tag8_hex}")"
    local txt
    txt="$(dns_query_txt "$fqdn")"
    INGESTED_HEX=""
    if [[ -n "$txt" ]]; then
        local raw_hex
        raw_hex="$(b32_decode_to_hex "$txt")"
        kopacz_ingest_hex "$raw_hex"
    fi
}

kopacz_close() {
    local pseq=$POLL_SEQ
    POLL_SEQ=$(( (POLL_SEQ + 1) & 65535 ))
    local hdr_hex
    hdr_hex="$(pack_header_hex 64 0 "$pseq" 0 1 0)"
    local tag8_hex
    tag8_hex="$(sign_control_hex "$hdr_hex")"
    local fqdn
    fqdn="$(build_qname "${hdr_hex}${tag8_hex}")"
    dns_query_txt "$fqdn" >/dev/null || true
}

# ── CLI Argument Parsing ─────────────────────────────────────────

DOMAIN="${KOPACZ_DOMAIN:-}"
SERVER_PUB_HEX="${KOPACZ_PUBKEY:-${KOPACZ_PSK:-}}"
RESOLVER="${KOPACZ_RESOLVER:-1.1.1.1:53}"
SESSION_TAG=""

while [[ $# -gt 0 && "$1" == -* ]]; do
    case "$1" in
        -d|--domain)   DOMAIN="$2"; shift 2 ;;
        -k|--pubkey|--psk) SERVER_PUB_HEX="$2"; shift 2 ;;
        -r|--resolver) RESOLVER="$2"; shift 2 ;;
        -t|--tag)      SESSION_TAG="$2"; shift 2 ;;
        -p|--posture)  shift 2 ;; # accepted for CLI compatibility
        *) break ;;
    esac
done

CMD="${1:-}"
shift || true

if [[ "$CMD" == "keygen" ]]; then
    openssl genpkey -algorithm X25519 -out "${TMP_DIR}/kg.pem" >/dev/null 2>&1
    priv_hex="$(openssl pkey -in "${TMP_DIR}/kg.pem" -outform DER 2>/dev/null | tail -c 32 | xxd -p -c 64 | tr -d '\n')"
    pub_hex="$(openssl pkey -in "${TMP_DIR}/kg.pem" -pubout -outform DER 2>/dev/null | tail -c 32 | xxd -p -c 64 | tr -d '\n')"
    echo "KOPACZ_PRIVKEY=${priv_hex}"
    echo "KOPACZ_PUBKEY=${pub_hex}"
    exit 0
fi

if [[ -z "$DOMAIN" || ${#SERVER_PUB_HEX} -ne 64 || -z "$CMD" ]]; then
    echo "Usage: $0 -d <domain> -k <64-hex-pubkey> [-r host[:port]] <fetch <url> | echo | ssh | keygen>" >&2
    exit 1
fi

NS_HOST="${RESOLVER%%:*}"
NS_PORT="${RESOLVER##*:}"
[[ "$NS_PORT" == "$NS_HOST" ]] && NS_PORT=53

if [[ -z "$SESSION_TAG" ]]; then
    SESSION_TAG="$(head -c 16 /dev/urandom | base32 -w 0 | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9')"
    SESSION_TAG="${SESSION_TAG:0:8}"
fi

kopacz_connect

if [[ "$CMD" == "echo" ]]; then
    IN_HEX="$(xxd -p -c 65536 | tr -d '\n')"
    IN_LEN=$(( ${#IN_HEX} / 2 ))
    # Send in 2048-byte (4096-hex-char) chunks
    OFF=0
    while (( OFF < ${#IN_HEX} )); do
        SLICE_HEX="${IN_HEX:OFF:4096}"
        SLICE_BYTES=$(( ${#SLICE_HEX} / 2 ))
        kopacz_send_hex "$SLICE_HEX"
        OUT_HEX="$SENT_DOWN_HEX"
        GOT_BYTES=$(( ${#OUT_HEX} / 2 ))
        if [[ -n "$OUT_HEX" ]]; then
            printf "%s" "$OUT_HEX" | xxd -r -p
        fi
        while (( GOT_BYTES < SLICE_BYTES )); do
            kopacz_poll_hex
            POLLED_HEX="$INGESTED_HEX"
            if [[ -n "$POLLED_HEX" ]]; then
                printf "%s" "$POLLED_HEX" | xxd -r -p
                GOT_BYTES=$(( GOT_BYTES + ${#POLLED_HEX} / 2 ))
            fi
        done
        OFF=$(( OFF + 4096 ))
    done
elif [[ "$CMD" == "fetch" ]]; then
    URL="${1:-}"
    if [[ -z "$URL" ]]; then
        echo "Error: fetch requires a URL" >&2
        exit 1
    fi
    URL_HEX="$(printf "%s" "$URL" | xxd -p -c 4096 | tr -d '\n')"
    # APP_WEB (0x04) + FETCH_READER (0x03) + URL
    kopacz_send_hex "0403${URL_HEX}"
    DOWN_HEX="$SENT_DOWN_HEX"
    DONE=0
    EMPTY=0
    while (( !DONE && EMPTY < 40 )); do
        if [[ -n "$DOWN_HEX" ]]; then
            EMPTY=0
            TYPE_BYTE=$(( 16#${DOWN_HEX:0:2} ))
            if (( TYPE_BYTE == 2 && ${#DOWN_HEX} > 2 )); then
                printf "%s" "${DOWN_HEX:2}" | xxd -r -p
            elif (( TYPE_BYTE == 3 )); then
                DONE=1
            fi
        else
            EMPTY=$(( EMPTY + 1 ))
            sleep 0.05
        fi
        if (( !DONE )); then
            kopacz_poll_hex
            DOWN_HEX="$INGESTED_HEX"
        fi
    done
fi

kopacz_close
exit 0
