<#
.SYNOPSIS
    kopacz.ps1 — 100% Standalone Pure-.NET / PowerShell Client for Kopacz v3 DNS Tunnel

.DESCRIPTION
    Zero external binaries, zero Python, zero C compiler.
    Uses ONLY exposed .NET Core / BCL features directly from PowerShell:
      - System.Security.Cryptography.ChaCha20Poly1305 (RFC 7539 AEAD)
      - System.Security.Cryptography.HKDF + SHA256 (RFC 5869 key schedule)
      - System.Security.Cryptography.RandomNumberGenerator (CSPRNG)
      - System.Numerics.BigInteger (RFC 7748 X25519 Montgomery ladder mod 2^255 - 19)
      - System.Net.Sockets.UdpClient (UDP/53 DNS wire packets)
      - System.Net.Http.HttpClient (RFC 8484 DoH JSON queries)
      - Built-in managed LZ4 Frame decompressor (0x184D2204)

.EXAMPLE
    pwsh .\clients\powershell\kopacz.ps1 -d t.example.com -k <64-hex-pubkey> -r 1.1.1.1:53 fetch https://example.com
    Get-Content payload.bin -AsByteStream | pwsh .\clients\powershell\kopacz.ps1 -d t.example.com -k <64-hex-pubkey> echo
    pwsh .\clients\powershell\kopacz.ps1 keygen
#>
$ErrorActionPreference = "Stop"

# ── Embedded .NET Helper for Fast X25519 (BigInteger), Base32, LZ4 & DNS Wire ──
if (-not ("KopaczNet.Core" -as [type])) {
    Add-Type -Language CSharp -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace KopaczNet
{
    public static class Core
    {
        // 2^255 - 19
        private static readonly BigInteger P = (BigInteger.One << 255) - new BigInteger(19);
        private static readonly BigInteger A24 = new BigInteger(121665);

        private static BigInteger ModP(BigInteger x)
        {
            BigInteger r = x % P;
            return r.Sign < 0 ? r + P : r;
        }

        // RFC 7748 Section 5 X25519 scalar multiplication using System.Numerics.BigInteger
        public static byte[] X25519(byte[] kInput, byte[] uInput)
        {
            byte[] k = (byte[])kInput.Clone();
            k[0] &= 248;
            k[31] &= 127;
            k[31] |= 64;

            byte[] uBytes = new byte[33];
            Buffer.BlockCopy(uInput, 0, uBytes, 0, 32);
            uBytes[31] &= 127; // mask high bit per RFC 7748
            BigInteger u = ModP(new BigInteger(uBytes));

            BigInteger x_1 = u;
            BigInteger x_2 = BigInteger.One;
            BigInteger z_2 = BigInteger.Zero;
            BigInteger x_3 = u;
            BigInteger z_3 = BigInteger.One;
            int swap = 0;

            for (int t = 254; t >= 0; t--)
            {
                int k_t = (k[t >> 3] >> (t & 7)) & 1;
                swap ^= k_t;
                if (swap != 0)
                {
                    BigInteger tmp = x_2; x_2 = x_3; x_3 = tmp;
                    tmp = z_2; z_2 = z_3; z_3 = tmp;
                }
                swap = k_t;

                BigInteger A  = ModP(x_2 + z_2);
                BigInteger AA = ModP(A * A);
                BigInteger B  = ModP(x_2 - z_2);
                BigInteger BB = ModP(B * B);
                BigInteger E  = ModP(AA - BB);
                BigInteger C  = ModP(x_3 + z_3);
                BigInteger D  = ModP(x_3 - z_3);
                BigInteger DA = ModP(D * A);
                BigInteger CB = ModP(C * B);

                BigInteger sum = ModP(DA + CB);
                x_3 = ModP(sum * sum);
                BigInteger diff = ModP(DA - CB);
                z_3 = ModP(x_1 * ModP(diff * diff));
                x_2 = ModP(AA * BB);
                z_2 = ModP(E * ModP(AA + ModP(A24 * E)));
            }

            if (swap != 0)
            {
                BigInteger tmp = x_2; x_2 = x_3; x_3 = tmp;
                tmp = z_2; z_2 = z_3; z_3 = tmp;
            }

            BigInteger zInv = BigInteger.ModPow(z_2, P - new BigInteger(2), P);
            BigInteger res  = ModP(x_2 * zInv);

            byte[] raw = res.ToByteArray();
            byte[] out32 = new byte[32];
            Buffer.BlockCopy(raw, 0, out32, 0, Math.Min(32, raw.Length));
            return out32;
        }

        public static byte[] X25519Base(byte[] kInput)
        {
            byte[] basePoint = new byte[32];
            basePoint[0] = 9;
            return X25519(kInput, basePoint);
        }

        // ── RFC 7539 ChaCha20-Poly1305 via .NET Core System.Security.Cryptography.ChaCha20Poly1305 ──
        public static byte[] AeadSeal(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad)
        {
            byte[] ct = new byte[plaintext.Length];
            byte[] tag = new byte[16];
            using (var aead = new ChaCha20Poly1305(key))
            {
                aead.Encrypt(nonce, plaintext, ct, tag, aad);
            }
            byte[] combined = new byte[ct.Length + 16];
            Buffer.BlockCopy(ct, 0, combined, 0, ct.Length);
            Buffer.BlockCopy(tag, 0, combined, ct.Length, 16);
            return combined;
        }

        public static byte[] AeadOpen(byte[] key, byte[] nonce, byte[] combined, byte[] aad)
        {
            if (combined == null || combined.Length < 16) return null;
            int ctLen = combined.Length - 16;
            byte[] ct = new byte[ctLen];
            byte[] tag = new byte[16];
            Buffer.BlockCopy(combined, 0, ct, 0, ctLen);
            Buffer.BlockCopy(combined, ctLen, tag, 0, 16);
            byte[] pt = new byte[ctLen];
            try
            {
                using (var aead = new ChaCha20Poly1305(key))
                {
                    aead.Decrypt(nonce, ct, tag, pt, aad);
                }
                return pt;
            }
            catch
            {
                return null;
            }
        }

        // ── RFC 5869 HKDF-SHA256 via .NET Core System.Security.Cryptography.HKDF ──
        public static byte[] HkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length)
        {
            return HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, length, salt, info);
        }

        // ── Base32 (RFC 4648 Lowercase Unpadded) ──
        private const string B32Alphabet = "abcdefghijklmnopqrstuvwxyz234567";

        public static string Base32Encode(byte[] data)
        {
            if (data == null || data.Length == 0) return string.Empty;
            var sb = new StringBuilder((data.Length * 8 + 4) / 5);
            int acc = 0, bits = 0;
            for (int i = 0; i < data.Length; i++)
            {
                acc = (acc << 8) | data[i];
                bits += 8;
                while (bits >= 5)
                {
                    bits -= 5;
                    sb.Append(B32Alphabet[(acc >> bits) & 0x1F]);
                }
            }
            if (bits > 0)
            {
                sb.Append(B32Alphabet[(acc << (5 - bits)) & 0x1F]);
            }
            return sb.ToString();
        }

        public static byte[] Base32Decode(string text)
        {
            if (string.IsNullOrEmpty(text)) return Array.Empty<byte>();
            var outList = new List<byte>(text.Length * 5 / 8);
            int acc = 0, bits = 0;
            for (int i = 0; i < text.Length; i++)
            {
                char c = text[i];
                int v = -1;
                if (c >= 'a' && c <= 'z') v = c - 'a';
                else if (c >= 'A' && c <= 'Z') v = c - 'A';
                else if (c >= '2' && c <= '7') v = c - '2' + 26;
                if (v < 0) continue;
                acc = (acc << 5) | v;
                bits += 5;
                if (bits >= 8)
                {
                    bits -= 8;
                    outList.Add((byte)((acc >> bits) & 0xFF));
                }
            }
            return outList.ToArray();
        }

        // ── LZ4 Frame Decompressor (0x184D2204) ──
        public static byte[] Lz4DecompressFrame(byte[] src)
        {
            if (src == null || src.Length < 7) return null;
            if (src[0] != 0x04 || src[1] != 0x22 || src[2] != 0x4D || src[3] != 0x18) return null;
            byte flg = src[4];
            bool bChecksum = (flg & 0x10) != 0;
            bool cSize     = (flg & 0x08) != 0;
            bool dictId    = (flg & 0x01) != 0;
            int pos = 6;
            if (cSize) pos += 8;
            if (dictId) pos += 4;
            pos += 1; // header checksum

            var dst = new List<byte>(src.Length * 3);
            while (pos + 4 <= src.Length)
            {
                uint bsz = (uint)(src[pos] | (src[pos + 1] << 8) | (src[pos + 2] << 16) | (src[pos + 3] << 24));
                pos += 4;
                if (bsz == 0) break;
                bool uncomp = (bsz & 0x80000000U) != 0;
                int blockLen = (int)(bsz & 0x7FFFFFFFU);
                int bEnd = pos + blockLen;
                if (bEnd > src.Length) return null;

                if (uncomp)
                {
                    for (int i = pos; i < bEnd; i++) dst.Add(src[i]);
                    pos = bEnd;
                }
                else
                {
                    while (pos < bEnd)
                    {
                        int token = src[pos++];
                        int litLen = token >> 4;
                        if (litLen == 15)
                        {
                            byte s;
                            do { s = src[pos++]; litLen += s; } while (s == 255 && pos < bEnd);
                        }
                        for (int i = 0; i < litLen; i++) dst.Add(src[pos++]);
                        if (pos >= bEnd) break;
                        int offset = src[pos] | (src[pos + 1] << 8);
                        pos += 2;
                        if (offset == 0 || offset > dst.Count) return null;
                        int matchLen = (token & 0x0F) + 4;
                        if (matchLen == 19)
                        {
                            byte s;
                            do { s = src[pos++]; matchLen += s; } while (s == 255 && pos < bEnd);
                        }
                        int matchPos = dst.Count - offset;
                        for (int i = 0; i < matchLen; i++) dst.Add(dst[matchPos + i]);
                    }
                }
                if (bChecksum) pos += 4;
            }
            return dst.ToArray();
        }

        // ── UDP/53 DNS TXT Query via System.Net.Sockets.UdpClient ──
        private static int SkipDnsName(byte[] buf, int pos)
        {
            while (pos < buf.Length)
            {
                int l = buf[pos];
                if (l == 0) return pos + 1;
                if ((l & 0xC0) == 0xC0) return pos + 2;
                pos += 1 + l;
            }
            return buf.Length;
        }

        public static string QueryDnsUdpTxt(string nsHost, int nsPort, string fqdn, int timeoutMs = 2000)
        {
            using (var udp = new UdpClient())
            {
                udp.Client.ReceiveTimeout = timeoutMs;
                udp.Client.SendTimeout = timeoutMs;
                var ms = new MemoryStream(512);
                byte[] txid = RandomNumberGenerator.GetBytes(2);
                ms.Write(txid, 0, 2);
                ms.Write(new byte[] { 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }, 0, 10);
                foreach (string lbl in fqdn.TrimEnd('.').Split('.'))
                {
                    byte[] lb = Encoding.ASCII.GetBytes(lbl);
                    ms.WriteByte((byte)lb.Length);
                    ms.Write(lb, 0, lb.Length);
                }
                ms.WriteByte(0x00);
                ms.Write(new byte[] { 0x00, 0x10, 0x00, 0x01 }, 0, 4); // QTYPE=TXT, QCLASS=IN
                // EDNS0 OPT record (4096-byte UDP payload)
                ms.Write(new byte[] { 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 0, 11);

                byte[] q = ms.ToArray();
                var ep = new IPEndPoint(IPAddress.Parse(nsHost), nsPort);
                for (int attempt = 0; attempt < 3; attempt++)
                {
                    try
                    {
                        udp.Send(q, q.Length, ep);
                        IPEndPoint remote = null;
                        byte[] resp = udp.Receive(ref remote);
                        if (resp.Length < 12 || resp[0] != txid[0] || resp[1] != txid[1]) continue;
                        int qd = (resp[4] << 8) | resp[5];
                        int an = (resp[6] << 8) | resp[7];
                        int pos = 12;
                        for (int i = 0; i < qd; i++) pos = SkipDnsName(resp, pos) + 4;
                        var sb = new StringBuilder();
                        for (int i = 0; i < an && pos < resp.Length; i++)
                        {
                            pos = SkipDnsName(resp, pos);
                            if (pos + 10 > resp.Length) break;
                            int rtype = (resp[pos] << 8) | resp[pos + 1];
                            int rdlen = (resp[pos + 8] << 8) | resp[pos + 9];
                            pos += 10;
                            if (rtype == 16 && pos + rdlen <= resp.Length)
                            {
                                int end = pos + rdlen;
                                int p = pos;
                                while (p < end)
                                {
                                    int sl = resp[p++];
                                    if (p + sl <= end)
                                    {
                                        sb.Append(Encoding.ASCII.GetString(resp, p, sl));
                                    }
                                    p += sl;
                                }
                            }
                            pos += rdlen;
                        }
                        return sb.ToString();
                    }
                    catch (SocketException)
                    {
                        continue;
                    }
                }
                return string.Empty;
            }
        }
    }
}
"@
}

# ── Helper Functions ─────────────────────────────────────────────

function ConvertFrom-Hex([string]$hex) {
    return [Convert]::FromHexString($hex)
}

function ConvertTo-Hex([byte[]]$bytes) {
    return [Convert]::ToHexString($bytes).ToLowerInvariant()
}

# ── CLI Argument Parsing ─────────────────────────────────────────

$Domain    = $env:KOPACZ_DOMAIN
$PubKeyHex = if ($env:KOPACZ_PUBKEY) { $env:KOPACZ_PUBKEY } else { $env:KOPACZ_PSK }
$Resolver  = if ($env:KOPACZ_RESOLVER) { $env:KOPACZ_RESOLVER } else { "1.1.1.1:53" }
$Tag       = ""

$idx = 0
while ($idx -lt $args.Count -and ([string]$args[$idx]).StartsWith("-")) {
    switch ([string]$args[$idx]) {
        { $_ -in "-d", "--domain" }   { $Domain    = [string]$args[$idx + 1]; $idx += 2; continue }
        { $_ -in "-k", "--pubkey", "--psk" } { $PubKeyHex = [string]$args[$idx + 1]; $idx += 2; continue }
        { $_ -in "-r", "--resolver" } { $Resolver  = [string]$args[$idx + 1]; $idx += 2; continue }
        { $_ -in "-t", "--tag" }      { $Tag       = [string]$args[$idx + 1]; $idx += 2; continue }
        { $_ -in "-p", "--posture" }  { $idx += 2; continue }
        default { break }
    }
}

$Command = if ($idx -lt $args.Count) { [string]$args[$idx] } else { "" }
$CmdArgs = if ($idx + 1 -lt $args.Count) { $args[($idx + 1)..($args.Count - 1)] } else { @() }

if ($Command -eq "keygen") {
    $priv = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
    $priv[0]  = $priv[0] -band 248
    $priv[31] = ($priv[31] -band 127) -bor 64
    $pub = [KopaczNet.Core]::X25519Base($priv)
    Write-Output "KOPACZ_PRIVKEY=$(ConvertTo-Hex $priv)"
    Write-Output "KOPACZ_PUBKEY=$(ConvertTo-Hex $pub)"
    exit 0
}

if ([string]::IsNullOrEmpty($Domain) -or [string]::IsNullOrEmpty($PubKeyHex) -or $PubKeyHex.Length -ne 64 -or [string]::IsNullOrEmpty($Command)) {
    [Console]::Error.WriteLine("Usage: kopacz.ps1 -d <domain> -k <64-hex-pubkey> [-r host[:port]] <fetch <url> | echo | keygen>")
    exit 1
}

$ServerPub = ConvertFrom-Hex $PubKeyHex
if ([string]::IsNullOrEmpty($Tag)) {
    $Tag = ([KopaczNet.Core]::Base32Encode([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(5))).Substring(0, 8)
}

$NsHost = "1.1.1.1"
$NsPort = 53
$HttpClient = $null
if ($Resolver -match "^https?://") {
    $HttpClient = [System.Net.Http.HttpClient]::new()
    $HttpClient.DefaultRequestHeaders.Add("Accept", "application/dns-json")
} else {
    $parts = $Resolver.Split(":")
    $NsHost = $parts[0]
    if ($parts.Length -gt 1) { $NsPort = [int]$parts[1] }
}

function Invoke-DnsTxtQuery([string]$fqdn) {
    if ($null -ne $HttpClient) {
        $uri = "$($Resolver)?name=$([Uri]::EscapeDataString($fqdn))&type=TXT"
        $json = $HttpClient.GetStringAsync($uri).GetAwaiter().GetResult()
        $doc = $json | ConvertFrom-Json
        if ($doc.Answer) {
            foreach ($ans in $doc.Answer) {
                if ($ans.type -eq 16 -and $ans.data) {
                    return ([string]$ans.data).Replace('"', '').Replace(' ', '')
                }
            }
        }
        return ""
    } else {
        return [KopaczNet.Core]::QueryDnsUdpTxt($NsHost, $NsPort, $fqdn, 2000)
    }
}

function New-QName([byte[]]$pkt) {
    $b32 = [KopaczNet.Core]::Base32Encode($pkt)
    $sb = [System.Text.StringBuilder]::new()
    for ($i = 0; $i -lt $b32.Length; $i += 63) {
        $len = [Math]::Min(63, $b32.Length - $i)
        [void]$sb.Append($b32.Substring($i, $len)).Append('.')
    }
    [void]$sb.Append($Tag).Append('.').Append($Domain)
    return $sb.ToString()
}

function New-Header([byte]$flags, [uint16]$streamId, [uint16]$seq, [byte]$fidx, [byte]$ftotal, [byte]$rsv) {
    $hdr = [byte[]]::new(8)
    $hdr[0] = $flags
    $hdr[1] = [byte](($streamId -shr 8) -band 0xFF)
    $hdr[2] = [byte]($streamId -band 0xFF)
    $hdr[3] = [byte](($seq -shr 8) -band 0xFF)
    $hdr[4] = [byte]($seq -band 0xFF)
    $hdr[5] = $fidx
    $hdr[6] = $ftotal
    $hdr[7] = $rsv
    return $hdr
}

# ── 1-RTT Noise_NK (es + ee) Handshake ───────────────────────────

$cEphPriv = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
$cEphPriv[0]  = $cEphPriv[0] -band 248
$cEphPriv[31] = ($cEphPriv[31] -band 127) -bor 64
$cEphPub = [KopaczNet.Core]::X25519Base($cEphPriv)

# es = X25519(c_eph_priv, s_static_pub)
$es = [KopaczNet.Core]::X25519($cEphPriv, $ServerPub)

$synSalt = [byte[]]::new(64)
[Buffer]::BlockCopy($cEphPub, 0, $synSalt, 0, 32)
[Buffer]::BlockCopy($ServerPub, 0, $synSalt, 32, 32)
$synInfo = [System.Text.Encoding]::ASCII.GetBytes("kopacz-v3-syn")
$synKey  = [KopaczNet.Core]::HkdfSha256($es, $synSalt, $synInfo, 32)

$tsSec = [uint64][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$tsBytes = [byte[]]::new(8)
for ($i = 0; $i -lt 8; $i++) {
    $tsBytes[$i] = [byte](($tsSec -shr (56 - 8 * $i)) -band 0xFF)
}
$synAad = [byte[]]::new(13 + 32)
[Buffer]::BlockCopy($synInfo, 0, $synAad, 0, 13)
[Buffer]::BlockCopy($cEphPub, 0, $synAad, 13, 32)
$zeroNonce = [byte[]]::new(12)
$sealedTs  = [KopaczNet.Core]::AeadSeal($synKey, $zeroNonce, $tsBytes, $synAad)

$synHdr = New-Header 0x80 0 0 0 1 60
$synPkt = [byte[]]::new(64)
[Buffer]::BlockCopy($synHdr, 0, $synPkt, 0, 8)
[Buffer]::BlockCopy($cEphPub, 0, $synPkt, 8, 32)
[Buffer]::BlockCopy($sealedTs, 0, $synPkt, 40, 24)

$txtResp = Invoke-DnsTxtQuery (New-QName $synPkt)
$rawSynAck = [KopaczNet.Core]::Base32Decode($txtResp)
if ($rawSynAck.Length -ne 56 -or (($rawSynAck[0] -band 0xA0) -ne 0xA0)) {
    [Console]::Error.WriteLine("Error: Handshake failed (invalid SYN-ACK)")
    exit 1
}

$sEphPub = [byte[]]::new(32)
$synAckTag = [byte[]]::new(16)
[Buffer]::BlockCopy($rawSynAck, 8, $sEphPub, 0, 32)
[Buffer]::BlockCopy($rawSynAck, 40, $synAckTag, 0, 16)

# ee = X25519(c_eph_priv, s_eph_pub)
$ee = [KopaczNet.Core]::X25519($cEphPriv, $sEphPub)
[Array]::Clear($cEphPriv, 0, 32) # PFS: zero ephemeral private key immediately

$ikm = [byte[]]::new(64)
[Buffer]::BlockCopy($es, 0, $ikm, 0, 32)
[Buffer]::BlockCopy($ee, 0, $ikm, 32, 32)
$sessSalt = [byte[]]::new(64)
[Buffer]::BlockCopy($cEphPub, 0, $sessSalt, 0, 32)
[Buffer]::BlockCopy($sEphPub, 0, $sessSalt, 32, 32)
$material = [KopaczNet.Core]::HkdfSha256($ikm, $sessSalt, [System.Text.Encoding]::ASCII.GetBytes("kopacz-v3"), 96)

$C2SKey    = $material[0..31]
$S2CKey    = $material[32..63]
$SynAckKey = $material[64..95]

$saPrefix = [System.Text.Encoding]::ASCII.GetBytes("kopacz-v3-synack:")
$saAad = [byte[]]::new(17 + 64)
[Buffer]::BlockCopy($saPrefix, 0, $saAad, 0, 17)
[Buffer]::BlockCopy($cEphPub, 0, $saAad, 17, 32)
[Buffer]::BlockCopy($sEphPub, 0, $saAad, 49, 32)

if ($null -eq ([KopaczNet.Core]::AeadOpen($SynAckKey, $zeroNonce, $synAckTag, $saAad))) {
    [Console]::Error.WriteLine("Error: SYN-ACK authentication failed")
    exit 1
}

# ── Session State ────────────────────────────────────────────────

$script:SendCtr   = [uint64]0
$script:Seq       = [uint16]0
$script:PollSeq   = [uint16]0
$script:HasAck    = $false
$script:AckNum    = [uint16]0
$script:ReasmSeq  = -1
$script:ReasmTot  = 0
$script:ReasmParts = @{}

function New-ControlSignature([byte[]]$hdr8) {
    $nonce = [byte[]]::new(12)
    $nonce[0] = 0x63; $nonce[1] = 0x74; $nonce[2] = 0x72; $nonce[3] = 0x6C # "ctrl"
    [Buffer]::BlockCopy($hdr8, 0, $nonce, 4, 8)
    $fullTag = [KopaczNet.Core]::AeadSeal($C2SKey, $nonce, [byte[]]::new(0), $hdr8)
    return $fullTag[0..7]
}

function Read-DownstreamPacket([byte[]]$raw) {
    if ($null -eq $raw -or $raw.Length -lt 8) { return $null }
    $flags = $raw[0]
    if (($flags -band 0x10) -eq 0) { return $null }
    $streamId = [uint16](($raw[1] -shl 8) -bor $raw[2])
    $seq      = [uint16](($raw[3] -shl 8) -bor $raw[4])
    $fidx     = [int]$raw[5]
    $ftotal   = [int]$raw[6]
    if ($ftotal -lt 1 -or $fidx -ge $ftotal) { return $null }

    if ($script:ReasmSeq -ne [int]$seq -or $script:ReasmTot -ne $ftotal) {
        $script:ReasmSeq   = [int]$seq
        $script:ReasmTot   = $ftotal
        $script:ReasmParts = @{}
    }
    $frag = [byte[]]::new($raw.Length - 8)
    [Buffer]::BlockCopy($raw, 8, $frag, 0, $frag.Length)
    $script:ReasmParts[$fidx] = $frag

    if ($script:ReasmParts.Count -lt $ftotal) { return $null }

    $ms = [System.IO.MemoryStream]::new()
    for ($i = 0; $i -lt $ftotal; $i++) {
        $part = $script:ReasmParts[$i]
        $ms.Write($part, 0, $part.Length)
    }
    $script:ReasmSeq = -1
    $enc = $ms.ToArray()
    if ($enc.Length -lt 28) { return $null }

    $nonce = $enc[0..11]
    $blob  = $enc[12..($enc.Length - 1)]
    $compBit = [byte]($flags -band 0x01)
    $aad = [byte[]]@(
        $compBit,
        [byte](($streamId -shr 8) -band 0xFF),
        [byte]($streamId -band 0xFF),
        [byte](($seq -shr 8) -band 0xFF),
        [byte]($seq -band 0xFF)
    )
    $pt = [KopaczNet.Core]::AeadOpen($S2CKey, $nonce, $blob, $aad)
    if ($null -eq $pt) { return $null }

    $script:HasAck = $true
    $script:AckNum = $seq
    if ($compBit -eq 1) {
        return [KopaczNet.Core]::Lz4DecompressFrame($pt)
    }
    return $pt
}

function Send-TunnelData([byte[]]$plaintext) {
    $seq = $script:Seq
    $script:Seq = [uint16](($script:Seq + 1) -band 0xFFFF)

    $nonce = [byte[]]::new(12)
    $ctr = $script:SendCtr
    $script:SendCtr++
    for ($i = 0; $i -lt 8; $i++) {
        $nonce[4 + $i] = [byte](($ctr -shr (56 - 8 * $i)) -band 0xFF)
    }
    $aad = [byte[]]@(0, 0, 0, [byte](($seq -shr 8) -band 0xFF), [byte]($seq -band 0xFF))
    $sealed = [KopaczNet.Core]::AeadSeal($C2SKey, $nonce, $plaintext, $aad)
    $enc = [byte[]]::new(12 + $sealed.Length)
    [Buffer]::BlockCopy($nonce, 0, $enc, 0, 12)
    [Buffer]::BlockCopy($sealed, 0, $enc, 12, $sealed.Length)

    $maxFrag = 96
    $totalFrags = [Math]::Max(1, [int][Math]::Ceiling($enc.Length / [double]$maxFrag))
    $downStream = [System.IO.MemoryStream]::new()

    for ($idx = 0; $idx -lt $totalFrags; $idx++) {
        $fl = [byte](0x10 -bor $(if ($totalFrags -gt 1) { 0x04 } else { 0 }) -bor $(if ($script:HasAck) { 0x20 } else { 0 }))
        $rsv = [byte]$(if ($script:HasAck) { $script:AckNum -band 0xFF } else { 0 })
        $hdr = New-Header $fl 0 $seq ([byte]$idx) ([byte]$totalFrags) $rsv
        $off = $idx * $maxFrag
        $clen = [Math]::Min($maxFrag, $enc.Length - $off)
        $pkt = [byte[]]::new(8 + $clen)
        [Buffer]::BlockCopy($hdr, 0, $pkt, 0, 8)
        [Buffer]::BlockCopy($enc, $off, $pkt, 8, $clen)

        $txt = Invoke-DnsTxtQuery (New-QName $pkt)
        if (-not [string]::IsNullOrEmpty($txt)) {
            $got = Read-DownstreamPacket ([KopaczNet.Core]::Base32Decode($txt))
            if ($null -ne $got -and $got.Length -gt 0) {
                $downStream.Write($got, 0, $got.Length)
            }
        }
    }
    return ,$downStream.ToArray()
}

function Invoke-TunnelPoll() {
    $pseq = $script:PollSeq
    $script:PollSeq = [uint16](($script:PollSeq + 1) -band 0xFFFF)
    if ($script:HasAck) {
        $hdr = New-Header 0x28 0 $script:AckNum ([byte](($pseq -shr 8) -band 0xFF)) 1 ([byte]($pseq -band 0xFF))
    } else {
        $hdr = New-Header 0x08 0 $pseq 0 1 0
    }
    $sig = New-ControlSignature $hdr
    $pkt = [byte[]]::new(16)
    [Buffer]::BlockCopy($hdr, 0, $pkt, 0, 8)
    [Buffer]::BlockCopy($sig, 0, $pkt, 8, 8)
    $txt = Invoke-DnsTxtQuery (New-QName $pkt)
    if ([string]::IsNullOrEmpty($txt)) { return $null }
    return ,(Read-DownstreamPacket ([KopaczNet.Core]::Base32Decode($txt)))
}

function Close-Tunnel() {
    $pseq = $script:PollSeq
    $hdr = New-Header 0x40 0 $pseq 0 1 0
    $sig = New-ControlSignature $hdr
    $pkt = [byte[]]::new(16)
    [Buffer]::BlockCopy($hdr, 0, $pkt, 0, 8)
    [Buffer]::BlockCopy($sig, 0, $pkt, 8, 8)
    [void](Invoke-DnsTxtQuery (New-QName $pkt))
}

# ── Execute Subcommand ───────────────────────────────────────────

$stdout = [Console]::OpenStandardOutput()

if ($Command -eq "echo") {
    $stdin = [Console]::OpenStandardInput()
    $msIn = [System.IO.MemoryStream]::new()
    $stdin.CopyTo($msIn)
    $allIn = $msIn.ToArray()

    for ($off = 0; $off -lt $allIn.Length; $off += 2048) {
        $slen = [Math]::Min(2048, $allIn.Length - $off)
        $slice = [byte[]]::new($slen)
        [Buffer]::BlockCopy($allIn, $off, $slice, 0, $slen)
        $down = Send-TunnelData $slice
        $gotBytes = 0
        if ($null -ne $down -and $down.Length -gt 0) {
            $stdout.Write($down, 0, $down.Length)
            $gotBytes += $down.Length
        }
        while ($gotBytes -lt $slen) {
            $polled = Invoke-TunnelPoll
            if ($null -ne $polled -and $polled.Length -gt 0) {
                $stdout.Write($polled, 0, $polled.Length)
                $gotBytes += $polled.Length
            }
        }
    }
    $stdout.Flush()
} elseif ($Command -eq "fetch") {
    if ($CmdArgs.Count -lt 1) {
        [Console]::Error.WriteLine("Error: fetch requires a URL")
        exit 1
    }
    $urlBytes = [System.Text.Encoding]::UTF8.GetBytes([string]$CmdArgs[0])
    $req = [byte[]]::new(2 + $urlBytes.Length)
    $req[0] = 0x04 # APP_WEB
    $req[1] = 0x03 # FETCH_READER
    [Buffer]::BlockCopy($urlBytes, 0, $req, 2, $urlBytes.Length)

    $down = Send-TunnelData $req
    $done = $false
    $empty = 0
    while (-not $done -and $empty -lt 40) {
        if ($null -ne $down -and $down.Length -gt 0) {
            $empty = 0
            if ($down[0] -eq 0x02 -and $down.Length -gt 1) {
                $stdout.Write($down, 1, $down.Length - 1)
            } elseif ($down[0] -eq 0x03) {
                $done = $true
            }
        } else {
            $empty++
            Start-Sleep -Milliseconds 30
        }
        if (-not $done) {
            $down = Invoke-TunnelPoll
        }
    }
    $stdout.Flush()
}

Close-Tunnel
exit 0
