#!/usr/bin/env python3
"""Test backends for Kuipernet Upload.

Two raw TCP servers that record exactly what reaches the backend side:

  * an HTTP/1.x origin (target of proxy_pass)
  * a FastCGI responder (target of fastcgi_pass, stands in for PHP-FPM)

Every accepted connection and every request is written as one JSON line:
request count, body bytes actually received and their SHA-256. A request whose
body stops early is still recorded (complete=false) with the bytes received,
so "0 requests / 0 bytes" in the log means nothing reached the backend.
"""
import asyncio
import hashlib
import json
import struct
import sys
import time

LOG = None


def record(**kw):
    kw["ts"] = round(time.time(), 3)
    LOG.write(json.dumps(kw, sort_keys=True) + "\n")
    LOG.flush()


# ---------------------------------------------------------------- HTTP origin

async def http_conn(reader, writer):
    conn_bytes = 0
    requests = 0
    try:
        while True:
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                head += chunk
                conn_bytes += len(chunk)
            if b"\r\n\r\n" not in head:
                break

            head, rest = head.split(b"\r\n\r\n", 1)
            lines = head.decode("latin-1").split("\r\n")
            method, uri, _ = lines[0].split(" ", 2)
            hdrs = {}
            for ln in lines[1:]:
                k, _, v = ln.partition(":")
                hdrs[k.strip().lower()] = v.strip()

            requests += 1
            sha = hashlib.sha256()
            got = 0
            complete = True
            chunked = "chunked" in hdrs.get("transfer-encoding", "").lower()

            if chunked:
                buf = rest
                while True:
                    while b"\r\n" not in buf:
                        d = await reader.read(65536)
                        if not d:
                            complete = False
                            break
                        buf += d
                        conn_bytes += len(d)
                    if not complete:
                        break
                    line, buf = buf.split(b"\r\n", 1)
                    size = int(line.split(b";")[0], 16)
                    while len(buf) < size + 2:
                        d = await reader.read(65536)
                        if not d:
                            complete = False
                            break
                        buf += d
                        conn_bytes += len(d)
                    if not complete:
                        sha.update(buf[:size])
                        got += min(len(buf), size)
                        break
                    sha.update(buf[:size])
                    got += size
                    buf = buf[size + 2:]
                    if size == 0:
                        break
            else:
                need = int(hdrs.get("content-length", "0"))
                data = rest[:need]
                sha.update(data)
                got = len(data)
                while got < need:
                    d = await reader.read(min(1 << 20, need - got))
                    if not d:
                        complete = False
                        break
                    conn_bytes += len(d)
                    sha.update(d)
                    got += len(d)

            record(backend="http", event="request", method=method, uri=uri,
                   test_id=hdrs.get("x-test-id", ""), body_bytes=got,
                   sha256=sha.hexdigest(), complete=complete,
                   content_length=hdrs.get("content-length"),
                   transfer_encoding=hdrs.get("transfer-encoding"))

            if not complete:
                break

            body = json.dumps({"backend": "http", "body_bytes": got,
                               "sha256": sha.hexdigest()}).encode()
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json"
                         b"\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
                         % len(body) + body)
            await writer.drain()
            break
    except Exception as e:  # noqa: BLE001 - test tool: record and go on
        record(backend="http", event="error", error=repr(e))
    finally:
        if requests == 0:
            record(backend="http", event="connection_without_request",
                   bytes=conn_bytes)
        writer.close()


# ----------------------------------------------------------- FastCGI responder

FCGI_BEGIN_REQUEST, FCGI_ABORT_REQUEST, FCGI_END_REQUEST = 1, 2, 3
FCGI_PARAMS, FCGI_STDIN, FCGI_STDOUT = 4, 5, 6


def fcgi_record(rtype, req_id, data):
    out = b""
    while True:
        piece, data = data[:65535], data[65535:]
        out += struct.pack("!BBHHBB", 1, rtype, req_id, len(piece), 0, 0)
        out += piece
        if not data:
            return out


def fcgi_params(buf):
    params = {}
    i = 0
    while i < len(buf):
        lens = []
        for _ in range(2):
            n = buf[i]
            if n >> 7:
                n = struct.unpack("!I", buf[i:i + 4])[0] & 0x7FFFFFFF
                i += 4
            else:
                i += 1
            lens.append(n)
        k = buf[i:i + lens[0]]
        i += lens[0]
        v = buf[i:i + lens[1]]
        i += lens[1]
        params[k.decode("latin-1")] = v.decode("latin-1")
    return params


async def fcgi_conn(reader, writer):
    began = False
    params_raw = b""
    params = {}
    sha = hashlib.sha256()
    got = 0
    stdin_records = 0
    complete = False
    req_id = 1
    conn_bytes = 0
    try:
        while True:
            try:
                hdr = await reader.readexactly(8)
            except asyncio.IncompleteReadError as e:
                conn_bytes += len(e.partial)
                break
            conn_bytes += 8
            _, rtype, req_id, clen, plen, _ = struct.unpack("!BBHHBB", hdr)
            try:
                data = await reader.readexactly(clen + plen)
            except asyncio.IncompleteReadError as e:
                conn_bytes += len(e.partial)
                if rtype == FCGI_STDIN:
                    part = e.partial[:clen]
                    sha.update(part)
                    got += len(part)
                break
            conn_bytes += clen + plen
            data = data[:clen]

            if rtype == FCGI_BEGIN_REQUEST:
                began = True
            elif rtype == FCGI_PARAMS:
                if clen:
                    params_raw += data
                else:
                    params = fcgi_params(params_raw)
            elif rtype == FCGI_STDIN:
                stdin_records += 1
                if clen == 0:
                    complete = True
                    break
                sha.update(data)
                got += clen
            elif rtype == FCGI_ABORT_REQUEST:
                break

        if began:
            if not params and params_raw:
                params = fcgi_params(params_raw)
            record(backend="fcgi", event="request",
                   method=params.get("REQUEST_METHOD", ""),
                   uri=params.get("REQUEST_URI", ""),
                   test_id=params.get("HTTP_X_TEST_ID", ""), body_bytes=got,
                   sha256=sha.hexdigest(), complete=complete,
                   content_length=params.get("CONTENT_LENGTH"),
                   stdin_records=stdin_records)
        else:
            record(backend="fcgi", event="connection_without_request",
                   bytes=conn_bytes)

        if complete:
            body = json.dumps({"backend": "fcgi", "body_bytes": got,
                               "sha256": sha.hexdigest()}).encode()
            out = (b"Status: 200 OK\r\nContent-Type: application/json\r\n\r\n"
                   + body)
            writer.write(fcgi_record(FCGI_STDOUT, req_id, out)
                         + fcgi_record(FCGI_STDOUT, req_id, b"")
                         + fcgi_record(FCGI_END_REQUEST, req_id,
                                       struct.pack("!IB3x", 0, 0)))
            await writer.drain()
    except Exception as e:  # noqa: BLE001
        record(backend="fcgi", event="error", error=repr(e))
    finally:
        writer.close()


async def main():
    global LOG
    http_port, fcgi_port, log_path = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
    LOG = open(log_path, "a")
    s1 = await asyncio.start_server(http_conn, "127.0.0.1", http_port,
                                    limit=1 << 20)
    s2 = await asyncio.start_server(fcgi_conn, "127.0.0.1", fcgi_port,
                                    limit=1 << 20)
    record(event="backends_started", http_port=http_port, fcgi_port=fcgi_port)
    async with s1, s2:
        await asyncio.gather(s1.serve_forever(), s2.serve_forever())


if __name__ == "__main__":
    asyncio.run(main())
