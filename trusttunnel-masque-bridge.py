#!/usr/bin/env python3
"""Loopback-only compatibility shim for usque 4.2.1 UDP ASSOCIATE.

usque keys UDP associations by address:port but does not replace an unspecified
client address with its TCP peer. TrustTunnel correctly sends 0.0.0.0:port.
Only that address is normalized; UDP packets go directly to usque's relay.
"""
import asyncio
import contextlib
import socket

BIND = ('127.0.0.1', 40002)
UPSTREAM = ('127.0.0.1', 40003)
MAX_CONNECTIONS = 256
connections = 0


async def normalize_request(reader):
    header = await reader.readexactly(4)
    if header[0] != 5 or header[2] != 0 or header[1] not in (1, 3):
        raise ValueError('Unsupported SOCKS request')
    atyp = header[3]
    if atyp in (1, 4):
        address = await reader.readexactly(4 if atyp == 1 else 16)
    elif atyp == 3:
        size = await reader.readexactly(1)
        address = size + await reader.readexactly(size[0])
    else:
        raise ValueError('Unsupported SOCKS address')
    port = await reader.readexactly(2)
    if header[1] == 3:
        if atyp != 1 or address not in (b'\x00\x00\x00\x00', socket.inet_aton('127.0.0.1')) or port == b'\x00\x00':
            raise ValueError('UDP ASSOCIATE requires a reserved local IPv4 port')
        address = socket.inet_aton('127.0.0.1')
    return header + address + port


async def pipe(reader, writer):
    while True:
        data = await reader.read(65536)
        if not data:
            with contextlib.suppress(OSError):
                writer.write_eof()
            return
        writer.write(data)
        await writer.drain()


async def handle(reader, writer):
    global connections
    if connections >= MAX_CONNECTIONS:
        writer.close()
        return
    connections += 1
    upstream_writer = None
    tasks = []
    try:
        async with asyncio.timeout(10):
            greeting = await reader.readexactly(2)
            if greeting[0] != 5 or not greeting[1]:
                return
            methods = await reader.readexactly(greeting[1])
            if 0 not in methods:
                writer.write(b'\x05\xff'); await writer.drain(); return
            upstream_reader, upstream_writer = await asyncio.open_connection(*UPSTREAM)
            upstream_writer.write(b'\x05\x01\x00'); await upstream_writer.drain()
            if await upstream_reader.readexactly(2) != b'\x05\x00':
                return
            writer.write(b'\x05\x00'); await writer.drain()
            request = await normalize_request(reader)
            upstream_writer.write(request); await upstream_writer.drain()
        tasks = [asyncio.create_task(pipe(reader, upstream_writer)), asyncio.create_task(pipe(upstream_reader, writer))]
        await asyncio.gather(*tasks)
    except (OSError, ValueError, asyncio.IncompleteReadError, TimeoutError):
        pass
    finally:
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        writer.close()
        if upstream_writer:
            upstream_writer.close()
        connections -= 1


async def main():
    server = await asyncio.start_server(handle, *BIND)
    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    asyncio.run(main())
