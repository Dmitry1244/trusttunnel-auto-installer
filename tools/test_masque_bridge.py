"""SOCKS compatibility checks using loopback fake upstreams only."""
import asyncio
import importlib.util
import unittest
import os
from pathlib import Path

spec = importlib.util.spec_from_file_location('bridge', os.environ.get('TT_BRIDGE_SOURCE') or Path(__file__).parents[1] / 'trusttunnel-masque-bridge.py')
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


class BridgeTests(unittest.IsolatedAsyncioTestCase):
    async def normalize(self, data):
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()
        return await bridge.normalize_request(reader)

    async def test_udp_unspecified_address_matches_real_client(self):
        data = b'\x05\x03\x00\x01\x00\x00\x00\x00\x9c\x40'
        self.assertEqual(await self.normalize(data), data[:4] + b'\x7f\x00\x00\x01' + data[-2:])

    async def test_connect_domain_is_not_rewritten(self):
        data = b'\x05\x01\x00\x03\x0bexample.org\x01\xbb'
        self.assertEqual(await self.normalize(data), data)

    async def test_invalid_and_unreserved_udp_endpoints_are_rejected(self):
        for data in (b'\x04\x03\x00\x01', b'\x05\x02\x00\x01',
                     b'\x05\x03\x00\x01\x7f\x00\x00\x01\x00\x00',
                     b'\x05\x03\x00\x01\x08\x08\x08\x08\x9c\x40'):
            with self.assertRaises(ValueError):
                await self.normalize(data)

    async def test_full_connect_preserves_binary_stream(self):
        observed = []
        async def upstream(reader, writer):
            self.assertEqual(await reader.readexactly(3), b'\x05\x01\x00')
            writer.write(b'\x05\x00'); await writer.drain()
            request = await reader.readexactly(10)
            observed.append(request)
            writer.write(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x01\xbb'); await writer.drain()
            await bridge.pipe(reader, writer)
            writer.close()
        server = await asyncio.start_server(upstream, '127.0.0.1', 0)
        previous = bridge.UPSTREAM
        bridge.UPSTREAM = ('127.0.0.1', server.sockets[0].getsockname()[1])
        proxy = await asyncio.start_server(bridge.handle, '127.0.0.1', 0)
        try:
            async with asyncio.timeout(5):
                reader, writer = await asyncio.open_connection('127.0.0.1', proxy.sockets[0].getsockname()[1])
                writer.write(b'\x05\x02\x00\x02'); await writer.drain()
                self.assertEqual(await reader.readexactly(2), b'\x05\x00')
                request = b'\x05\x01\x00\x01\x01\x01\x01\x01\x01\xbb'
                writer.write(request); await writer.drain()
                await reader.readexactly(10)
                payload = bytes(range(256)) * 512
                writer.write(payload); await writer.drain()
                self.assertEqual(await reader.readexactly(len(payload)), payload)
                writer.close(); await writer.wait_closed()
                self.assertEqual(observed, [request])
        finally:
            bridge.UPSTREAM = previous
            proxy.close(); server.close()
            await proxy.wait_closed(); await server.wait_closed()


if __name__ == '__main__':
    unittest.main()
