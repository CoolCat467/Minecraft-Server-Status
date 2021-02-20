#!/usr/bin/env python3
# Minecraft Server Info. Can figure out how many players are on a minecraft server.
# -*- coding: utf-8 -*-

# Programmed by CoolCat467
# Large segmants of code stolen from Dinnerbone's MCStatus package.

__title__ = 'Minecraft Server Info'
__author__ = 'CoolCat467'
__version__ = '0.0.0'
__ver_major__ = 0
__ver_minor__ = 0
__ver_patch__ = 0

serverIp = ''
serverPort = 25565

BUFSIZE = 2048

server = 'mcapi.us'

import os

from http import client

import socket
import struct

import random
import datetime
import json

from urllib.parse import urlparse
import dns.resolver

def parse_address(address):
    """Return a tuple of hostname, port from address."""
    tmp = urlparse('//'+address)
    if not tmp.hostname:
        raise ValueError(f"Invalid address '{address}'")
    return (tmp.hostname, tmp.port)

##mcapi.us/server/status?ip=&port=25565
def requestData(conn, ip, port):
    # Request command to server
    conn.request('GET', f'/server/status?ip={ip}&port={port}')
    # Get response from server
    resp = conn.getresponse()
    
    print(f'Response Status: {resp.status}\nResponse Reason: {resp.reason}\n')
    data = resp.read()
    
    if resp.status == 200 and resp.reason == 'OK':
        jsdata = json.loads(data)
        process_json(jsdata)
    else:
        print('Request failed.')

class Connection:
    """Base class for reading and writing data."""
    def __init__(self):
        """Keep byte arrays of sent and recieved."""
        self.sent = bytearray()
        self.received = bytearray()
    
    def read(self, length):
        """Return up to length data from received and delete it from they received array."""
        result = self.received[:length]
        self.received = self.received[length:]
        return result
    
    def write(self, data):
        """If data is a connection, flush it and add it to self. Otherwise, add byte array of data to self."""
        if isinstance(data, Connection):
            data = bytearray(data.flush())
        if isinstance(data, str):
            data = bytearray(data)
        self.sent.extend(data)
    
    def receive(self, data):
        """Add data to received byte array."""
        if not isinstance(data, bytearray):
            data = bytearray(data)
        self.received.extend(data)
    
    def remaining(self):
        """Return the length of received."""
        return len(self.received)
    
    def flush(self):
        """Return all of sent while deleting it from self."""
        result = self.sent
        self.sent = ""
        return result
    
    def _unpack(self, format, data):
        """Unpack <data> in format of big-endian <format>."""
        return struct.unpack(">" + format, bytes(data))[0]
    
    def _pack(self, format, data):
        """Pack <data> in format of big-endian <format>."""
        return struct.pack(">" + format, data)
    
    def read_varint(self):
        """Read an intiger."""
        result = 0
        for i in range(5):
            part = ord(self.read(1))
            result |= (part & 0x7F) << 7 * i
            if not part & 0x80:
                return result
        raise IOError("Server sent a varint that was too big!")
    
    def write_varint(self, value):
        """Write an intiger."""
        remaining = value
        for i in range(5):
            if remaining & ~0x7F == 0:
                self.write(struct.pack("!B", remaining))
                return
            self.write(struct.pack("!B", remaining & 0x7F | 0x80))
            remaining >>= 7
        raise ValueError("The value %d is too big to send in a varint" % value)
    
    def read_utf(self):
        """Return a read utf-8 string."""
        length = self.read_varint()
        return self.read(length).decode('utf8')
    
    def write_utf(self, value):
        """Write a utf-8 string."""
        self.write_varint(len(value))
        self.write(bytearray(value, 'utf8'))
    
    def read_ascii(self):
        """Return the ISO-8849-1 decode of read data."""
        result = bytearray()
        while len(result) == 0 or result[-1] != 0:
            result.extend(self.read(1))
        return result[:-1].decode("ISO-8859-1")
    
    def write_ascii(self, value):
        """Write the ISO-8849-1 encode of data."""
        self.write(bytearray(value, 'ISO-8859-1'))
        self.write(bytearray.fromhex("00"))
    
    def read_short(self):
        """Read a short."""
        return self._unpack("h", self.read(2))
    
    def write_short(self, value):
        """Write a short."""
        self.write(self._pack("h", value))
    
    def read_ushort(self):
        """Read an unsigned short."""
        return self._unpack("H", self.read(2))
    
    def write_ushort(self, value):
        """Write an unsigned short."""
        self.write(self._pack("H", value))
    
    def read_int(self):
        """Read an intiger."""
        return self._unpack("i", self.read(4))
    
    def write_int(self, value):
        """Write an intiger."""
        self.write(self._pack("i", value))
    
    def read_uint(self):
        """Read an unsigned intiger."""
        return self._unpack("I", self.read(4))
    
    def write_uint(self, value):
        """Write an unsigned intiger."""
        self.write(self._pack("I", value))
    
    def read_long(self):
        """Read a long."""
        return self._unpack("q", self.read(8))
    
    def write_long(self, value):
        """Write a long."""
        self.write(self._pack("q", value))
    
    def read_ulong(self):
        """Read an unsigned long."""
        return self._unpack("Q", self.read(8))
    
    def write_ulong(self, value):
        """Write an unsigned long."""
        self.write(self._pack("Q", value))
    
    def read_buffer(self):
        """Read a buffer."""
        length = self.read_varint()
        result = Connection()
        result.receive(self.read(length))
        return result
    
    def write_buffer(self, buffer):
        """Write a buffer."""
        data = buffer.flush()
        self.write_varint(len(data))
        self.write(data)
    pass

class TCPSocketConnection(Connection):
    """TCP Socket Base Class."""
    def __init__(self, addr, timeout=3):
        super().__init__()
        self.socket = socket.create_connection(addr, timeout=timeout)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    
    def flush(self):
        raise TypeError("TCPSocketConnection does not support flush()")
    
    def receive(self, data):
        raise TypeError("TCPSocketConnection does not support receive()")
    
    def remaining(self):
        raise TypeError("TCPSocketConnection does not support remaining()")
    
    def read(self, length):
        """Read up to length from socket."""
        result = bytearray()
        while len(result) < length:
            new = self.socket.recv(length - len(result))
            if len(new) == 0:
                raise IOError("Server did not respond with any information!")
            result.extend(new)
        return result
    
    def write(self, data):
        """Send data with socket."""
        self.socket.send(data)
    
    def __del__(self):
        """Close socket."""
        try:
            self.socket.close()
        except:
            pass
    pass

class MinecraftServer():
    def __init__(self, host, port=25565):
        """Remember wat host and port we were given."""
        self.host = host
        self.port = port
    
    @staticmethod
    def lookup(address):
        """Look up address, and return MinecraftServer instance after sucessfull lookup."""
        host, port = parse_address(address)
        if port is None:
            port = 25565
            try:
                answers = dns.resolver.query("_minecraft._tcp." + host, "SRV")
                if len(answers):
                    answer = answers[0]
                    host = str(answer.target).rstrip(".")
                    port = int(answer.port)
            except Exception:
                pass
        
        return MinecraftServer(host, port)
    
    def ping(self, tries=3, **kwargs):
        """Return the latancy of the connection to the server in milisecconds."""
        connection = TCPSocketConnection((self.host, self.port))
        exception = None
        for attempt in range(tries):
            try:
                pinger = ServerPinger(connection, host=self.host, port=self.port, **kwargs)
                pinger.handshake()
                return pinger.test_ping()
            except Exception as e:
                exception = e
        raise exception
    
    def status(self, tries=3, **kwargs):
        """Return a tuple of json, latancy (in milisecconds) from the server."""
        connection = TCPSocketConnection((self.host, self.port))
        exception = None
        for attempt in range(tries):
            try:
                pinger = ServerPinger(connection, host=self.host, port=self.port, **kwargs)
                pinger.handshake()
                result = pinger.read_status()
                latency = pinger.test_ping()
                return result, latency
            except Exception as e:
                exception = e
        raise exception
    pass

class ServerPinger:
    def __init__(self, connection, host='', port=25565, version=47, ping_token=None):
        """Initialize server pinger."""
        if ping_token is None:
            ping_token = random.randint(0, (1 << 63) - 1)
        self.version = version
        self.connection = connection
        self.host = host
        self.port = port
        self.ping_token = ping_token
    
    def handshake(self):
        """Preform handshake with the server, and tell it we intend to query it."""
        packet = Connection()
        packet.write_varint(0)
        packet.write_varint(self.version)
        packet.write_utf(self.host)
        packet.write_ushort(self.port)
        packet.write_varint(1)  # Intention to query status
        
        self.connection.write_buffer(packet)
    
    def read_status(self):
        """Request the server's status and return the json from the response."""
        request = Connection()
        request.write_varint(0)  # Request status
        self.connection.write_buffer(request)

        response = self.connection.read_buffer()
        if response.read_varint() != 0:
            raise IOError("Received invalid status response packet.")
        try:
            raw = json.loads(response.read_utf())
        except ValueError:
            raise IOError("Received invalid JSON")
        try:
            return raw
        except ValueError as e:
            raise IOError("Received invalid status response: %s" % e)
    
    def test_ping(self):
        """Return the latancy in milisecconds of the connection to the server."""
        request = Connection()
        request.write_varint(1)  # Test ping
        request.write_long(self.ping_token)
        sent = datetime.datetime.now()
        self.connection.write_buffer(request)
        
        response = self.connection.read_buffer()
        received = datetime.datetime.now()
        if response.read_varint() != 1:
            raise IOError("Received invalid ping response packet.")
        received_token = response.read_long()
        if received_token != self.ping_token:
            raise IOError("Received mangled ping response packet (expected token %d, received %d)" % (
                self.ping_token, received_token))
        
        delta = (received - sent)
        # We have no trivial way of getting a time delta :(
        return (delta.days * 24 * 60 * 60 + delta.seconds) * 1000 + delta.microseconds / 1000.0
    pass

class MinecraftServerStatus(TCPSocketConnection):
    # Get the server status
    def __init__(self, host='', port=25565, version=47, ping_token=None, timeout=3):
        """Initialize minecraft server status."""
        if ping_token is None:
            ping_token = random.randint(0, (1 << 63) - 1)
        self.version = version
        self.socket = socket.socket()
        self.host = host
        self.port = port
        self.timeout = timeout
        self.ping_token = ping_token
    
    def status(self, tries=3):
        """Return a tuple of json, latancy (in milisecconds) from the server."""
        self.close_socket()
        super().__init__((self.host, self.port), self.timeout)
        
        exception = None
        for attempt in range(tries):
            try:
                self.handshake()
                status = self.read_status()
                latancy = self.test_ping()
                return status, latancy
            except Exception as e:
                exception = e
        else:
            raise exception
    
    def ping(self, tries=3):
        """Ping the server, returning the latancy between sending and receiving data."""
        self.close_socket()
        super().__init__((self.host, self.port), self.timeout)
        
        exception = None
        for attempt in range(tries):
            try:
                self.handshake()
                return self.test_ping()
            except Exception as e:
                exception = e
        else:
            raise exception
    
    def handshake(self):
        """Preform the handshake with the server."""
        packet = Connection()
        packet.write_varint(0)
        packet.write_varint(self.version)
        packet.write_utf(self.host)
        packet.write_ushort(self.port)
        packet.write_varint(1)  # Intention to query status
        
        self.write_buffer(packet)
    
    def read_status(self):
        """Request status of the server in json."""
        request = Connection()
        request.write_varint(0)  # Request status
        self.write_buffer(request)
        
        response = self.read_buffer()
        if response.read_varint() != 0:
            raise IOError("Received invalid status response packet.")
        try:
            raw = json.loads(response.read_utf())
        except ValueError:
            raise IOError("Received invalid JSON")
        try:
            return raw
        except ValueError as e:
            raise IOError("Received invalid status response: %s" % e)
    
    def test_ping(self):
        """Return the latancy of the connection to the server in milisecconds."""
        request = Connection()
        request.write_varint(1)  # Test ping
        request.write_long(self.ping_token)
        sent = datetime.datetime.now()
        self.write_buffer(request)
        
        response = self.read_buffer()
        received = datetime.datetime.now()
        if response.read_varint() != 1:
            raise IOError("Received invalid ping response packet.")
        received_token = response.read_long()
        if received_token != self.ping_token:
            raise IOError("Received mangled ping response packet (expected token %d, received %d)" % (
                self.ping_token, received_token))
        
        delta = (received - sent)
        # We have no trivial way of getting a time delta :(
        return (delta.days * 24 * 60 * 60 + delta.seconds) * 1000 + delta.microseconds / 1000.0
    
    def close_socket(self):
        try:
            self.socket.close()
        except:
            pass
    
    def __del__(self):
        self.close_socket()
    pass

def requestDataSocket(ip, port):
    """Request data from the server itsself."""
    mc = MinecraftServer(ip, port)
    json, latancy = mc.status()
    process_json(json)

def process_json(jsdata):
##        print(jsdata)
    ##    if jsdata['status'] == 'success':
    ##        if jsdata['online']:
    if 'players' in jsdata:
        players = jsdata['players']
        if 'now' in players:
            onlinecount = players['now']
        elif 'online' in players:
            onlinecount = players['online']
        else:
            print('No "now" or "online" in players.')
            return
        if onlinecount >= 1:
            playersample = players['sample']
            names = []
            for player in playersample:
                names.append(player['name'])
            print(f'Following people are online: {", ".join(names)}')
            return
        print('No one is online.')
        return
    print('No players.')
    return

def run():
##    try:
##        conn = client.HTTPConnection(server)
##    except BaseException as err:
##        print(f'An Error occorred trying to connect to {server}.')
##    else:
##        requestData(conn, serverIp, serverPort)
##    finally:
##        conn.close()
    requestDataSocket(serverIp, serverPort)

if __name__ == '__main__':
    print('%s v%s\nProgrammed by %s.' % (__title__, __version__, __author__))
    run()
