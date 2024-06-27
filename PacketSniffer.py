import socket
import struct
import textwrap


def run():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw, address = connection.recvfrom(65536)
        destination, source, ethProto, data = unpackToMAC(raw)
        print('\nEthernet frame: ')
        print("" + destination + "|" + source + "|" + ethProto)

        if ethProto == 8:
            version, headerLen, ttl, protocol, source, target, data = unpackIPV4(data)
            print('\t - ' + "IPv4 packet: ")
            print('\t\t' + f"Version: {version}" + f"Header length: {headerLen}" + f"Time to live: {ttl}")
            print('\t\t' + f"Protocol: {protocol}" + f"Source: {source}" + f"Target: {target}")

            if protocol == 1:
                icmpType, code, checksum, packetData = unpackICMP(data)
                print('\t - ' + "ICMP packet: ")
                print('\t\t' + f"Type: {icmpType}" + f"Check sum: {checksum}" + f"Code: {code}")
                print('\t\t' + f"Data: {data}")
            elif protocol == 6:
                source, destination, sequence, acknowledgment, flags, packetData = unpackTCP()
                print('\t - ' + "TCP packet: ")
                print('\t \t - ' + f"Source: {source}" + f"Destination: {destination}")
                print('\t \t -' + f"Sequence: {sequence}" + "Acknowledgment: {acknowledgment}")
                print('\t \t -' + "Flags: ")
                for i in range(len(flags)):
                    print('\t \t \t -' + flags[i])
                print('\t \t -' + f"Data: {data}")
                

            elif protocol == 12:
                source, destination, length, packetData = unpackUDP(data)
                print('\t \t - ' + f"Source: {source}" + f"Destination: {destination}")
                print('\t \t - ' + f"Length: {length}")
                print('\t \t -' + f"Data: {data}")
            else:
                return



def get_mac(data):
    return ':'.join(map('{:02x}'.format, data)).upper()


def unpackToMAC(data):
    destination, source, frametype = struct.unpack('! 6s 6s H', data[:14])
    return get_mac(destination), get_mac(source), socket.htons(frametype), data[14:]


# return: version, header length, time to live, protocol, source ip, target ip, and packet data
def unpackIPV4(data):
    vIHL = data[0]
    version = vIHL >> 4
    headerLen = (vIHL & 15) * 4  # tells you where the header ends and the data starts
    ttl, protocol, source, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, headerLen, ttl, protocol, getIP(source), getIP(target), data[headerLen:]


def getIP(data):
    return '.'.join(map(str, data))

def unpackICMP(data):
    icmpType, code, checksum, packetData = struct.unpack('! B B H', data[:4]), data[4:]
    return icmpType, code, checksum, packetData

def unpackTCP(data):
    source, destination, sequence, acknowledgement, offResFlags = struct.unpack('! H H L L H', data[:14])
    offset = (offResFlags >> 12) * 4
    flags = []
    for i in range(5):
        flags[i] = (offResFlags & (32 / (2**i))) >> (5 - i)
    return source, destination, sequence, acknowledgment, flags, data[offset:]

def unpackUDP(data):
    source, destination, length, packetData = struct.unpack('! H H 2x H', data[:8]), data[8:]
    return source, destination, length, packetData
