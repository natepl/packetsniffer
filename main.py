import socket
import struct
import textwrap


def main():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw, address = connection.recvfrom(65536)
        destination, source, ethType, data = unpackToMAC(raw)
        print('\nEthernet frame: ')
        print("" + destination + "|" + source + "|" + ethType)


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


if __name__ == "__main__":
    main()
