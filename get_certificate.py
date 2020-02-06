# requires a recent enough python with idna support in socket
# pyopenssl, cryptography and idna

from OpenSSL import SSL
from cryptography import x509
from cryptography.x509.oid import NameOID
import idna
import hashlib


from socket import socket


def verify_cert(cert, hostname):
    # verify notAfter/notBefore, CA trusted, servername/sni/hostname
    cert.has_expired()
    # service_identity.pyopenssl.verify_hostname(client_ssl, hostname)
    # issuer

def get_certificate(hostname, port):
    
    try:
        hostname_idna = idna.encode(hostname)
        sock = socket()
        sock.connect((hostname, port))
        peername = sock.getpeername()
        ctx = SSL.Context(SSL.SSLv23_METHOD) # most compatible
        ctx.check_hostname = False
        ctx.verify_mode = SSL.VERIFY_NONE

        sock_ssl = SSL.Connection(ctx, sock)
        sock_ssl.set_connect_state()
        sock_ssl.set_tlsext_host_name(hostname_idna)
        sock_ssl.do_handshake()
        cert = sock_ssl.get_peer_certificate()
        crypto_cert = cert.to_cryptography()
        sock_ssl.close()
        sock.close()
    except Exception as e:
        print('Could Not Connect due to: ' + str(e))
        return None

    return crypto_cert

def get_alt_names(cert):
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return None

def get_common_name(cert):
    try:
        names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None

def get_issuer(cert):
    try:
        names = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None

def get_serial_number(cert):
    try:
        serial_number = hex(cert.serial_number)
        return serial_number
    except Exception as e:
        print('Could not generate serial number due to: ' + str(e))
        return None


def print_basic_info(cert):
    if (cert != None):
        s = '''»\tcommonName: {commonname}
        \tSAN: {SAN}
        \tissuer: {issuer}
        \tnotBefore: {notbefore}
        \tnotAfter:  {notafter}
        \tserialNumber:  {serialNumber}
        '''.format(                
                commonname=get_common_name(cert),
                SAN=get_alt_names(cert),
                issuer=get_issuer(cert),
                notbefore=cert.not_valid_before,
                notafter=cert.not_valid_after,
                serialNumber=get_serial_number(cert)
        )
        print(s)

def check_it_out(hostname, port):
    cert = get_certificate(hostname, port)
    print_basic_info(cert)


domain_list = [
{'domain': 'www.usda.gov', 'port': 443},
{'domain': 'damjan.softver.org.mk', 'port': 443},
{'domain': 'wrong.host.badssl.com', 'port': 443},
{'domain': 'ca.ocsr.nl', 'port': 443},
{'domain': 'faß.de', 'port': 443},
{'domain': 'самодеј.мкд', 'port': 443},
{'domain': 'google.com', 'port': 443},
{'domain': 'a', 'port': 443}
]

for item in domain_list:
    cert = get_certificate(item['domain'], item['port'])
    print_basic_info(cert)