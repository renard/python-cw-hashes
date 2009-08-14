#!/usr/bin/python
# encoding: utf-8

__author__ = 'Sébastien Gross'
__copyright__ = 'Copyright (c) 2009 Sébastien Gross <seb•ɑƬ•chezwam•ɖɵʈ•org>'


import random
import string
import crypt
from base64 import urlsafe_b64encode as encode64
from base64 import urlsafe_b64decode as decode64

import hashlib

class CWHashes:
    def __init__(self, password, salt=None):
        self.password = password
        self.salt = salt
        self.out = {}
        return

    """Run all shemes"""
    def run_all(self):
        self.apr1()
        self.base64()
        self.clear()
        self.crypt()
        self.crypted_md5()
        self.md5()
        self.md5_64()
        self.smd5()
        self.mysql()
        self.mysql_old()
        self.nt()
        self.ntlm()
        self.sha1()
        self.sha1_64()
        self.ssha()



    """Returns ramdom data"""
    def _gen_random(self, len=10, upper=True, lower=True, digits=True,
        punctuation=True):
        sample = ''
        if upper: sample += string.ascii_uppercase
        if lower: sample += string.ascii_lowercase
        if digits: sample += string.digits
        if punctuation: sample += string.punctuation
        rnd=random.Random()
        return ''.join(rnd.sample(sample, len))

    """Return UN*X crypted hash"""
    def crypt(self):
        s = self.salt or self._gen_random(len=2, punctuation=False)
        hash = crypt.crypt(self.password, s[:2])
        self.out['crypt'] = {
            'header': '{crypt}',
            'salt': s,
            'hash': hash }
        return hash

    """Return crypted MD5 password"""
    def _crypted_md5(self, magic='$1$'):
        m = hashlib.md5()
        salt = self.salt or self._gen_random(punctuation=False)
        password = self.password

        m.update(password + magic + salt)
        mixin = hashlib.md5(password + salt + password).digest()
        i = len(password)
        while i:
            if i & 1:
                m.update('\x00')
            else:
                m.update(password[0])
            i >>= 1
        final = m.digest()
        for i in range(1000):
            m2 = hashlib.md5()
            if i & 1: m2.update(password)
            else: m2.update(final)
            if i % 3: m2.update(salt)
            if i % 7: m2.update(password)
            if i & 1: m2.update(final)
            else: m2.update(password)
            final = m2.digest()
        itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

        rearranged = ''
        for a, b, c in ((0, 6, 12), (1, 7, 13), (2, 8, 14), (3, 9, 15), (4, 10, 5)):
            v = ord(final[a]) << 16 | ord(final[b]) << 8 | ord(final[c])
            for i in range(4):
                rearranged += itoa64[v & 0x3f]; v >>= 6
        v = ord(final[11])
        for i in range(2):
            rearranged += itoa64[v & 0x3f]; v >>= 6
        hash = magic + salt + '$' + rearranged
        self.out['_c_md5'] = {
            'header': '{_c_md5}',
            'salt': salt,
            'hash': hash }
        return hash


    """Return Apache APR1 hash"""
    def apr1(self):
        self._crypted_md5('$apr1$')
        self.out['apr1'] = self.out['_c_md5']
        del(self.out['_c_md5'])
        return self.out['apr1']['hash']

    """Return base64 hash"""
    def base64(self):
        hash = encode64(self.password)
        self.out['b64'] = {
            'header': '{b64}',
            'salt': None,
            'hash': hash }
        return hash

    """Return crypted MD5 hash"""
    def crypted_md5(self):
        self._crypted_md5('$1$')
        self.out['crypted_md5'] = self.out['_c_md5']
        del(self.out['_c_md5'])
        return self.out['crypted_md5']['hash']




    """Generate MD5 hexdigest"""
    def md5(self):
        hash = hashlib.md5(self.password).hexdigest()
        self.out['md5'] = {
            'header': '{md5}',
            'salt': None,
            'hash': hash }
        return hash

    """Generate base64 MD5 digest"""
    def md5_64(self):
        hash = encode64(hashlib.md5(self.password).digest())
        self.out['md5_64'] = {
            'header': '{md5_64}',
            'salt': None,
            'hash': hash }
        return hash

    """Generate MySQL formated hash"""
    def mysql(self):
        pass1 = hashlib.sha1(self.password).digest()
        pass2 = hashlib.sha1(pass1).hexdigest()
        hash = "*" + pass2.upper()
        self.out['mysql'] = {
            'header': '{mysql}',
            'salt': None,
            'hash': hash }
        return hash


    """Generate MySQL old-formated hash"""
    def mysql_old(self):
        nr = 1345345333
        add = 7
        nr2 = 0x12345671
        for c in (ord(x) for x in self.password if x not in (' ', '\t')):
            nr^= (((nr & 63)+add)*c)+ (nr << 8) & 0xFFFFFFFF
            nr2= (nr2 + ((nr2 << 8) ^ nr)) & 0xFFFFFFFF
            add= (add + c) & 0xFFFFFFFF
        hash = "%08x%08x" % (nr & 0x7FFFFFFF,nr2 & 0x7FFFFFFF)
        self.out['mysql_old'] = {
            'header': '{mysql_old}',
            'salt': None,
            'hash': hash }
        return hash

    """Return plaintext password"""
    def clear(self):
        hash = self.password
        self.out['clear'] = {
            'header': '{clear}',
            'salt': None,
            'hash': hash }
        return hash

    """Generate a Seeded MD5 Hash"""
    def smd5(self):
        s = self.salt or self._gen_random()
        h = hashlib.md5(self.password)
        h.update(s)
        hash = encode64(h.digest() + s)
        self.out['smd5'] = {
            'header': '{smd5}',
            'salt': s,
            'hash': hash }
        return hash

    """Generate Windows NT hash"""
    def nt(self):
        try:
            try:
                import smbpasswd
                hash =  smbpasswd.nthash(self.password)
            except:
                from Crypto.Hash import MD4
                hash = MD4.new(self.password.encode("utf-16-le")).hexdigest().upper()
            self.out['nt'] = {
                'header': '{nt}',
                'salt': None,
                'hash': hash }
            return hash
        except:
            return None

    """Generate Windows NTLM hash"""
    def ntlm(self):
        try:
            import smbpasswd
            hash =  smbpasswd.lmhash(self.password)
            self.out['ntlm'] = {
                'header': '{ntlm}',
                'salt': None,
                'hash': hash }
            return hash
        except:
            return None





    """Generate SHA1 hexdigest"""
    def sha1(self):
        hash = hashlib.sha1(self.password).hexdigest()
        self.out['sha1'] = {
            'header': '{sha1}',
            'salt': None,
            'hash': hash }
        return hash

    """Generate base64 SHA1 digest"""
    def sha1_64(self):
        hash = encode64(hashlib.sha1(self.password).digest())
        self.out['sha1_64'] = {
            'header': '{sha1_64}',
            'salt': None,
            'hash': hash }
        return hash

    """Generate a Seeded SHA1 Hash"""
    def ssha(self):
        s = self.salt or self._gen_random()
        h = hashlib.sha1(self.password)
        h.update(s)
        hash = encode64(h.digest() + s)
        self.out['ssha'] = {
            'header': '{ssha}',
            'salt': s,
            'hash': hash }
        return hash
  
    def __str__(self):
        keys = self.out.keys()
        keys.sort()
        lines = ['%13s  %13s %s' % ("Scheme", "Salt", "Hash")]
        for k in keys:
            s = self.out[k]['salt'] or ''
            h = '%s' % self.out[k]['header']
            lines.append("%13s: %13s %s" %
                (k, s, self.out[k]['hash']))
        return '\n'.join(lines)
        
    def __repr__(self):
        lines = [ "<%s" % self.__class__.__name__ ]
        lines.append(self.__str__())
        lines.append('>')
        return '\n'.join(lines)


def __init__():
    import sys
    try:
        p = sys.argv[1]
        try:
            s = sys.argv[2]
        except:
            s = None
    except:
        sys.stderr.write("%s password [salt]" % sys.argv[0])
        sys.exit(1)

    c = CWHashes(p, s)
    c.run_all()
    print c

if __name__ == '__main__':
  __init__()

# vim:ts=4:sw=4:sts=4:set expandtab:
