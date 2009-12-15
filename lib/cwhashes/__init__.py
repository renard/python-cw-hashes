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
    def __init__(self, password=None, kwargs=None):
        self.keymaps = {
            'azerty': 'ertyuiopsdfghjklxcvbn',
            'colemak': 'qwahzxcvbm',
            'qwertz': 'qwertuiopasdfghjklxcvbnm',
            'qzerty': 'ertuiopsdfghjklxcvbn',
        }
        self.password = password or self._gen_random(**kwargs)
        self.salt = kwargs['salt']
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



    """Returns random data"""
    def _gen_random(self, chars=10, upper=True, lower=True, digit=True,
        punctuation=True, keymap=None, **trash):
        sample = ''
        # First try to find common map
        try:
            layout = self.keymaps[keymap]
            if upper: sample += layout.upper()
            if lower: sample += layout.lower()
        except:
            # Try to list supported layouts
            if keymap == 'list':
                import sys
                print "Supported keymaps and common letters with qwerty:\n"
                keys = self.keymaps.keys()
                keys.sort()
                for k in keys:
                    print "  %s: %s" % (k, self.keymaps[k])
                sys.exit(0)
            else:
                # Common password
                if upper: sample += string.ascii_uppercase
                if lower: sample += string.ascii_lowercase
                if punctuation: sample += string.punctuation
        if digit: sample += string.digits
        if not sample: sample = string.letters + string.digits
        rnd=random.Random()
        sample = list(sample)
        if chars > len(sample):
            new_chars = len(sample) / 2
            loops = chars / new_chars
            ret = ''
            for x in xrange(loops):
                ret += self._gen_random(new_chars, upper, lower, digit,
                    punctuation, keymap)
            if len(ret) < chars:
                ret += self._gen_random(chars - len(ret), upper, lower,
                    digit, punctuation, keymap)
            return ret
        else:
            return ''.join(rnd.sample(sample, chars))

    """Return UN*X crypted hash"""
    def crypt(self):
        s = self.salt or self._gen_random(chars=2, punctuation=False)
        hash = crypt.crypt(self.password, s[:2])
        self.out['crypt'] = {
            'header': '{crypt}',
            'salt': s,
            'hash': hash }
        return hash

    """Return crypted MD5 password"""
    def _crypted_md5(self, magic='$1$'):
        salt = self.salt or self._gen_random(punctuation=False)
        password = self.password
        ctx = password + magic + salt
        final =  hashlib.md5(password + salt + password).digest()
        for pl in range(len(password), 0, -16):
            if pl > 16:
                ctx += final[:16]
            else:
                ctx += final[:pl]

        i = len(password)
        while i:
            if i & 1:
                ctx += chr(0)
            else:
                ctx += password[0]
            i >>= 1

        final = hashlib.md5(ctx).digest()
        for i in range(1000):
            ctx1 = ''
            if i & 1: ctx1 += password
            else: ctx1 += final[:16]
            if i % 3: ctx1 += salt
            if i % 7: ctx1 += password
            if i & 1: ctx1 += final[:16]
            else: ctx1 += password
            final = hashlib.md5(ctx1).digest()

        itoa64 = './' + string.digits + string.ascii_uppercase \
            + string.ascii_lowercase
        rearranged = ''
        for a, b, c in ((0, 6, 12), (1, 7, 13), (2, 8, 14), (3, 9, 15), (4, 10, 5)):
            v = ord(final[a]) << 16 | ord(final[b]) << 8 | ord(final[c])
            for i in range(4):
                rearranged += itoa64[v & 0x3f]
                v >>= 6

        v = ord(final[11])
        for i in range(2):
            rearranged += itoa64[v & 0x3f]
            v >>= 6
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

def parse_options():
    import optparse
    u = "Usage: %prog [options] [password]"
    e = "Use '-k list' to list supported keymap"
    p = optparse.OptionParser(usage=u, epilog=e)
    p.add_option("-c", "--chars", dest="chars", default=10, metavar="CHARS",
        type="int", help="Password length (default: %default)")
    p.add_option("-s", "--salt", dest="salt", metavar="SALT",
        help="Password salt (default: random)")
    p.add_option("-L", "--no-lower", dest="lower", default=True,
        action="store_false", help="Do not use lower case chars (default: %default)")
    p.add_option("-U", "--no-upper", dest="upper", default=True,
        action="store_false", help="Do not use upper case chars (default: %default)")
    p.add_option("-D", "--no-digit", dest="digit", default=True,
        action="store_false", help="Do not use digit chars (default: %default)")
    p.add_option("-p", "--punctuation", dest="punctuation", default=False,
        action="store_true", help="Use ponctuation chars (default: %default)")
    p.add_option("-k", "--keymap", dest="keymap", default=None, metavar="KEYMAP",
        help="Make sure password is same in qwerty and KEYMAP (default: %default)")

    (o, a) = p.parse_args()
    return (o.__dict__, a)

def __init__():
    import sys

    (o, a) = parse_options()
    if len(a) == 0: a = [ None ]

    c = CWHashes(a[0], o)
    c.run_all()
    print c

if __name__ == '__main__':
  __init__()

# vim:ts=4:sw=4:sts=4:set expandtab:
