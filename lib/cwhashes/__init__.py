#!/usr/bin/python
# encoding: utf-8

__author__ = 'Sébastien Gross'
__copyright__ = 'Copyright (c) 2009 Sébastien Gross <seb•ɑƬ•chezwam•ɖɵʈ•org>'


import random
import string
import crypt
from base64 import b64encode as encode64
from base64 import b64decode as decode64

import hashlib
import re
import sys

class CWHashes:

    """ Each test definition consists of several item:

    - test name
    - match condition function
    - minimum value
    - complexity bonus
    - rate computing function
    - basic requirement (true / false)
    """
    tests = (
        (
            'Length',
            lambda p: len(p),
            8, 0,
            lambda n, s: 4 * n,
            True,
        ),
        (
            'Ascii uppercase',
            lambda p: len(re.findall('[A-Z]', p)),
            1, 26,
            lambda n, s: (n < s and n > 0) and (s - n) * 2 or 0,
            True,
        ),
        (
            'Ascii lowercase',
            lambda p: len(re.findall('[a-z]', p)),
            1, 26,
            lambda n, s: (n < s and n > 0) and (s - n) * 2 or 0,
            True,
        ),
        (
            'Digit',
            lambda p: len(re.findall('[0-9]', p)),
            1, 10,
            lambda n, s: (n < s) and (4 * n) or 0,
            True,
        ),
        (
            'Symbol',
            lambda p: len(re.findall('[^a-zA-Z0-9]', p)),
            1, 32, # len(string.punctuation) - tab & space
            lambda n, s: 6 * n,
            True,
        ),
        (
            'Digit or symbol in middle part',
            lambda p: len(re.findall('[^a-zA-Z]', p[1:-1])),
            1, 0,
            lambda n, s: 2 * n,
            False,
        ),
        (
            'Letters only',
            lambda p: (len(p) == len(re.findall('[a-z]', p.lower())))
                and len(p) or 0,
            0, 0,
            lambda n, s: -n,
            False,
        ),
        (
            'Digits only',
            lambda p: (len(p) == len(re.findall('[0-9]', p))) and len(p) or 0,
            0, 0,
            lambda n, s: -n,
            False,
        ),
        (
            'Repeated characters',
            lambda p: len(re.findall('(?=(.).*?\\1)', p.lower())),
            0, 0,
            lambda n, s: -((n * n) + n),
            False,
        ),

        (
            'Consecutive ascii uppercase',
            lambda p: len(re.findall('(?=[A-Z][A-Z])', p)),
            0, 0,
            lambda n, s: -(n * 2),
            False,
        ),
        (
            'Consecutive ascii lowercase',
            lambda p: len(re.findall('(?=[a-z][a-z])', p)),
            0, 0,
            lambda n, s: -(n * 2),
            False,
        ),
        (
            'Consecutive digits',
            lambda p: len(re.findall('(?=[0-9][0-9])', p)),
            0, 0,
            lambda n, s: -(n * 2),
            False,
        ),
        (
            'Sequential letters',
            lambda p: len(re.findall('(?=' + '|'.join( [ '|'.join(
                [
                    string.ascii_lowercase[ x : x + 3],
                    string.ascii_lowercase[ x : x + 3][::-1]
                ]
                ) for x in xrange(len(string.ascii_lowercase) - 2)]) + ')',
            p.lower())),
            0, 0,
            lambda n, s: -(n * 3),
            False,
        ),
        (
            'Sequential digits',
            lambda p: len(re.findall('(?=' + '|'.join( [ '|'.join(
                [
                    string.digits[ x : x + 3],
                    string.digits[ x : x + 3][::-1]
                ]
                ) for x in xrange(len(string.digits) - 2)]) + ')',
            p)),
            0, 0,
            lambda n, s: -(n * 3),
            False,
        ),
        (
            # This test should be the last one
            'Requirement Bonus',
            lambda p: p,
            0, 0,
            lambda n, s: (n >= s ) and (n * 2) or 0,
            False,
        ),
    )

    # human readable scores
    hr_scores = (
        (-sys.maxint, 0, "Extremely weak"),
        (0, 20, "Very weak"),
        (20, 40, "Weak"),
        (40, 60, "Good"),
        (60, 80, "Strong"),
        (80, 100, "Very strong"),
        (10, sys.maxint, "Extremely strong"),
    )

    # Tries per seconds
    # Source http://www.lockdown.co.uk/?pg=combi
    rates = (
        ( 'Pentium 100', 1000000 ),
        ( 'Dual Processor PC', 10000000 ),
        ( 'PCs cluster', 100000000 ),
        ( 'Supercomputer', 1000000000 ),
    )



    def __init__(self, password=None, kwargs=None):
        self.keymaps = {
            'azerty': 'ertyuiopsdfghjklxcvbn',
            'colemak': 'qwahzxcvbm',
            'qwertz': 'qwertuiopasdfghjklxcvbnm',
            'qzerty': 'ertuiopsdfghjklxcvbn',
        }
        self.tries = 0
        if password:
            self.password = password
            self.check_password_strenght()
        else:
            self.init_results()
            while self.checks['score'] < 100:
                self.password = self._gen_random(**kwargs)
                self.check_password_strenght()
                self.tries += 1
        self.salt = kwargs['salt']
        self.out = {}
        return

    def init_results(self):
        self.checks = {
            'results' : [],
            'score' : 0,
            'char_class': 0,
            'combinaisons' : 0,
        }

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
            new_chars = len(sample)
            loops = chars / new_chars
            ret = ''
            for x in xrange(loops):
                ret += self._gen_random(new_chars, upper, lower, digit,
                    punctuation, keymap)
            if len(ret) < chars:
                ret += self._gen_random(chars - len(ret), upper, lower,
                    digit, punctuation, keymap)
            ret = list(ret)
            rnd.shuffle(ret)
            return ''.join(ret)
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

    """


    """
    def check_password_strenght(self):
        p = self.password.decode('utf-8')

        self.init_results()

        pl = len(p)

        required_cond = 0
        required_test = 0
        for name, func, min, comp_bonus, score_func, req in CWHashes.tests:
            bonus = 0
            sc = func(p)
            if sc >= 1:
                self.checks['char_class'] += comp_bonus
            if req: required_test += 1
            if req and sc >= min:
                required_cond += 1
            # the last test is a spacial bonus !
            if name == CWHashes.tests[-1][0]:
                sc = required_cond
                bonus = score_func(required_cond, required_test)
            else:
                bonus = score_func(sc, pl)
            self.checks['results'].append((name, sc, bonus))
            self.checks['score'] += bonus
        for i in xrange(1, pl + 1):
            self.checks['combinaisons'] += self.checks['char_class'] ** i

    def pprint_checks(self):
        try:
            if not self.checks:
                self.check_password_strenght()
        except:
            self.check_password_strenght()
        print("Password analysis")
        print("%-30s%8s%8s" % ("Test", "Count", "Bonus"))
        for r in self.checks['results']:
            print("%-30s%8d%8d" % r)

        complexity = ''
        for i in CWHashes.hr_scores:
            if self.checks['score'] >= i[0] and self.checks['score'] < i[1]:
                complexity = i[2]
                break
        print("%-38s%8d" % ("Password final score: %s:" % complexity,
            self.checks['score']))

        """
        # TODO: this part should be developped later
        for t, r in CWHashes.rates:
            time = self.checks['combinaisons'] / r
            mins, secs = divmod(time, 60)
            hours, mins = divmod(mins, 60)
            days, hours = divmod(hours, 24)
            months, days = divmod(days, 30)
            years, months = divmod(months, 12)
            print("Life estimation on a %s (%d tries/sec)" % (t, r))
            print "%d years %d months %d days %d hours %d minutes %d seconds" % \
                (years, months, days, hours, mins, secs)
        """


def parse_options():
    import optparse
    u = "Usage: %prog [options] [password]"
    e = "Use '-k list' to list supported keymap"
    p = optparse.OptionParser(usage=u, epilog=e)
    p.add_option("-a", "--analyze", dest="analyze", default=False,
        action="store_true", help="Print password analyzis (default: %default)")
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
    if o['analyze']:
        c.pprint_checks()

if __name__ == '__main__':
  __init__()

# vim:ts=4:sw=4:sts=4:set expandtab:
