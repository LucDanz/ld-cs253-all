import hashlib
import hmac
import random
import string

SECRET = 'mj9GrPlsbs7\x0cb|B.`Yt'

def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    ###Your code here
    val = h.split('|')[0]
    if make_secure_val(val) == h:
        return val
    else:
        return None

def make_salt(length = 5):
	return ''.join(random.choice(string.letters) for _ in range(length))

def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	pw_hash = hashlib.sha256(name + pw + salt).hexdigest()
	return "%s,%s" % (pw_hash,salt)

def valid_pw(name, pw, h):
	salt = h.split(',')[1]
	return h == make_pw_hash(name,pw,salt)
		
