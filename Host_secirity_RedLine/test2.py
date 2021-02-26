import random
import string
def password_user_test():
    return 0
def ssd_config_test():
    cmds = "cat /etc/ssh/sshd_config | egrep 'Protocol|PasswordAuthentication|PermitEmptyPasswords|PermitEmptyPasswds|PermitRootLogion|MaxAuthTries|ClientAliveInterval|PubkeyAuthentication|AuthorizedKeysFile|Ciphers' |grep -v '#'"
    return 0
def sha1_test():
    cmds1 = "openssl x509 -inform pem -noout -text -in /etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt"
    cmds2 = "openssl x509 -inform pem -noout -text -in /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
    cmds3 = "openssl x509 -inform pem -noout -text -in /etc/pki/ca-trust/extracted/pem/email-ca-bundle.pem"

print(random.sample(string.ascii_letters + string.digits, 9))