# -*- coding:utf-8 -*-
# @Author:  Pilgrim
# @Software: Pycharm
# @Time: 2021/2/24
import paramiko
import logging
import time


def ssh(sys_ip, username, password, root_password, cmds):
    try:
        # 创建ssh客户端
        client = paramiko.SSHClient()
        # 第一次ssh远程时会提示输入yes或者no
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # 密码方式远程连接
        try:
            client.connect(sys_ip, 22, username=username, password=password, timeout=10, allow_agent=False, look_for_keys=False)
        except:
            logging.info('err: can not conn %s ,pls check %s and password of xxxxxx', (sys_ip, username))
        # 互信方式远程连接
        # key_file = paramiko.RSAKey.from_private_key_file("/root/.ssh/id_rsa")
        # ssh.connect(sys_ip, 22, username=username, pkey=key_file, timeout=20)
        # 执行命令

        stdin, stdout, stderr = client.exec_command("sudo root")
        stdin.write(root_password+'\n')
        stdin.flush()
        stdin.write(cmds)
        result = stdout.read().decode('utf-8')

        # 获取命令执行结果,返回的数据是一个list
        #result = stdout.readlines()
        return result
    except Exception as e:
        print(e)
    finally:
        client.close()

def sha1_test(sys_ip,username,password,r_password):
    cmds1 = "openssl x509 -inform pem -noout -text -in /etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt"
    cmds2 = "openssl x509 -inform pem -noout -text -in /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
    cmds3 = "openssl x509 -inform pem -noout -text -in /etc/pki/ca-trust/extracted/pem/email-ca-bundle.pem"
    print("\033[1;37;43m\tca-bundle.trust.crt:check\033[0m")
    print(ssh(sys_ip, username, password, r_password, cmds1))
    print("\033[1;37;43m\ttls-ca-bundle.pem:check\033[0m")
    print(ssh(sys_ip, username, password, r_password, cmds2))
    print("\033[1;37;43m\temail-ca-bundle.pem:check\033[0m")
    print(ssh(sys_ip, username, password, r_password, cmds3))
if __name__ == "__main__":
    sys_ip = "172.171.51.106"
    username = "hisec"
    password = "cGFzc3dvcmQK"
    r_password = "17router@123"
    cmds = "ls"
    sha1_test(sys_ip, username, password, r_password)
