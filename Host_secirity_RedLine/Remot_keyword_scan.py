# -*- coding:utf-8 -*-
# @Author:  Pilgrim
# @Software: Pycharm
# @Time: 2021/2/24
import paramiko
import logging
import time
import random

#随机数，小写字母+数字
#48-57数字，97-122小写字母，65-90大写，33-46特殊符号，58-64运算符，91-96，123-126运算优先级字符等
def getRandomSet(bits, mod):
    num_set = [chr(i) for i in range(48, 58)]
    char_set_small = [chr(i) for i in range(97, 123)]
    char_set_big = [chr(i) for i in range(65, 91)]
    special_set = [chr(i) for i in range(33, 46)]
    if mod == "username":
        total_set = num_set + char_set_small
        value_set = "".join(random.sample(total_set, bits))
    elif mod == "password":
        total_set = num_set + char_set_small + special_set
        value_set = "".join(random.sample(total_set, bits))
    elif mod == "password_BigWrite":
        total_set = char_set_big
        value_set = "".join(random.sample(total_set, bits))
    elif mod == "password_SmallWrite":
        total_set = char_set_small
        value_set = "".join(random.sample(total_set, bits))
    elif mod == "password_Special":
        total_set = special_set
        value_set = "".join(random.sample(total_set, bits))
    else:
        print("mod input error! only support  username or password password_BigWrite password_SmallWrite password_Special")
    return value_set



#远程连接服务器，切换root用户
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
        client_root = client.invoke_shell()
        time.sleep(1)
        client_root.send('su \n')
        buff = ''
        while not buff.endswith('Password: '):
            resp = client_root.recv(2048)
            buff += resp.decode('utf-8')
        client_root.send(root_password)
        client_root.send('\n')
        buff = ''
        while not buff.endswith('# '):
            resp = client_root.recv(2048)
            buff += resp.decode('utf-8')
        if buff.endswith('# '):
            print("Aleardy change root!")
        buff = ''
        client_root.send(cmds)
        client_root.send('\n')
        while not buff.endswith('# '):
            resp = client_root.recv(8192)
            buff += resp.decode('utf-8')

        #stdin, stdout, stderr = client_root.exec_command(cmds, get_pty=True)
        # 获取命令执行结果,返回的数据是一个list
        #result = stdout.readlines()
       # result = stdout.read().decode('utf-8')
        #return result
    except Exception as e:
        print(e)
    finally:
        client.close()
    return buff

#证书签名SHA1模块检测
def sha1_test(sys_ip, username, password, r_password):
    cmds1 = "openssl x509 -inform pem -noout -text -in /etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt"
    cmds2 = "openssl x509 -inform pem -noout -text -in /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
    cmds3 = "openssl x509 -inform pem -noout -text -in /etc/pki/ca-trust/extracted/pem/email-ca-bundle.pem"
    print("\033[1;37;43m\tca-bundle.trust.crt:check\033[0m")
    print(ssh(sys_ip, username, password, r_password, cmds1))
    print("\033[1;37;43m\ttls-ca-bundle.pem:check\033[0m")
    print(ssh(sys_ip, username, password, r_password, cmds2))
    print("\033[1;37;43m\temail-ca-bundle.pem:check\033[0m")
    print(ssh(sys_ip, username, password, r_password, cmds3))

#ssh暴力破解检查模块
def Ssd_Config_Test(sys_ip, username, password, r_password):
    cmd = "cat /etc/ssh/sshd_config | egrep 'Protocol|PasswordAuthentication|PermitEmptyPasswords|PermitEmptyPasswds|PermitRootLogion|MaxAuthTries|ClientAliveInterval|PubkeyAuthentication|AuthorizedKeysFile|Ciphers' |grep -v '#'"
    print("\033[1;37;43m\t暴力破解，检查ssd_config文件配置参数：\033[0m")
    print(ssh(sys_ip, username, password, r_password, cmd))

#系统全0端口监听检测
def Listen_Ip_Port_Test(sys_ip, username, password, r_password):
    cmd ="netstat -apn|awk '{if($5~/0.0.0.0|:::/) print $0}'|egrep -v '127.0.0.0|::1:'"
    print("\033[1;37;43m\t系统监听全0IP，端口检测：\033[0m")
    print(ssh(sys_ip, username, password, r_password, cmd))

#系统中第三方网络嗅探工具，调试工具检测
def Tools_Test(sys_ip, username, password, r_password):
    cmd = "find / -name 'tcpdump' -o -name 'gdb' -o -name 'strace' -o -name 'readelf' -o -name 'cpp' -o -name 'netstat' -o -name 'nc' -o -name 'namp' -o -name 'ethereal'"
    print("\033[1;37;43m\t系统中第三方网络嗅探工具，调试工具检测：\033[0m")
    print(ssh(sys_ip, username, password, r_password, cmd))

#进程运行权限检测
def Process_Authority_Test(sys_ip, username, password, r_password):
    cmd = "ps -ef | grep root"
    print("\033[1;37;43m\t系统中第三方网络嗅探工具，调试工具检测：\033[0m")
    print("运行软件程序的帐号要尽可能的使用操作系统低权限的帐号，尤其是对外提供服务的和能够被远程访问的进程（如web服务、数据库、ftpserver、命令行CLI）")
    print(ssh(sys_ip, username, password, r_password, cmd))

#禁止TLS协议中使用含CBC对称密码算法的加密套件
def TLS_CBC_Test(sys_ip, username, password, r_password):
    cmd1 = "openssl s_client -tls1_2 -cipher AES128-SHA256 -connect 0.0.0.0:1800"
    cmd2 = "openssl s_client -tls1_2 -cipher ECDHE-RSA-AES128-SHA256 -connect 0.0.0.0:1800"
    print("\033[1;37;43m\tTLS AES128-SHA256检测：\033[0m")
    print(ssh(sys_ip, username, password, r_password, cmd1))
    print("\033[1;37;43m\tTLS ECDHE-RSA-AES128-SHA256检测：\033[0m")
    print(ssh(sys_ip, username, password, r_password, cmd2))

#秘钥文件权限检查
def Key_File_Authority_Test(sys_ip, username, password, r_password):
    cmd = '''for name in `find / -regextype posix-extended -regex ".*\.(crt|pem)"`; do ls -l $name*; done'''
    print("\033[1;37;43m\t秘钥文件权限检测：\033[0m")
    print(ssh(sys_ip, username, password, r_password, cmd))

#系统自身操作维护口令与密码复杂度监测
def Username_Password_Test():
    username = 'user' + getRandomSet(8, 'username')
    password = getRandomSet(20, 'password')
    #创建用户
    creat_user_cmd = 'useradd ' + username
    print(creat_user_cmd)
    #ssh(sys_ip, username, password, r_password, cmd)
    #密码复杂度测试
    #密码小于6位测试
    pass_test_cmd1 = 'echo ' + username + ':' + getRandomSet(5, 'password') + ' | chpasswd'
    print(pass_test_cmd1)
    result1 = ssh(sys_ip, username, password, r_password, pass_test_cmd1)
    if result1==0:
        print("检测结果：\033[1;32;43\t Flase,密码应该大于6位\033[0m")
    elif result1 == 1:
        print("检测结果：Ture , 密码不能小于6位 ")
    else :
        print("\033[1;32;43\t修改用户密码失败 \033[0m")
    #密码用户名相同测试
    pass_test_cmd2 = 'echo ' + username + ':' + username + ' | chpasswd'
    print(pass_test_cmd2)
    result1 = ssh(sys_ip, username, password, r_password, pass_test_cmd1)
    if result1 == 0:
        print("检测结果：\033[1;32;43\t Flase,密码与用户名不应该相同\033[0m")
    elif result1 == 1:
        print("检测结果：Ture , 密码与用户名不相同 ")
    else:
        print("\033[1;32;43\t修改用户密码失败 \033[0m")
    #只有大写字母密码测试
    pass_test_cmd3 = 'echo ' + username + ':' + getRandomSet(8, 'password_BigWrite') + ' | chpasswd'
    print(pass_test_cmd1)
    result1 = ssh(sys_ip, username, password, r_password, pass_test_cmd3)
    if result1 == 0:
        print("检测结果：\033[1;32;43\t Flase,密码不应该只有大写字母\033[0m")
    elif result1 == 1:
        print("检测结果：Ture , 密码不能全大写 ")
    else:
        print("\033[1;32;43\t创建用户失败 \033[0m")
    #只有小写字母密码测试
    pass_test_cmd4 = 'echo ' + username + ':' + getRandomSet(8, 'password_SmallWrite') + ' | chpasswd'
    print(pass_test_cmd1)
    result1 = ssh(sys_ip, username, password, r_password, pass_test_cmd4)
    if result1 == 0:
        print("检测结果：\033[1;32;43\t Flase,密码不应该只有小写\033[0m")
    elif result1 == 1:
        print("检测结果：Ture , 密码不能只有小写 ")
    else:
        print("\033[1;32;43\t创建用户失败 \033[0m")
    #只有特殊字符密码测试
    pass_test_cmd5 = 'echo ' + username + ':' + getRandomSet(8, 'password_Special') + ' | chpasswd'
    print(pass_test_cmd1)
    result1 = ssh(sys_ip, username, password, r_password, pass_test_cmd5)
    if result1 == 0:
        print("检测结果：\033[1;32;43\t Flase,密码不应该只有特殊字符\033[0m")
    elif result1 == 1:
        print("检测结果：Ture , 密码不能只有特殊字符 ")
    else:
        print("\033[1;32;43\t创建用户失败 \033[0m")

if __name__ == "__main__":
    sys_ip = "172.171.51.106"
    username = "hisec"
    password = "cGFzc3dvcmQK"
    r_password = "17router@123"
    cmds = "ls"
    #sha1_test(sys_ip, username, password, r_password)
    #Ssd_Config_Test(sys_ip, username, password, r_password)
    #Listen_Ip_Port_Test(sys_ip, username, password, r_password)
    #Tools_Test(sys_ip, username, password, r_password)
    #Process_Authority_Test(sys_ip, username, password, r_password)
    #TLS_CBC_Test(sys_ip, username, password, r_password)
    #Key_File_Authority_Test(sys_ip, username, password, r_password)
    Username_Password_Test()