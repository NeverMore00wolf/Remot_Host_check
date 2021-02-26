import re
str = 'Feb 24 15:56:01 master CROND[610506]: (root) CMD (/home/database/web/run-allmoudles-mon.sh)'
#regex = 'feb'
#if re.search(regex, str, re.I):
#    print(1111)

#path = "test_user_infopy"
#suffix = path.split(".")[-1]
#print(suffix)

a = ['py','log','xml']
path = "test_user_info.py"
suffix = path.split(".")[-1]
if suffix in a:
    print('hellow')
