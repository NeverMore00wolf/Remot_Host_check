import os
import re
def get_files_name(root_dir):
    check_suffix = ['log', 'xml', 'conf', 'yml']
    cur_dir = os.path.abspath(root_dir)
    file_list = os.listdir(cur_dir)
    files_name_list = []
    for file in file_list:
        fullfile = cur_dir + "/" + file
        if os.path.isfile(fullfile):
            file_suffix = file.split(".")[-1]
            if file_suffix in check_suffix:
                files_name_list.append(fullfile)
        elif os.path.isdir(fullfile):
            dir_extra_list = get_files_name(fullfile)
            if len(dir_extra_list) != 0: #空文件判断
                for x in dir_extra_list:
                    files_name_list.append(x)
        else:
            continue
    return files_name_list

def Keyword_scan(file_path_list):
    for file_path in file_path_list:
        with open(file_path, 'r', encoding="utf-8", errors="ignore") as file:
            line_number = 0
            for line in file:
                #regex = "bank|password:|account|passwd:|key:|"
                regex = "\s?password:|key:\s|passwd:\s|bank|account\s|key=|passwd=|"
                if re.search(regex, line, re.I):
                    print(line, 'file_name:', file_path, 'Lines:', line_number, '\n')
                    line_number = line_number + 1
                else:
                    line_number = line_number + 1



if __name__ == "__main__":
    file_name_list = []
    file_path = input('Please enter the directory path you want to explore: ')
    #target = input('please enter the key word you want to find: ')
    #file_path = "/home/program/hisec/logs/"
    file_name_list = get_files_name(file_path)
    Keyword_scan(file_name_list)
