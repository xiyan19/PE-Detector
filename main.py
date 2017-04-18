# -*- coding: utf-8 -*-

"""
    此脚本用于删除指定目录下的非PE文件。(只处理一层目录，子文件夹及其内含文件不处理)

    使用方法：python main.py [target dir] [-d]

    ----------------------------

    PE文件，Portable Executable file format简称。
    如何判断一个文件是否为PE格式的文件：
    1、首先检验文件头部第一个字的值是否等于IMAGE_DOS_SIGNATURE，是则DOS MZ header有效；
    2、一旦证明文件的DOS header有效后，就可用e_lfanew来定位PE header了；
    3、比较PE header的第一个字的值是否等于IMAGE_NT_HEADER。如果前后两个值都匹配，那我们就认为该文件是一个有效的PE文件。

    从做法上来说：
    1、查找MZ头是否为0X4D5A；
    2、如果上面条件符合 则用e_lfanew指针定位pe头，e_lfanew一般位于0X3C；
    3、如果上面条件符合 则判断pe头是否为0x5045，都符合，则是有效PE文件。

    要注意大小端模式带来的影响。

    Last commit info:
    ~~~~~~~~~~~~~~~~~
    $LastChangedDate: 4/17/2017
    $Annotation: Create.
    $Author: xiyan19
"""


import struct, os, sys


# 读取文件的头两个字节，PE文件为0x4d5a
def getFileHeader(path):
    try:
        fileHandle = open(path, "rb")
        fileHeader = struct.unpack("h", fileHandle.read(2))[0]
        fileHandle.close()

        return fileHeader

    except Exception as e:
        # print(e)
        print("[-] Getting the file header of '" + path + "' is failed.")  # 此类文件暂不删除，单独处理

        return


# 获取e_lfanew指针指向的PE头，PE文件为0x5045
def getPEHeader(path):
    try:
        fileHandle = open(path,"rb")
        fileHandle.seek(60,0)
        e_lfanew = struct.unpack("h",fileHandle.read(2))[0]
        fileHandle.seek(e_lfanew,0)
        peHeader = struct.unpack("h",fileHandle.read(2))[0]
        fileHandle.close()

        return peHeader

    except Exception as e:
        # print(e)
        print("[-] Getting the PE header of '" + path + "' is failed.")  # 此类文件暂不删除，单独处理

        return


if __name__=="__main__":
    debug = 0  # 默认关闭debug模式
    if len(sys.argv) == 3 and sys.argv[2] == "-d":
        debug = 1

    # 获取目标文件夹下的所有文件名（包括目录）
    fileList = os.listdir(sys.argv[1])

    for file in fileList:
        # 拼接文件路径
        filePath = sys.argv[1]+"/"+file

        if os.path.isdir(filePath):  # 处理其为文件夹的情况
            if debug == 1:
                print("[-] " + file + " is a dir.")
        elif getFileHeader(filePath) == 23117 and getPEHeader(filePath) == 17744:
            if debug == 1:
                print("[+] " + file + " is a PE file.")
        else:
            if debug == 1:
                print("[-] " + file + " isn't a PE file.")
            os.system("rm " + filePath)

    print("[+] Done.")
