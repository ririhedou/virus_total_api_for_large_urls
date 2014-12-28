#!/usr/bin/python
# -*- coding: utf-8 -*-
#for URLs

from just_for_url import vtapi
import os
import argparse
import hashlib

__author__= "ketian"


def parse_options():
    parser = argparse.ArgumentParser(description="Send or retrieve the apk files")
    parser.add_argument('-s', '--send', type=str, help='the action to send apks to search')
    parser.add_argument('-r', '--retrieve', type=str, help='the action to retrieve apks from dataset in virustotal' )    
    args = parser.parse_args()
    return args


def get_filepaths(directory):
    """
    this function will generate the fienames in a directory
    """ 
    file_paths = []
    #walk tree  
    for root,directories,files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root,filename)
            file_paths.append(filepath)
    
    return file_paths 


def main():
    
    vt = None
    option = None
    vt = vtapi()
    args = parse_options()

    if args.send:
       option = 's'
       _file = args.send 
    if args.retrieve:
       option = 'r'
       _file = args.retrieve

    f = open(_file, 'r')
    f_re = open('report.txt', 'wb')
    for line in f.readlines():
        url_src = str(line.strip()) #remove the "\n" for each line 
        flag, res = vt.do_it(url_src, option=option)
        f_re.write(url_src + '\n')
        for each_line in res:
            f_re.write(each_line + '\n')  
        f_re.write('\n') 
    f.close()
    f_re.close()
    print ("check the reportl.txt")

if __name__ == "__main__":
   exit(main())
