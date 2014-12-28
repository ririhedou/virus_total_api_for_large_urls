#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests
import json
import time 


class vtapi():
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.api = "79cfe4a9acf92f308311b7d877ed4b27f286c493c955d701f51094dfb7e54dbd"
        self.baseurl = "https://www.virustotal.com/vtapi/v2/"

    def do_it(self, urls, option):
        
        res = [] 
        if option=="S" or option=="s": #send
           try:
             results = self.send_results_url(urls)
             flag,res = self.scan_and_print_send_results( results)
           except:
             return 2,res
        elif option=="R" or option == "r": #retrieve
           try: 
             results = self.retrieve_results_url(urls)
             flag,res = self.scan_and_print_retrieve_results(results)
           except:
             return 2,res
        else:
             raw_input("Wrong Option! Enter to exit")  
             exit()  

        return flag,res 
 
    #Print results from a file
    def scan_and_print_retrieve_results(self, results):
        
        flag =0
        res = [] 
        if results['response_code'] == 0:
            print "No response got, try again later or send the url first"
            flag =2
        else:
            for i in results['scans']:
                s1 =  "%s : %s" % ( str(i), str(results['scans'][i]['result'])) 
                print (s1)
                res.append(s1)
                flag = 1
         
        return flag,res

    def scan_and_print_send_results(self, results):
        
        res = []
        flag = 0
        if results['response_code'] == 0:
            print "No response got, try again later"
        else:
            print ("the permanentlink is ")
            print (results['permalink'])
            res.append(str(results['permalink'])) 
   
        return flag,res

    #retrieve 
    def retrieve_results_url(self, url_rsc):

        base = self.baseurl + "url/report"
        para = {"apikey": self.api, "resource": url_rsc}
        response = requests.post(base, data=para)
        time.sleep(15)    
        json_data = json.loads(response.text)
        return (json_data)


    #Function to get results of a scanned file
    def send_results_url(self, url_src):
        
        base = self.baseurl + "url/scan" 
        attr = {"url":url_src, "apikey": self.api}
        response = requests.post(base, data=attr )       
        time.sleep(15)    
        json_data = json.loads(response.text)
        return (json_data)

    
