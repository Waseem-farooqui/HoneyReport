'''
Created on Aug 12, 2015

@author: waseem
'''
import requests
import json

def Submit_Binary():
    REST_URL = "http://172.20.16.57:8090/tasks/create/file"
    SAMPLE_FILE = "/home/waseem/binaries/1a3e522537a96da07ad0aaf7b2864b11"
    with open(SAMPLE_FILE, "rb") as sample:
        multipart_file = {"file": ("temp_file_name", sample)}
        request = requests.post(REST_URL, files= multipart_file)
        print(request.text)
    json_decoder = json.JSONDecoder()

    task_id = json_decoder.decode(request.text)['task_id']
    return task_id

def Get_Report(task_id):
    REST_URL = "http://115.186.176.139:8090/tasks/report/"+task_id
    request=requests.get(REST_URL)
    print(request.text)

#def Read_Files():
    
#Submit_Binary()
Get_Report('10')