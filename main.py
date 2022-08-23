"""
1. change directory to where you have stored the executable.
2. download pip: python -m pip install --upgrade pip
3. download requests package: python -m pip install requests
4. change the API key in line 13
5. run this program with command:  python [executable_path] [input_file],  ex: python ./main.py samplefile.txt
"""
from pathlib import Path
import requests # handle request from url
import hashlib #for calculating hash value
import sys # handle input file

apikey = '2a9ad0c8f121e7e5aefeef54e01f08fa'
filename = ""
data_id = ""
def hash_file(filename):
   """"This function returns the SHA-1 hash
   of the file passed into it"""
   # make a hash object
   h = hashlib.sha1()
   # open file for reading in binary mode
   with open(filename,'rb') as file:
       # loop till the end of the file
       chunk = 0
       while chunk != b'':
           # read only 1024 bytes at a time
           chunk = file.read(1024)
           h.update(chunk)
   # return the hex representation of digest
   return h.hexdigest()

def main():
    try:
        file_path = sys.argv[1] #retrieve file as the first argument
    except IndexError as err:
        print("Please enter command in the following format: python ./test.py [input_file]")
        return -1

    filename = Path(file_path).name #retrieve file name
    hash = hash_file(filename) #get hash value of the file

    #retrieve scan history if the file exists in the DB
    url = "https://api.metadefender.com/v4/hash/{}/scanhistory".format(hash)
    headers = {
     "apikey": "{}".format(apikey)
    }
    try:
        response = requests.request("GET", url, headers=headers)
    except requests.exceptions.HTTPError as err:
        print("can not reach url: ", url)
        return -1
    if response.status_code == 200: #step 3 results are found, file is previously stored in cache, The request has succeeded
        data = response.json()["scan_result_history"]
        data_id =  data[0]["data_id"]  #retrieve data_id, can skip to step 6
    else: #step 4 results are not found, upload the file and receive a "data_id"
        # Scanning file and upload it
        url = "https://api.metadefender.com/v4/file"
        headers = {
         "apikey": "{}".format(apikey), #example api key, insert own key after
         "Content-Type": "application/octet-stream",
        }
        payload = file_path
        try:
            response = requests.request("POST", url, headers=headers, data=payload)
        except requests.exceptions.HTTPError as err:
            print("can not reach url: ", url)
            return -1
        data = response.json()
        data_id = data["data_id"] #retrieve data_id


    #fetch data here
    url = "https://api.metadefender.com/v4/file/{}".format(data_id) #data_id is stored from previous result!
    headers = {
     "apikey": "{}".format(apikey), #example api key, insert own key after
     "x-file-metadata": "{x-file-metadata}"
    }
    try:
        response = requests.request("GET", url, headers=headers)
    except requests.exceptions.HTTPError as err:
        print("can not reach url: ", url)
        return -1
    data = response.json()
    while data["scan_results"]["scan_all_result_a"] == "In queue":
        print("waiting ...")
        try:
            response = requests.request("GET", url, headers=headers)
        except requests.exceptions.HTTPError as err:
            print("can not reach url: ", url)
            return -1
        data = response.json()

    print("Filename:", filename)
    print("overall_status: ", data["scan_results"]["scan_all_result_a"])
    search = data["scan_results"]["scan_details"]
    for engine in search:   # key:value,  engine:{process result}
        result = search[engine]
        print("engine: ", engine)
        if result['threat_found']:
            print("threat_found: ", result['threat_found'])
        else:
            print("threat_found: ", "clean")
        print("def_time: ", result['def_time'])

if __name__ == "__main__":
    main()