import json
import urllib2
from poster.encode import multipart_encode
from poster.streaminghttp import register_openers
import os


class VirusTotal(object):
    
    def __init__(self, apikey=""):
        """ Initialize a VirusTotal object by passing the apikey as a parameter
        """
        self.apikey = apikey
    
    
    #    
    # Report printing functions      
    #
    def parse_generator(self, dictionary, indent=False):
        for k, v in dictionary.iteritems():
            if isinstance(v, dict):
                yield "[%s]"%k
                for value in self.parse(v, True):
                    yield value         
            else:
                if indent:
                    indent_char = "\t"
                else:
                    indent_char=""
                yield "%s%s: %s"%(indent_char,k,v)
                
    def get_report(self, v_total_json):
        """ Calls a recursive generator to generate a "pretty" report """      
        virus_total_report = ""
        for parsed_data in self.parse_generator(json.loads(v_total_json)):
            virus_total_report += "%s\n"%parsed_data
        return virus_total_report
    
    #  
    # Virus Total API functions 
    # 
    def submit_file_for_scan(self,filepath):
        """ Submits a file to be scanned
            Returns the JSON response
        """     
        # Register the streaming http handlers with urllib2
        register_openers()
        # Extract the file name
        filename = os.path.basename(filepath)
        # headers contains the necessary Content-Type and Content-Length
        # datagen is a generator object that yields the encoded parameters
        try:
            datagen, headers = multipart_encode({"name": filename, "file": open(filepath, "rb"), "apikey":self.apikey})
            # Create the Request object
            request = urllib2.Request("https://www.virustotal.com/vtapi/v2/file/scan", datagen, headers)
            # Submit the file and read the reply
            # TODO: Save this data
            submission_info =  urllib2.urlopen(request).read()
            return submission_info
        except Exception, err:
            print err
            return
        
    
    def lookup_by_hash(self,hash):
        """ Searches the virus total db for malware information based on md5/sha256 hashes
            Returns JSON
        """
        query_dict = {}
        query_dict["endpoint"] =  "https://www.virustotal.com/vtapi/v2/file/report"
        query_dict["apikey"]   =  self.apikey
        query_dict["resource"] =  hash
        url = "{endpoint}?apikey={apikey}&resource={resource}".format(**query_dict)     
        v_total_json = urllib2.urlopen(url).read()
        return v_total_json

