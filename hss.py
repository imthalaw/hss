import time
import os
import hashlib
from virus_total_apis import PublicApi
VirusTotalPublicApi

# Configuration 
API_KEY = "YOUR API KEY"

# Functions 
def get_file_hash(filepath):
 sha256_hash = hashlib_sha256()
 try:
   with open(filepath, "rb") as f:
     for byte_block in inter(lambda: f.read, b""):
