import time
import os
import hashlib
from virus_total_apis import PublicApi as VirusTotalPublicApi

# Configuration 
api_key = "YOUR API KEY"

# Functions 
def get_file_hash(filepath):
  sha256_hash = hashlib_sha256()
  try:
      with open(filepath, "rb") as f:
          for byte_block in inter(lambda: f.read(4096), b""):
              sha256_hash.update(byte_block)
      return sha256_hash.hexdigest()
  except FileNotFoundError:
    print(f"Error: The file '{filepath}' was not found.")
    return None
  except Exception as e:
    print(f"An error occured while hashing the file: {e}")
    return None


def check_file_hash(file_hash, api_key):
  if not file_hash:
    return
  
  # Initialize the VirusTotal API client
  vt = VirusTotalPublicApi(api_key)

  print(f"\nChecking hash: {file_hash}")

  # Virus Totals api has a rate limit of 4 request per minute. Careful.
  time.sleep(15)

  response = vt.get_file_report(file_hash)

  if response["response_code"] == 200: # Request succesful
    if response["results"]["response_code"] == 1: # Hash found in dataset
      positives = response["results"]["positives"]
      total = response["results"]["total"]
      scan_date = response["results"]["scan_date"]
      print(f"✅ Analysis found!")
      print(f"  Scan Date: {scan_date}")
      print(f"  Detections: {positives} / {total}")
      if positives > 0:
        print("   🚨 Result: File is concidered malicious by one or more vendors.")
      else:
        print("   👍 Result: '{filepath}' File appears to be clean.")
    elif response["results"]["response_code"] == 0: # Hash not found
      print("❓ Analysis not found. The file may not have been scanned by VirusTotal before.")
    else:
      print("An unexpected API response was received.")
      print(response)
  else: # Request Failed
    print(f"❌ Error checking hash. Status code: {response['response_code']}")
    print(f"    Message: {response.get('verbose_msg', 'No verbose message.')}")

# Main Execution
if __name__ == "__main__":
  file_to_check = input("enter the full path to the file you want to check: ")

  if os.path.exists(file_to_check):
    calculated_hash = get_file_hash(file_to_check)

    check_file_hash(calculated_hash, API_KEY)
  else:
    print(f"Error: The path '{file_to_check}' does not exist or is invalid.")