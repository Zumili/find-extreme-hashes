#usr/bin/python
import time
import itertools
import string
import hashlib
import sys
import signal
import threading
import getopt
import random

info = """
  Name            : find-smallest-hash-py3.py
  Created By      : Thomas Messmer
  Blog            : http://thomas-messmer.com
  Documentation   : https://github.com/Zumili/
  License         : The MIT License
  Version         : 1.0
"""
# A lot of globals, ugly I know, but it increases the performance a bit...

smallest_hexdigest =  ("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                       "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                       "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                       "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")

                       
output_file = ''
user_name = ''
hashlib_type = hashlib.md5()
total_pass_try = 0
candidates_found = 0
start_time = 0
hash_per_sec = 0
digits_only = 0
random_length = 0
done = False
use_postfix = False
suppress_info = False

def signal_handler(signal, frame):
    print('\nYou pressed Ctrl+C!')
    global done
    done=True
    sys.exit(0)

def animate():
    global hash_per_sec
    for c in itertools.cycle(['|', '/', '-', '\\']):
        if done==True:
            break
        
        sys.stdout.write('\rloading ' + c + ' H/s: ' 
                         + str(int(hash_per_sec)))
        sys.stdout.flush()
        time.sleep(0.2)

        
def _attack(charset_combined):

    if suppress_info == False:
        print(info)
        print("[+] Start Time: ", time.strftime('%H:%M:%S'))
        print("Charset: ",charset_combined)
        if user_name != "":
            print('User-Name:', user_name)
        print('Output-File:', output_file)   
        time.sleep(2.0)
        t = threading.Thread(target=animate)
        t.start()
    
    start_time = time.time()
    
    if random_length != 0:
        rsw = int(random_length,10)
        L = len(charset_combined)

        while 1:
            #112000 H/s
            if not use_postfix:
                #This is surprisingly faster
                random_string = user_name+''.join (
                    charset_combined[int(L * random.random())] 
                    for _ in range(rsw)
                    )
                #Than this
                #random_string = "%s%s" % (user_name,''.join (
                    #charset_combined[int(L * random.random())] 
                    #for _ in range(rsw))
                    #)
            else:
                #This is surprisingly faster
                random_string = ''.join ( 
                    charset_combined[int(L * random.random())] 
                    for _ in range(rsw)
                    ) + user_name
                #Than this
                #random_string = "%s%s" % (''.join (
                #charset_combined[int(L * random.random())] 
                #for _ in range(rsw)),user_name)
            
            # Put hashit() function definition instead of function call 
            # in here to increase the performance 1-2%
            hashit(random_string)
 
    else:
        brute_force_string=""
        for n in range(1, 31+1):
            if not suppress_info:
                print("\n[!] I'm at ", n , "-character")
          
            for xs in itertools.product(charset_combined, repeat=n):
                saved = ''.join(xs)
                brute_force_string = user_name+saved
                hashit(brute_force_string)
        

    
def hashit(hash_string):

    global hash_per_sec
    global total_pass_try
    global candidates_found
    global start_time
    global smallest_hexdigest    

    hashlib_type.update(bytes(hash_string, encoding='utf-8'))
    total_pass_try += 1
    if total_pass_try % 100000 == 0:
        elapsed_time_fl = (time.time() - start_time)
        start_time = time.time()
        hash_per_sec = 100000/elapsed_time_fl
    
    if (hashlib_type.hexdigest() < smallest_hexdigest and 
        (hashlib_type.hexdigest().isdecimal() or not digits_only)):
        smallest_hexdigest = hashlib_type.hexdigest()
        candidates_found += 1
        if not suppress_info:
            print('\n\n\nFound smaller hash!\n')
            print(smallest_hexdigest+':'+hash_string)
            print("\n[-] Time: ", time.strftime('%H:%M:%S'))
            print("[-] Keywords attempted: ", total_pass_try,'')
            print("[-] Candidates found: ", candidates_found,'\n')
        else:
            print(smallest_hexdigest+':'+hash_string)

        if output_file != '':
            f = open(output_file, "w")
            f.write(smallest_hexdigest+':'+hash_string)
            f.close()
    return

    
def print_help(msg):
    print('\n',msg,'\n')
    print("""Usage: python %s [options]
    Options Short/Long  | Type | Description
    ====================+======+=========================================
    -u, --user-name     | Str  | user-name works as pre- or postfix
    -c, --charset       | Num  | [-c ?] charset [0,1,2,3,4,5,6,7,8]
    -r, --random-length | Num  | length of random string [1-31]: 0 or not used for sequential brute force
    -m, --hash-type     | Num  | [-m ?] hash mode 0=MD5, 1400=SHA256, ...
    -o, --output-file   | Str  | output file for smallest hash
    -d, --digits-only   |      | when hash should only contain digits (0-9)
    -p, --post-fix      |      | selects if user-name should be postfix
    -s, --suppress-info |      | no info only hash:candidate pair, good for pipe
    """%sys.argv[0])
    return

    
def print_hashtypes():
    print("""Hash Modes - option [-m]
         # | Name         | Category
    =======+==============+=====================         
         0 | MD5          | Raw Hash
       100 | SHA1         | Raw Hash
       600 | BLAKE2b-512  | Raw Hash
      1300 | SHA2-224     | Raw Hash
      1400 | SHA2-256     | Raw Hash
      1700 | SHA2-512     | Raw Hash
     17300 | SHA3-224     | Raw Hash
     17400 | SHA3-256     | Raw Hash
     17500 | SHA3-384     | Raw Hash
     17600 | SHA3-512     | Raw Hash
    """)
    return

    
def print_charsets():
    print("""Character Sets - option [-c]
         # | Charset
    =======+=================================
         0 | %s
         1 | %s
         2 | %s
         3 | %s
         4 | %s
         5 | %s
         6 | %s
         7 | %s
         8 | %s         
    """%(string.ascii_letters+string.digits+string.punctuation,
    string.ascii_lowercase,
    string.ascii_uppercase,
    string.ascii_letters,
    string.digits,
    string.hexdigits,
    string.punctuation,
    string.ascii_letters+string.digits,
    string.printable.replace(' \t\n\r\x0b\x0c', '')
    ))
    return
    
def main(argv):
    
    global user_name
    global random_length
    global output_file
    global hashlib_type
    global digits_only
    global use_postfix
    global suppress_info
    opts=0
    hashtype=0
    charset=0

    try:
      opts, args = getopt.getopt(argv,"hu:c:r:o:m:dps",['help', 
                                                        'user-name=',
                                                        'charset=',
                                                        'random-length=',
                                                        'output-file=',
                                                        'hash-type=',
                                                        'digits-only',
                                                        'post-fix',
                                                        'surpress-info',
                                                        ])
    
    except getopt.error as msg:
        sys.stdout = sys.stderr
        #print_help(msg)

    if not opts:
        print("""Usage: python %s [options]
        Try -h, --help   for more help.
        """%sys.argv[0])
        sys.exit(2)
        
    for opt, arg in opts:
      if opt in ("-h", "--help"):
         print_help("")
         sys.exit()
      elif opt in ("-u", "--user-name"):
         user_name = arg
      elif opt in ("-c", "--charset"):
         charset = arg          
      elif opt in ("-r", "--random-length"):
         random_length = arg         
      elif opt in ("-o", "--output-file"):
         output_file = arg
      elif opt in ("-m", "--hash-type"):
         hashtype = arg
      elif opt in ("-d", "--digits-only"):
         digits_only = True
      elif opt in ("-p", "--post-fix"):
         use_postfix = True     
      elif opt in ("-s", "--surpress-info"):
         suppress_info = True     


    if charset == "0":
        charset_combined = (string.ascii_letters
                            + string.digits
                            + string.punctuation)
    elif charset == "1":
        charset_combined = string.ascii_lowercase
    elif charset == "2":
        charset_combined = string.ascii_uppercase
    elif charset == "3":
        charset_combined = string.ascii_letters
    elif charset == "4":
        charset_combined = string.digits
    elif charset == "5":
        charset_combined = string.hexdigits
    elif charset == "6":
        charset_combined = string.punctuation
    elif charset == "7":
        charset_combined = string.ascii_letters+string.digits
    elif charset == "8":
        charset_combined = string.printable.replace(' \t\n\r\x0b\x0c', '')
    elif charset == "?":
        print_charsets()
        sys.exit()        
    else:
        charset_combined = (string.ascii_letters
                            + string.digits 
                            + string.punctuation) 


    if hashtype == "0":
        hashlib_type = hashlib.md5()
    elif hashtype == "100":
        hashlib_type = hashlib.sha1()    
    elif hashtype == "600":
        hashlib_type = hashlib.blake2b()
    elif hashtype == "1300":
        hashlib_type = hashlib.sha224()
    elif hashtype == "1400":
        hashlib_type = hashlib.sha256()
    elif hashtype == "1700":
        hashlib_type = hashlib.sha512()      
    elif hashtype == "17300":
        hashlib_type = hashlib.sha3_224()
    elif hashtype == "17400":
        hashlib_type = hashlib.sha3_256()
    elif hashtype == "17500":
        hashlib_type = hashlib.sha3_384()        
    elif hashtype == "17600":
        hashlib_type = hashlib.sha3_512()
    elif hashtype == "?":
        print_hashtypes()
        sys.exit()
    else:
        print_help("option -m requires argument\n use [-m ?] for hash type list")
        sys.exit()    


    signal.signal(signal.SIGINT, signal_handler)
    return _attack(charset_combined)

if __name__ == "__main__":
    main(sys.argv[1:])
