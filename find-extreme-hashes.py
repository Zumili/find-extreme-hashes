#usr/bin/python
import os
import time
import itertools
import string
import hashlib
import sys
import signal
import getopt
import random
import threading
import multiprocessing
from multiprocessing import Process
from ctypes import c_char_p

__version__ = '1.0.0'

info = """
  Name            : find-extreme-hashes.py
  Created By      : Thomas Messmer
  Blog            : http://thomas-messmer.com
  Documentation   : https://github.com/Zumili/find-extreme-hashes
  License         : The MIT License
  Version         : %s
""" % (__version__)

#TODO: Use "argparse" instead of "getopt" with ugly parameter test
#https://docs.python.org/3/howto/argparse.html

# Used to break all loops in processes and treads
done = False

class AttackConfig(object):
    id = 0
    user_name = ""
    hashlib_type_str = ""
    charset_combined = ""
    output_file = ""
    random_length = 0
    digits_only = 0
    use_postfix = False
    no_info = False
    find_small_hash = True
    find_big_hash = False
    bf_steps=0

    # The class "constructor" - It's actually an initializer 
    def __init__(self, id, user_name, hashlib_type_str,charset_combined,
                output_file,random_length,digits_only,use_postfix,
                no_info,find_small_hash,find_big_hash,bf_steps):
        self.id = id
        self.user_name = user_name
        self.hashlib_type_str = hashlib_type_str
        self.charset_combined = charset_combined
        self.output_file = output_file
        self.random_length = random_length
        self.digits_only = digits_only
        self.use_postfix = use_postfix
        self.no_info = no_info
        self.find_small_hash = find_small_hash
        self.find_big_hash = find_big_hash
        self.bf_steps = bf_steps

        
def signal_handler(signal, frame):

    global done
    done=True
    sys.exit(0)

def animate(mpa_hash_per_sec):
    
    for c in itertools.cycle(['|', '/', '-', '\\']):
        if done==True:
            break
        
        hash_per_sec_string = "H/s: "
        for i in range(len(mpa_hash_per_sec)):
            hash_per_sec_string = (hash_per_sec_string 
                                    + "(P" +str(i)+" "
                                    + str(mpa_hash_per_sec[i])+") ")
         
        sys.stdout.write('\r' + c + " " + hash_per_sec_string )
        sys.stdout.flush()
        time.sleep(0.2)
     

def _attack(attack_config,
            mpv_smallest_hexdigest, mpv_biggest_hexdigest,
            mpa_hash_per_sec_array,
            lock):
  
    smallest_hex = ("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
    biggest_hex =  ("00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000")

    smallest_candidate = ""
    biggest_candidate = ""
                          
    hash_per_sec = 0
    worker_passes = 0
    smaller_candidates_found = 0
    bigger_candidates_found = 0
    
    # Create local variables for performance increase!
    # Do not use attack_config.<element> in loops!
    charset_combined = attack_config.charset_combined
    output_file = attack_config.output_file
    random_length = attack_config.random_length
    digits_only = attack_config.digits_only
    use_postfix = attack_config.use_postfix
    user_name = attack_config.user_name
    id = attack_config.id
    hashlib_type_str = attack_config.hashlib_type_str
    find_small_hash = attack_config.find_small_hash
    find_big_hash = attack_config.find_big_hash
    no_info = attack_config.no_info
    bf_steps = attack_config.bf_steps
    
    start_time = time.time()
    
    # If random_length != 0 we use a randomized approach
    if random_length != 0:
        #rsw = int(random_length,10)
        L = len(attack_config.charset_combined)
        tmp_passes = 0
        while 1:
            #112000 H/s
            if not use_postfix:
                random_string = user_name+''.join (
                    charset_combined[int(L * random.random())] 
                    for _ in range(random_length)
                    )
            else:
                random_string = ''.join ( 
                    charset_combined[int(L * random.random())] 
                    for _ in range(random_length)
                    ) + user_name
            
            #worker_passes += 1
            #if worker_passes % 100000 == 0:
            # The following 4 lines should be slightly faster than 
            # the previous 2
            tmp_passes += 1
            if tmp_passes > 100000:
                tmp_passes = 0
                worker_passes += 100000
            
                elapsed_time_fl = (time.time() - start_time)
                start_time = time.time()
                hash_per_sec = int(100000/elapsed_time_fl)
                
                lock.acquire()
                mpa_hash_per_sec_array[id] = hash_per_sec
                lock.release()
                
                if done==True:
                    break
            
            # Even a bit more faster when leaving encoding string 
            #(python 3.x only)
            act_hash_hex = hashlib.new(hashlib_type_str,random_string
                                            .encode()).hexdigest()
            
            # Faster than using bytes       
            #act_hash_hex = hashlib.new(hashlib_type_str,random_string
                                            #.encode('utf-8')).hexdigest()
            
            # 10% slower
            #act_hash_hex = hashlib.new(hashlib_type_str,bytes(
                                              #random_string,
                                              #encoding='utf-8')
                                              #).hexdigest()
            
            if (find_small_hash and act_hash_hex < smallest_hex and 
                (not digits_only or act_hash_hex.isdecimal())):
                
                smallest_hex = act_hash_hex
                smaller_candidates_found += 1
                
                lock.acquire()
                if smallest_hex < mpv_smallest_hexdigest.get():
                    mpv_smallest_hexdigest.set(smallest_hex)
                    smallest_candidate = random_string
                    
                    print_found_info(id,"Smaller",smallest_hex,
                                    random_string,worker_passes,
                                    smaller_candidates_found,no_info)
                    
                    write_output(output_file,smallest_hex,
                                    smallest_candidate,
                                    biggest_hex,
                                    biggest_candidate)
                else:
                    smallest_hex = mpv_smallest_hexdigest.get()
                lock.release()
   
                
            
            elif (find_big_hash and act_hash_hex > biggest_hex and 
                (not digits_only or act_hash_hex.isdecimal())):
                
                biggest_hex = act_hash_hex
                bigger_candidates_found += 1
                
                lock.acquire()
                if biggest_hex > mpv_biggest_hexdigest.get():
                    mpv_biggest_hexdigest.set(biggest_hex)
                    biggest_candidate = random_string
                    
                    print_found_info(id,"Bigger",biggest_hex,
                                    random_string,worker_passes,
                                    bigger_candidates_found,no_info)
                    
                    write_output(output_file,smallest_hex,
                                    smallest_candidate,
                                    biggest_hex,
                                    biggest_candidate)
                else:
                    biggest_hex = mpv_biggest_hexdigest.get()
                lock.release()

    # If random_length not set we use a brute force approach
    else:
        brute_force_string = ""
        break_loop = False
        tmp_passes = 0
        for n in range(bf_steps, 47+1):
            if not no_info:
                print("\n[!] I'm at character %i"%n)
          
            for xs in itertools.product(charset_combined, repeat=n):
                saved = ''.join(xs)
                brute_force_string = user_name+saved
                
                #worker_passes += 1
                #if worker_passes % 100000 == 0:
                # The following 4 lines should be slightly faster than
                # the previous 2
                tmp_passes += 1
                if tmp_passes > 100000:
                    tmp_passes = 0
                    worker_passes += 100000
                    
                    elapsed_time_fl = (time.time() - start_time)
                    start_time = time.time()
                    hash_per_sec = int(100000/elapsed_time_fl)
                    
                    lock.acquire()
                    mpa_hash_per_sec_array[id] = hash_per_sec
                    lock.release()
                    
                    if done==True:
                        break_loop = True
                        break

                act_hash_hex = hashlib.new(hashlib_type_str,
                                                brute_force_string
                                                .encode()).hexdigest()

                if (find_small_hash and act_hash_hex < smallest_hex and 
                    (not digits_only or act_hash_hex.isdecimal())):

                    smallest_hex = act_hash_hex
                    smaller_candidates_found += 1
                    
                    lock.acquire()
                    if smallest_hex < mpv_smallest_hexdigest.get():
                        mpv_smallest_hexdigest.set(smallest_hex)
                        smallest_candidate = brute_force_string
                        
                        print_found_info(id,"Smaller",smallest_hex,
                                        brute_force_string,worker_passes,
                                        smaller_candidates_found,no_info)
                                        
                        write_output(output_file,smallest_hex,
                                        smallest_candidate,
                                        biggest_hex,
                                        biggest_candidate)

                    else:
                        smallest_hex = mpv_smallest_hexdigest.get()
                    lock.release()
                
                elif (find_big_hash and act_hash_hex > biggest_hex and 
                    (not digits_only or act_hash_hex.isdecimal())):

                    biggest_hex = act_hash_hex
                    bigger_candidates_found += 1
                    
                    lock.acquire()
                    if biggest_hex > mpv_biggest_hexdigest.get():
                        mpv_biggest_hexdigest.set(biggest_hex)
                        biggest_candidate = brute_force_string
                        
                        print_found_info(id,"Bigger",biggest_hex,
                                        brute_force_string,worker_passes,
                                        bigger_candidates_found,no_info)
                                        
                        write_output(output_file,smallest_hex,
                                        smallest_candidate,
                                        biggest_hex,
                                        biggest_candidate)
                    else:
                        biggest_hex = mpv_biggest_hexdigest.get()
                    lock.release()
            
            if break_loop:
                break



def write_output(output_file,smallest_hex,smallest_candidate,
                biggest_hex,biggest_candidate):
    
    if output_file != '':
        f = open(output_file, "w")
        if smallest_candidate != "":
            f.write(smallest_hex+':'+smallest_candidate+'\n')
        if biggest_candidate != "":
            f.write(biggest_hex+':'+biggest_candidate)
        f.close()


    return
                

def print_found_info(id,hash_type_str,hexdigest,candidate,worker_passes,
                    candidate_found,no_info):
    
    if no_info == False:
        print('\n\n\n'+hash_type_str+' Hash in P%i\n' % id)
        print(hexdigest+':'+candidate)
        print("\n[|] Time: ", time.strftime('%H:%M:%S'))
        print("[|] Keywords attempted: ", worker_passes,'')
        print("[|] Candidates found: ", candidate_found,'\n') 
    else:
        print(hexdigest+':'+candidate)
    
    return    
    
def print_help(msg):
    print_options(msg)
    
def print_options(msg):
    print(msg)
    print("""Usage: python %s [options]
    
 Options Short/Long  | Type | Description
=====================+======+==========================================
 -m, --hash-type     | Num  | [-m ?] hash mode e.g. 0=MD5, 1400=SHA256
 -c, --charset       | Num  | [-c ?] charset [0,1,2,...,custom]
 -r, --random-length | Num  | [-r ?] length of rand str or brute force
 -f, --find-mode     | Num  | [-f ?] find 0=small 1=big 2=small and big
 -d, --digits-only   |      | hash must only contain digits (0-9)
 -u, --user-name     | Str  | user-name works as pre- or postfix
 -p, --post-fix      |      | selects if user-name should be postfix
 -o, --output-file   | Str  | output file for found extreme hashes
 -n, --no-info       |      | only hash:candidate pair, good for pipe
 -w, --worker        | Num  | [-w ?] worker count, minimum 1 worker
 -e, --exclude-chars | Str  | string of characters removed from charset
 -b, --bf-steps      | Num  | [-b ?] brute force step size if worker >1
 -s, --shuffle       |      | shuffle final charset
 """%sys.argv[0])
    return

def print_bf_steps_info():    
    print("""Brute Force Steps - option [-b <steps>]
    
  If 1 worker used, brute force starts at pos <steps>+1.
  If more workers used e.g. [-w 3] brute force starts at:
  1*<steps>+1 for 1. worker.
  2*<steps>+1 for 2. worker.
  3*<steps>+1 for 3. worker.
  ...and so on...
  """)
    return
    

def print_random_length_info():    
    print("""Random Length and Brute Force Selector - option [-r <length>]
    
  If used e.g. [-r 8] it defines the length of random string used
  to create the hash.
  If [-r 0] or [not used] it sets internal mode to brute force.
  Possible length of string is [1-31].
  """)
    return

def print_find_mode_info():    
    print("""Find Mode - option [-f <mode>]
    
          # | Find Mode
============+=================================
  [not used]| Find only smaller hashes.  
  [-f 0]    | Find only smaller hashes. 
  [-f 1]    | Find only bigger hashes.
  [-f 2]    | Find both, bigger and smaller hashes.
  """)
    return
    
    
def print_worker_count_info():
    print("""Worker Count - option [-w <worker>]
    
  [-w 0], [-w 1] or [not used] always use 1 worker
  Maximum worker count depends on maximum cpu count!
  Max Cpu Count: %i
  """%int(multiprocessing.cpu_count()))
    return

def print_user_name_info():
    print("""User Name - option [-w <user-name>]
    
  Must contain at least 3 characters!
  """)
    return
    
def print_output_file_info():
    print("""Output File - option [-w <out-file>]
    
  Must contain at least 3 charaters!
    """)
    return    

def print_hashtypes():
    tmp_list = list(hashlib.algorithms_guaranteed)
    tmp_list.sort() # sorts normally by alphabetical order
    tmp_list.sort(key=len) # sorts by length
    tmp_str ='\n   '.join(tmp_list)
    print("Hash Modes - option [-m <mode>]")
    print("\nAvailable hashing algortihms:\n")
    print("  ",tmp_str)
    
    return
    
# def print_hashtypes():
    # print("""Hash Modes - option [-m <mode>]
    
    # Mode # | Name         | Category
    # =======+==============+=====================         
         # 0 | MD5          | Raw Hash
       # 100 | SHA1         | Raw Hash
       # 600 | BLAKE2b-512  | Raw Hash
      # 1300 | SHA2-224     | Raw Hash
      # 1400 | SHA2-256     | Raw Hash
      # 1700 | SHA2-512     | Raw Hash
     # 17300 | SHA3-224     | Raw Hash
     # 17400 | SHA3-256     | Raw Hash
     # 17500 | SHA3-384     | Raw Hash
     # 17600 | SHA3-512     | Raw Hash
    # """)
    # return

def break_long_string(long_string,break_index):
    tmp_string = (long_string[:break_index]+'\n        '
                 + long_string[break_index:])
    return tmp_string
    
def print_charsets():
    print("""Character Sets - option [-c <set>]
    
    # | Charset
======+=================================
    0 | %s
    1 | %s
    2 | %s
    3 | %s
    4 | %s
    5 | %s
    6 | %s
    7 | %s
    8 | %s
  Str | use individual string as charset e.g. [-c 123abcABC]
    """%(string.ascii_lowercase,
        string.ascii_uppercase,
        string.ascii_letters,
        string.digits,
        string.hexdigits,
        string.punctuation,
        string.ascii_letters+string.digits,
        break_long_string(string.printable
                        .replace(' \t\n\r\x0b\x0c', ''),62),
        break_long_string(string.ascii_letters+string.digits
                         + string.punctuation,62)
    ))
    return

def print_examples():
    print(""" Examples
    
    # | Command / Description
======+=================================
    1 | Start simple brute force with standart charset 0 and MD5 algo
      | python find-extreme-hash.py -m 0
      | --------------------------------
    2 | Use MD5, charset 5 (digits), add a prefix <USER> and shuffle 
      | charset
      | python find-extreme-hash.py -m 0 -c 5 -u <USER> -s
      | --------------------------------
    3 | Use SHA1, charset 1 (lowercase), find only biggest and no info
      | python find-extreme-hash.py -m 100 -c 1 -f 1 -n
      | --------------------------------
      | More exmaples on https://github.com/Zumili/find-extreme-hashes  
""")


    
def main(argv):

    assert sys.version_info >= (3, 0)
    #assert sys.hexversion < 0x03030000

    opts=0
    args=0
   
    #read variables
    user_name = ""
    charset=""
    random_length = 0
    hashtype=""
    output_file = ""
    digits_only = 0
    use_postfix = False
    no_info = False
    find_mode=0
    exclude_chars = ""
    bf_steps=0
    shuffle = False

    #created variables
    charset_combined = ""
    hashlib_type_str = "md5"
    find_small_hash = True
    find_big_hash = False
   
    total_passes = 0
    worker_count = 1
    
    #global variable 
    smallest_hex_g =  ("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
    
    #global variable
    biggest_hex_g =   ("00000000000000000000000000000000"
                           "00000000000000000000000000000000"
                           "00000000000000000000000000000000"
                           "00000000000000000000000000000000")
    
    try:
      opts, args = getopt.getopt(argv,"hu:c:r:o:m:dpnf:w:e:b:s",['help', 
                                                        'user-name=',
                                                        'charset=',
                                                        'random-length=',
                                                        'output-file=',
                                                        'hash-type=',
                                                        'digits-only',
                                                        'post-fix',
                                                        'no-info',
                                                        'find-mode=',
                                                        'worker=',
                                                        'exclude-chars=',
                                                        'bf-steps=',
                                                        'shuffle',
                                                        'examples',
                                                        ])
    
    except getopt.error as msg:
        sys.stdout = sys.stderr
        print_help(msg)
        sys.exit(2)

    if not opts:# and not args:
        print("Usage: python %s [options]...\n"%sys.argv[0])
        print("Try -h, --help for more help.")
        sys.exit(2)
        
    for option_key, option_value in opts:
      if option_key in ("-h", "--help"):
         print_help("")
         sys.exit()
      elif option_key in ("-u", "--user-name"):
         user_name = option_value
      elif option_key in ("-c", "--charset"):
         charset = option_value          
      elif option_key in ("-r", "--random-length"):
         random_length = option_value         
      elif option_key in ("-o", "--output-file"):
         output_file = option_value
      elif option_key in ("-m", "--hash-type"):
         hashtype = option_value
      elif option_key in ("-d", "--digits-only"):
         digits_only = True
      elif option_key in ("-p", "--post-fix"):
         use_postfix = True     
      elif option_key in ("-n", "--no-info"):
         no_info = True     
      elif option_key in ("-f", "--find-mode"):
         find_mode = option_value
      elif option_key in ("-w", "--worker"):
         worker_count = option_value
      elif option_key in ("-e", "--exclude-chars"):
         exclude_chars = option_value
      elif option_key in ("-b", "--bf-steps"):
         bf_steps = option_value
      elif option_key in ("-s", "--shuffle"):
         shuffle = True      
      elif option_key in ("--examples"):
         print_examples()
         sys.exit()

    # Test hashtype parameter
    if hashtype == "?":
        print_hashtypes()
        sys.exit()
    elif hashtype.lower() in hashlib.algorithms_guaranteed:
        hashlib_type_str = hashtype.lower()
    else:
        #print_help("\noption -m requires argument\n"
        #           + " use [-m ?] for hash type list")
        print_hashtypes()
        sys.exit()  

    # Test charset parameter
    if charset == "0":
        charset_combined = string.ascii_lowercase
    elif charset == "1":
        charset_combined = string.ascii_uppercase
    elif charset == "2":
        charset_combined = string.ascii_letters
    elif charset == "3":
        charset_combined = string.digits
    elif charset == "4":
        charset_combined = string.hexdigits
    elif charset == "5":
        charset_combined = string.punctuation
    elif charset == "6":
        charset_combined = string.ascii_letters+string.digits
    elif charset == "7":
        charset_combined = string.printable.replace(' \t\n\r\x0b\x0c', '')
    elif charset == "8":
        charset_combined = (string.ascii_letters
                            + string.digits
                            + string.punctuation)        
    elif charset == "9":
        charset_combined = string.ascii_letters+string.punctuation
    elif charset == "?":
        print_charsets()
        sys.exit()        
    elif charset != "":
        charset_combined = charset
    else:
        charset_combined = string.ascii_lowercase

        
    if exclude_chars != "":
        charset_combined = charset_combined.translate(
                               {ord(i): None for i in exclude_chars}
                               )

    if shuffle:
        l = list(charset_combined)
        random.shuffle(l)
        charset_combined = ''.join(l)

    # Test user_name parameter
    #print("user_name: ",user_name)
    #if not ((user_name[-1] == "\"" or user_name[-1] == "'") 
        #and (user_name[0] == "\"" or user_name[0] == "'")):
        #print_charsets()
    if user_name == "?":
        print_user_name_info()
        sys.exit()        
    elif user_name != "" and len(user_name) < 3:
        print_user_name_info()
        sys.exit()

    # Test output_file parameter     
    if output_file == "?":
        print_output_file_info()
        sys.exit()        
    elif output_file != "" and len(output_file) < 3:
        print_output_file_info()
        sys.exit()    

    # Test find_mode parameter    
    if find_mode == "?":
        print_find_mode_info()
        sys.exit()
    else:
        try:
            find_mode = int(find_mode)
            if find_mode not in range(0, 2+1):
                sys.exit()
        except:
            print_find_mode_info()
            sys.exit()
    if find_mode == 0:
        find_small_hash = True
        find_big_hash = False
    elif find_mode == 1:
        find_small_hash = False
        find_big_hash = True
    elif find_mode == 2:
        find_small_hash = True
        find_big_hash = True
    

    cpu_count = multiprocessing.cpu_count()  

    # Test worker_count parameter
    if worker_count == "?":
        print_worker_count_info()
        sys.exit()
    else:
        try:
            worker_count = int(worker_count)
            if worker_count not in range(1, cpu_count+1):
                #worker_count = 1
                sys.exit()
        except:
            #worker_count = 1
            print_worker_count_info()
            sys.exit()

    # Print a warning if all cpu processors are used
    if worker_count == cpu_count and not no_info:
        print("""\n                    WARNING !!!
  Using all cores will slow down everything else on your computer.
        """)
        a = input("Start anyway? Use y/Y for YES n/N for NO! ")
        if not (a == 'y' or a == 'Y' or a == 'yes' 
                or a == 'Yes' or a == 'z' or a == 'Z'):
            sys.exit()
            
   
    # Test bf_steps parameter
    if bf_steps == "?":
        print_bf_steps_info()
        sys.exit()
    else:
        try:
            bf_steps = int(bf_steps)
            if bf_steps not in range(0, 12+1):
                #print_bf_steps_info()
                sys.exit()
        except:
            print_bf_steps_info()
            sys.exit()

    
    # Test random_length parameter
    if random_length == "?":
        print_random_length_info()
        sys.exit()
    else:
        try:
            random_length = int(random_length)
            if random_length not in range(0, 31+1):
                #random_length = 0
                sys.exit()
        except:
            #random_length = 0
            print_random_length_info()
            sys.exit()
    
    
    # If brute force mode and no steps, only use one worker
    if random_length == 0 and bf_steps == 0:
        worker_count = 1
    
    
    # Create "lock", "manager" and "managed elements" for multiprocessing
    lock = multiprocessing.Lock()
    manager = multiprocessing.Manager()
    mpv_smallest_hexdigest = manager.Value(c_char_p,smallest_hex_g)
    mpv_biggest_hexdigest  = manager.Value(c_char_p,biggest_hex_g)
    mpa_hash_per_sec = manager.Array('i', range(worker_count))
    
    
        
    if no_info == False:
        print(info)
        print("[+] Start Time: ", time.strftime('%H:%M:%S'))
        print("[|] Charset: ",charset_combined)
        if user_name != "":
            print('[|] User-Name:', user_name)
        if output_file != "":            
            print('[|] Output-File:', output_file)  
    
  
    signal.signal(signal.SIGINT, signal_handler)
    
    # If info is not suppressed, start new thread 
    # to show H/s for each worker
    if no_info == False:
        time.sleep(1.0)
        t = threading.Thread(target=animate, args=(mpa_hash_per_sec,))
        t.start()

    # Create jobs array for workers
    jobs = []
    
    # Start selected amount of workers and append them to jobs array
    for i in range(0, (worker_count)):

        attack_config = AttackConfig(i, 
                                    user_name, hashlib_type_str,
                                    charset_combined, output_file,
                                    random_length, 
                                    digits_only, use_postfix, no_info,
                                    find_small_hash, find_big_hash,
                                    (i+1)*bf_steps)
        
        p = Process(target=_attack, args=(attack_config, 
                                          mpv_smallest_hexdigest,
                                          mpv_biggest_hexdigest,
                                          mpa_hash_per_sec,
                                          lock,))

        jobs.append(p)
        p.start()
        if no_info == False:
            print("Starting worker",(i))
    
    # Join all processes to wait for there termination
    for i in range(0, (worker_count)):
        jobs[i].join()
    # Alternative, do nothing and sleep a bit
    #while not done:
        #time.sleep(0.1)
        #pass

    

if __name__ == "__main__":
    main(sys.argv[1:])
    