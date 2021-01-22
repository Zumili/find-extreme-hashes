# find-extreme-hashes
A CPU-based tool to find the smallest or biggest hash of a specific type like MD5, SHA1 and more in python > 3.6.
```bash
  Name            : find-extreme-hashes.py
  Created By      : Thomas Messmer
  Blog            : http://thomas-messmer.com
  Documentation   : https://github.com/Zumili/find-extreme-hashes
  License         : The MIT License
  Version         : 1.0.0
```

## How to install?

`git clone https://github.com/Zumili/find-extreme-hashes`

## How to run?

`python find-extreme-hashes.py -h`

```bash
 Options Short/Long  | Type | Description
 ====================+======+=========================================  
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
```


Show hash types  
`python find-extreme-hashes.py -m ?`

Show charsets  
`python find-extreme-hashes.py -c ?`

### Examples

Finding the smallest (-f 0 or NOT USED!) MD5 hash (-m md5) with a brute force approach (-r NOT USED!).  
`python find-extreme-hashes.py -m md5`

Finding the biggest (-f 1) SHA1 hash (-m sha1) with a randomized approach, adding a user-name as prefix and a random string with the length of 8 (-r 8).  
`python find-extreme-hashes.py -m sha1 -u <USER-NAME> -f 1 -r 8`

Finding the smallest BLAKE2B hash (-m blake2b) with a randomized approach, adding a user-name as postfix (-p) and a random string with the length of 12 (-r 12) with charset 3 [digits] (-c 3).  
`python find-extreme-hashes.py -m blake2b -u <USER-NAME> -p -r 12 -c 4`

Finding the smallest and biggest (-f 2) SHA256 hash (-m sha256) which only contains digits (-d) and write the hash:plain pairs to a file (-o OUTPUT.txt).  
`python find-extreme-hashes.py -m sha256 -d -f 2 -o OUTPUT.txt`

Finding the smallest SHA512 hash (-m sha512) with randomized approach with a random string with the length of 8, charset 2 [ascii_letters] and suppress all additional information (-n) except for the hash:plain pair and pipe that into a file.  
`python find-extreme-hashes.py -m sha512 -r 8 -c 3 -n > OUTPUT.txt`

Finding the smallest MD5 hash, with brute force mode (-r NOT USED!) using charset 4 (-c 4) containing "0123456789abcdefABCDEF" and excluding "abcdef" (-e abcdef) from that charset. Final charset is then: "0123456789ABCDEF".  
`python find-extreme-hashes.py -m md5 -c 4 -e abcdef`

Finding smallest SHA256 hash (-m sha256) with custom charset (-c Thequickbrownfxjmpsvtlazydg) and no info (-n) with 3 workers (-w 3) and a brute force step size for each worker of 6 characters (-b 6).  
`python find-extreme-hashes.py -m sha256 -c Thequickbrownfxjmpsvtlazydg -n -w 3 -b 6` 

### Running in background

You can also run the script in background with using e.g. (nohup) at the beginning of line and (>& /dev/null &) at the end to prevent any output file from being created.
`nohup python3.7 find-extreme-hashes.py -m md5 -r 10 -c 6 -w 2 -u <USER-NAME> -o OUTPUT.txt -n >& /dev/null &`

To stop the processes created with nohub use:
`jobs`
`[1] + Running nohup python find-extreme-hashes.py ... <options> ...`
`kill %1`

## Version
1.0

## License
[The MIT License](https://opensource.org/licenses/MIT)

## Who?
Written by Thomas Messmer ([thomas-messmer.com](http://thomas-messmer.com)) for scientific purposes only.
