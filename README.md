# find-smallest-hash-py3
Find the smallest hash of a specific type like MD5, SHA1 and more in python 3.x.

## How to install?

`git clone https://github.com/Zumili/Python-Find-Smallest-Hash`

## How to run?

`python find-smallest-hash-py3.py -h`

```bash
Options Short/Long      | Type | Description
    ====================+======+========================================= 
    -u, --user-name     | Str  | user-name works as pre- or postfix  
    -c, --charset       | Num  | [-c ?] charset [0,1,2,3,4,5,6,7,8]  
    -r, --random-length | Num  | length of random string [1-31]: 0 or not used for sequential brute force  
    -m, --hash-type     | Num  | [-m ?] hash mode 0=MD5, 1400=SHA256, ...  
    -o, --output-file   | Str  | output file for smallest hash  
    -d, --digits-only   |      | when hash should only contain digits (0-9)  
    -p, --post-fix      |      | selects if user-name should be postfix  
    -s, --surpress-info |      | no info only candidate, good for pipe  
```


Show hash types  
`python find-smallest-hash-py3.py -m ?`

Show charsets  
`python find-smallest-hash-py3.py -c ?`

### Examples

Finding the smallest MD5 hash (-m 0) with a brute force approach  
`python find-smallest-hash-py3.py -m 0`

Finding the smallest SHA1 hash (-m 100) with a randomized approach, adding a user-name as prefix and a random string with the length of 8 (-r 8)  
`python find-smallest-hash-py3.py -m 100 -u <USER-NAME> -r 8`

Finding the smallest BLAKE2B hash (-m 600) with a randomized approach, adding a user-name as postfix (-p) and a random string with the length of 12 (-r 12) with charset 4 [digits] (-c 4)  
`python find-smallest-hash-py3.py -m 100 -u <USER-NAME> -p -r 12 -c 4`

Finding the smallest SHA-256 hash (-m 1400) which only contains digits (-d) and write the smallest hash:plain pair to a file (-o OUTPUT.txt)  
`python find-smallest-hash-py3.py -m 1400 -d -o OUTPUT.txt`

Finding the smallest SHA-512 hash (-m 1700) with randomized approach with a random string with the length of 8, charset 3 [ascii_letters] and suppress all additional information (-s) except for the hash:plain pair and pipe that into a file  
`python find-smallest-hash-py3.py -m 1700 -r 8 -c 3 -s > OUTPUT.txt`

## Version
1.0

## License
[The MIT License](https://opensource.org/licenses/MIT)

## Who?
Written by Thomas Messmer ([thomas-messmer.com](http://thomas-messmer.com)) for scientific purposes only.
