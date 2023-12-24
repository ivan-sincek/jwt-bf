# JWT BF

Brute force a JWT token. Script uses multithreading.

Tested on Kali Linux v2023.4 (64-bit).

Made for educational purposes. I hope it will help!

## How to Run

Open your preferred console from [/src/](https://github.com/ivan-sincek/jwt-bf/tree/main/src) and run the commands shown below.

Install required packages:

```fundamental
pip3 install -r requirements.txt
```

Run the script:

```fundamental
python3 jwt_bf.py
```

## Usage

```fundamental
JWT BF v2.2 ( github.com/ivan-sincek/jwt-bf )

Usage:   python3 jwt_bf.py -w wordlist    -t token       [-th threads]
Example: python3 jwt_bf.py -w secrets.txt -t xxx.yyy.zzz [-th 50     ]

DESCRIPTION
    Brute force a JWT token
WORDLIST
    Wordlist to use
    Spacing will be stripped, empty lines ignored, and duplicates removed
    -w <wordlist> - secrets.txt | etc.
TOKEN
    JWT token to crack
    -t <token> - xxx.yyy.zzz | etc.
THREADS
    Number of parallel threads to run
    Wordlist will be split equally between threads
    Default: 10
    -th <threads> - 50 | etc.
```