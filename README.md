# rpz_processor
Straightforward Response Policy Zone processor with allow-listing

## Example Usage

Retrieve the wildcard main block list from Hagezi, 
converting it into an RPZ with no allow-list:

```commandline
main.py -c wildcards -a - -u https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/multi.txt -o herp.rpz
```

Retrieve the domain block list from Hagezi, again
converting it into an RPZ with no allow-list:

```commandline
main.py -c domains -a - -u https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/multi.txt -o herp.rpz
```
