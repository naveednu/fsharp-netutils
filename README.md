#F# network utilities


Collection of F# scripts to perform different tasks including whois, nslookup

###Usage

**whois** - Provide domain name as an argument to whois.fsx

`> fsi.exe whois.fsx google.com`

**nslookup** - Provide domain name and query type as arguments to nslookup.fsx *(supported query types are: A, NS, MX, CNAME)*

`> fsi.exe nslookup.fsx google.com MX`

`> fsi.exe nslookup.fsx yahoo.com A`

`> fsi.exe nslookup.fsx yahoo.com NS`




