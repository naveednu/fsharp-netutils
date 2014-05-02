#load "dns.fs"
open DNS

if fsi.CommandLineArgs.Length < 3 then
    printfn "Usage: %s <domain> <query>" fsi.CommandLineArgs.[0]
    exit(0)
    
let domain = fsi.CommandLineArgs.[1]
let query = fsi.CommandLineArgs.[2]

match query.ToLower() with
| "mx" -> nslookup(domain, QueryType.MX)
| "a" -> nslookup(domain, QueryType.A)
| "cname" -> nslookup(domain, QueryType.CNAME)
| "ns" -> nslookup(domain, QueryType.NS)
| "aaaa" -> nslookup(domain, QueryType.AAAA)
| "any" -> nslookup(domain, QueryType.ANY)
| _ -> printfn "Unknwon query specificed"

