
open System.Net.Sockets
open System.Text

let whois (domainName: string) : string =
    let whoisServer = "whois.verisign-grs.com"
    let client = new TcpClient(whoisServer, 43)
    let stream = client.GetStream()
    let bytes = Encoding.ASCII.GetBytes("domain " + domainName + "\r\n")
    stream.Write(bytes, 0, bytes.Length)
    stream.Flush()
    
    let rec reader (acc): string =
        let buf = Array.zeroCreate 512
        let bytesread = stream.Read(buf, 0, 512)
        if bytesread > 0 then
            reader (acc + Encoding.ASCII.GetString(buf))
        else
            acc
    reader ""
    
if fsi.CommandLineArgs.Length < 2 then
    printfn "Usage: %s <domain>" fsi.CommandLineArgs.[0]
    exit(0)
let domain = fsi.CommandLineArgs.[1]
printfn "%s" (whois domain)
