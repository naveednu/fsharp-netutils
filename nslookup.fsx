open System.Net
open System.Net.Sockets
open System.Net.NetworkInformation
open System.Text

let getLocalDns =
    let res = NetworkInterface.GetAllNetworkInterfaces()
              |> Seq.map (fun (ifs) -> 
                           Set.ofSeq ((ifs.GetIPProperties().DnsAddresses) 
                           |> Seq.map (fun x -> x.ToString())))
                        
    let addresses = res |> Set.unionMany
    addresses |> Seq.head

let Bytes2Int16 (x:byte[]) : int16 =  (int16 x.[0]<<<8||| int16 x.[1])

let rec parseQName (acc) (data:byte[]) (start:int) =
    let pos = start
    let len = int data.[pos]
    if len > 0 then
        if len = 0xC0 then
            let result, _ = parseQName (acc) (data) (int data.[pos+1])
            result, (start+2)
        else
            let temp = data.[pos+1..pos+len]
            parseQName (acc + Encoding.ASCII.GetString([|for x in temp-> byte(x)|])+".") (data) (pos+len+1) 
    else
        acc, (start+1)
    
type QueryType =
    | A = 1s
    | NS = 2s
    | CNAME = 5s
    | MX = 15s
    
type Question = {
    Name: string;
    Type: int16;
    Class: int16;
}
        
type Answer(data:byte[], start:int) = 
    let name, pos = parseQName "" data start
    member x.QName = name.TrimEnd([|'.'|])
    member x.Type = Bytes2Int16 data.[pos..pos+1]
    member x.Class = Bytes2Int16 data.[pos+2..pos+3] 
    member x.TTL = int data.[pos+4]
    member x.RDLength = Bytes2Int16 data.[pos+8..pos+9]
    member x.RDStart = pos+10
   
    member x.print()=
        printfn "answer name = %s, type = %d, class = %d rlength =%d, rdstart = %d" (x.QName) x.Type x.Class x.RDLength x.RDStart
    member x.printRecord()=
        let qtype = QueryType.ToObject(typeof<QueryType>, x.Type) :?> QueryType
        match qtype with
        | QueryType.MX -> 
            let exchange, _ = parseQName "" data (x.RDStart+2)
            printfn "%s\tmail exchanger = %d %s" x.QName (Bytes2Int16 data.[x.RDStart..x.RDStart+2]) exchange
        | QueryType.NS ->
            let nameServer, _ = parseQName "" data (x.RDStart)
            printfn "%s\tnameserver = %s" x.QName nameServer
        | QueryType.CNAME ->
            let cname, _ = parseQName "" data (x.RDStart)
            printfn "%s    canonical name = %s" x.QName cname
        | QueryType.A ->
            printfn "Name:   %s" x.QName
            printf "Address: "
            Array.iteri (fun i octet -> 
                          match i with
                          | 3 -> printf "%d\n" (int(octet))
                          | _ -> printf "%d." (int(octet))) data.[x.RDStart..x.RDStart+3]
        | _ -> printfn "Invalid type"
                          
type ResponsePacket(data:byte[]) = 

    let mutable _ansPosition = 0
    do 
        let qname, pos = parseQName "" data 12
        let question = {Name=qname; Type = Bytes2Int16 data.[pos..pos+1]; Class = Bytes2Int16 data.[pos+2..pos+3]}
        _ansPosition <- pos+4

    member x.TransId =  Bytes2Int16 data.[0..1]
    member x.Flags = Bytes2Int16 data.[2..3]
    member x.NumQuestions = Bytes2Int16 data.[4..5]
    member x.NumAnswers = Bytes2Int16 data.[6..7]
    member x.Authority = Bytes2Int16 data.[8..9]
    member x.Additional = Bytes2Int16 data.[10..11]
    
    member x.PrintDescription()=
        printfn "Questions = %d, Answers = %d TransId = %d" x.NumQuestions x.NumAnswers x.TransId
        

    member x.GetAnswers()=
        let rec _gans (acc) (pos) (num) =
            if num > 0 then
                let answer = new Answer(data, pos)
                _gans (answer :: acc) (answer.RDStart+ int answer.RDLength) (num-1)
            else
                acc
        _gans [] _ansPosition (int x.NumAnswers)

let buildQuery (domain:string) (queryType:QueryType) =
    let header = [ 14uy; 79uy; 1uy; 0uy; 0uy; 1uy; 0uy; 0uy; 0uy; 0uy; 0uy; 0uy ]
    let parts = domain.Split('.')
    let domainParts = Array.fold (fun acc (x:string) -> acc @ [byte(x.Length)] @ [for y in x -> byte(y)]) [] parts
    let query = header @ domainParts @ [0uy; 0uy; byte(queryType); 0uy; 1uy;]
    query |> List.toArray

let nslookup(domainName: string, queryType: QueryType) = 
    let dnsServer = getLocalDns  
    let udpClient = new UdpClient(dnsServer, 53)
    let query = buildQuery domainName queryType
    
    udpClient.Send(query, query.Length) |> ignore
    let ipe = new IPEndPoint(IPAddress.Any, 0)
    let result = udpClient.Receive(ref ipe)
      
    let response = [|for x in result -> int(x)|]
    if response.[3] <> 128 then
        printfn "Invalid response"
        exit(0)
    let mutable answers = response.[7]
    if answers = 0 then 
        printfn "No answers in response."
        exit(0)
    
    let packet = new ResponsePacket(result)
    for n in packet.GetAnswers() do
        n.printRecord()

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
| _ -> printfn "Unknwon query specificed"

