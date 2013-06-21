open System.Net
open System.Net.Sockets
open System.Text


let dns = "8.8.8.8"
let Bytes2Int16 (x:byte[]) : int16 =  (int16 x.[0]<<<8||| int16 x.[1])

let rec parseQName (acc) (data:byte[]) (start:int) =
    let pos = start
    let len = int data.[pos]
    if len > 0 then
        if len = 192 then
            let result, _ = parseQName (acc) (data) (int data.[pos+1])
            result, (start+2)
        else
            let temp = data.[pos+1..pos+len]
            parseQName (acc + Encoding.ASCII.GetString([|for x in temp-> byte(x)|])+".") (data) (pos+len+1) 
    else
        acc.Trim([|'.'|]), (start+1)
    
type QueryType =
    | A = 1s
    | CNAME = 5s
    | MX = 15s
    
type Question = {
    Name: string;
    Type: int16;
    Class: int16;
}
        
type Answer(data:byte[], start:int) = 
    let name, pos = parseQName "" data start
    member x.QName = name
    member x.Type = Bytes2Int16 data.[pos..pos+1]
    member x.Class = Bytes2Int16 data.[pos+2..pos+3] 
    member x.TTL = int data.[pos+4]
    member x.RDLength = Bytes2Int16 data.[pos+8..pos+9]
    member x.RDStart = pos+10
   
    member this.print()=
        printfn "answer name = %s, type = %d, class = %d rlength =%d, rdstart = %d" (this.QName) this.Type this.Class this.RDLength this.RDStart
    member this.printRecord()=
        if this.Type = (int16)QueryType.MX then
            let name, _ = parseQName "" data (this.RDStart+2)
            printfn "Exchange: %s, Preference: %d" name (Bytes2Int16 data.[this.RDStart..this.RDStart+2])
        else if this.Type = (int16) QueryType.CNAME then
            let name, _ = parseQName "" data (this.RDStart)
            printfn "CNAME: %s" name
        else if this.Type = (int16) QueryType.A then
            printf "IP Address: "
            Array.iteri (fun i octet -> 
                          match i with
                          | 3 -> printf "%d\n" (int(octet))
                          | _ -> printf "%d." (int(octet))) data.[this.RDStart..this.RDStart+3]
                          
type ResponsePacket(data:byte[]) = 
    let mutable _ansPosition = 0
    member x.TransId =  Bytes2Int16 data.[0..1]
    member x.Flags = Bytes2Int16 data.[2..3]
    member x.Questions = Bytes2Int16 data.[4..5]
    member x.NumAnswers = Bytes2Int16 data.[6..7]
    member x.Authority = Bytes2Int16 data.[8..9]
    member x.Additional = Bytes2Int16 data.[10..11]
    
    member x.PrintDescription()=
        printfn "Questions = %d, Answers = %d TransId = %d" x.Questions x.NumAnswers x.TransId
        
    member x.GetQuestion() =
        let qname, pos = parseQName "" data 12
        let question = {Name=qname; Type = Bytes2Int16 data.[pos..pos+1]; Class = Bytes2Int16 data.[pos+2..pos+3]}
        _ansPosition <- pos+4
        question
    member x.GetAnswers()=
        let rec _gans (acc) (pos) (num) =
            if num > 0 then
                let answer = new Answer(data, pos)
                _gans (answer :: acc) (answer.RDStart+ int answer.RDLength) (num-1)
            else
                acc
        _gans [] _ansPosition (int x.NumAnswers)

let nslookup(domainName: string, queryType: QueryType) =   
    let udpClient = new UdpClient(dns, 53)
    
    let header = [ 14uy; 79uy; 1uy; 0uy; 0uy; 1uy; 0uy; 0uy; 0uy; 0uy; 0uy; 0uy ]
    let parts = domainName.Split('.')
    let domainParts = Array.fold (fun acc (x:string) -> acc @ [byte(x.Length)] @ [for y in x -> byte(y)]) [] parts
    let query = header @ domainParts @ [0uy; 0uy; byte(queryType); 0uy; 1uy;]
    udpClient.Send(List.toArray query, query.Length) |> ignore
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
    packet.PrintDescription()
    let question = packet.GetQuestion()
    printfn "Name = %s Type= %d Class = %d" question.Name question.Type question.Class
    for n in packet.GetAnswers() do
        n.printRecord()

nslookup("live.com", QueryType.MX)
    
