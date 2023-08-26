# ProtoDNS
A work-in-progress basic DNS client and server written in Rust programming language for my enhancing my own understanding of DNS protocol. \\

A DNS message has : 
    [+] Header
    [+] Question
    [+] Response
    [+] Authority
    [+] Additional Space
    
\\
Header controls the contents of a DNS message, is of 12 bytes (2 x 6) and contains: 
    [+] Identification
    [+] Flags
    [+] No. of Questions
    [+] No. of Responses
    [+] No. of Authority RR (resource records)
    [+] No. of Additional RR 

\\
Question section in the DNS message contains 3 fields: 
    [+] QName -> domain name requested
    [+] QType -> Type of resource record requested  (A -> IPv4 address mapping, AAAA-> IPv6 address mapping, MX -> SMTP mail server for the domain)
    [+] QClass

\\
Rest of the 3 sections (Response, Authority, Additional Space) each contain RRs(possibly empty concatenated RRs) 
    [+] Response contains RRs that answer the question
    [+] Authority contains RRs that point toward an authoritative name server
    [+] Additional Space contains RRs which relate to the query but are not strictly answers to the question section

\\
Response Records (RRs) have the structure : 
    [+] Name
    [+] Type
    [+] Class
    [+] TTL
    [+] RDLength
    [+] RData

\\
So basically for a DNS message (both request and response), 3 different structures are to be defined 
    [+] Header
    [+] Question
    [+] RR
