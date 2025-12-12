# BitlockerInfo
C++ code demonstrating how to extract the Bitlocker recovery key

This simple project demonstrates how to extract the Bitlocker recovery key programmatically.  This program does the same thing as "manage-bde -status" and "manage-bde -protectors -get <drive>" from the command line.

It works by calling the undocumented full volume encryption (FVE) APIs.  The APIs and flags had to be reverse-engineering so I cannot guarantee they are totally accurate.  Use for educational purposes only.

Sample output:

`Drive C:`  
`  Status: encrypted and activated`  
`  Drive ID: {1D7C3E92-6671-4170-B6F3-DFECACDE91F7}`  
`  Recovery key: 123456-123456-123456-123456-123456-123456-123456-123456`  
`Drive D:`  
`  Status: encrypted with clear-text password`  
`  Drive ID: {A0E38946-B891-4829-8E65-744442A06A87}`  
`  Recovery key: 123456-123456-123456-123456-123456-123456-123456-123456`  

This code also works on "device encryption" which is the limited form of Bitlocker found on "Home" versions of Windows.
