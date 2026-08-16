
# DB Schema

ID (PK)
IP Address
OS / Version NULL
Status (Open/Closed) DEFAULT Open
↓ (One Target can have many Sessions) ↓
SESSIONS
ID (PK)
Target_ID (FK)
Payload_ID (FK)
StartTime
Status
↑ (One Payload can be used in many Sessions) ↑
PAYLOADS
ID (PK)
Name
Code/Binary
Target_Arch
Notes
