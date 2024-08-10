# SMB3-Decryption

Special Thanks to @khr0x40sh (https://x.com/khr0x40sh) and his article on Medium (https://medium.com/maverislabs/decrypting-smb3-traffic-with-just-a-pcap-absolutely-maybe-712ed23ff6a2) for providing the idea and doing all the background research. I have merely adapted his Python code to Python3, also created a new file that calculates randomeSessionKey using NTLM hash in stead of password. 

## The idea : 
SMB3 encrypted traffic can be decrypted based on the information present in the captured packets, specifically, using SessionID and SessionKey values. 
However, the session key in the packet is encrypted session key and not the session key that can decrypt the traffic. 
To decrypt the traffic, we need to calculate the random session key by using information present in pcap and the lsass.dmp

## The method : 

Calculate Session Key
The Random Session Key could be calculated using:

-User’s password or NTLM hash  
-User’s domain  
-User’s username  
-NTProofStr  
-Key Exchange Key (Also known as the NTLMv2 Session Base Key)  
-Encrypted Session Key  

Pseudocode :   
-Unicode (utf-16le) of password  
-MD4 hash of the above **(This is also the NTLM Hash of the password)**  
-Unicode(utf-16le) and Uppercase of Username and Domain/Workgroup together   
-Calculating the ResponseKeyNT via HMAC_MD5(NTLM Hash, Unicode of User/Domain above)  
-NTProofStr (can be calculated but not needed as it is present in the PCAP)  
-Calculating the KeyExchangeKey via HMAC_MD5(ResponseKeyNT,NTProofStr)  
-Decrypt the Encrypted Session Key via RC4 and the Key Exchange Key to finally get the Random Session Key  

Example : 
user= “test”   
domain= “workgroup”  
password = “test”  
NTProofStr = a0e42a75c54bbb0fab814593569faa22  
EncryptedSessionKey = C914ADCEB0F1C32FB7C2548D8D959F01  
hash = MD4(password.encode(‘utf16-le’))  
hash is 0cb6948805f797bf2a82807973b89537  
ResponseKeyNT(HMAC_MD5(hash, (user.toUpper()+domain.toUpper()).encode(‘utf16-le’)))  
ResponseKeyNT is f31eb9f73fc9d5405f9ae516fb068315   
KeyExchangeKey=HMAC_MD5(ResponseKeyNT, NTProofStr)  
KeyExchangeKey is fd160d4ed7f2cb38f64262d7617f23b3  
RandomSessionKey = RC4(KeyExchangeKey,EncryptedSessionKey)  
RandomSessionKey is 4462b99bb21423c29dbb4b4a983fde03  


