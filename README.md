Hell's Gate VX Technique originally develop by :

 Paul Laîné (@am0nsec)<br>
 smelly__vx (@RtlMateusz)
 

 Link to the original paper: https://vxug.fakedoma.in/papers/VXUG/Exclusive/HellsGate.pdf
 PDF also included in this repository.

 Overview :

 
  1   The first step is to access to the Thread Environment Block (TEB) <br>
  2   From there, access the PEB<br>
  3   Go through the PEB and get the base address from ntdll.dll<br>
  4   Access the EAT from ntdll.dll<br>
  5   Use djb2 hashing on all native functions in the code<br>
  6   Hash the function names retrieved from EAT using the djb2 algorithm<br>
  7   Compare the hashed function names with the hashed entries in EAT<br>
  8   If they match, store the function address in VX_TABLE as VX_TABLE_ENTRY<br>
  9   Based on the (absolut) function address, do an opcode comparison of the syscall stub<br>
      from the native functions in ntdll.dll to check if the function is hooked or not<br>
  10  Additionally, based on checking the opcodes for the syscall and return instruction,<br> 
      if they are not too far apart to avoid executing a wrong native function or syscall.<br>
  11  Use the HellsGate function to prepare the execution of a direct syscall.<br>
  12  Use the HellDescent function to proceed the execution of a direct syscall<br>


  Modification :
  
   Now this Poc performs process injection using Hellsgate VX technique, takes PID through 
   command line argument
   Usage : Hellsgate.exe <PID>.

  Please note:
  
   I am not claiming that this technique is develop by me or any thing else, I already refer 
   original authors.<br>
   I did this for learning purpose, I prefer modification to understand technique in detailed 
   form.<br>
   And finial words this code is not enough to bypass modern-day EDR/AV you have to comeup with 
   new ideas like Encryption , obfuscation etc<br>
 
