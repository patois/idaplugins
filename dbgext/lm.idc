/*
LawnMower IDC script v1.0 - written by Dennis Elser
---------------------------------------------------
This is an IDC script for the
Disassembler IDA Pro by Datarescue.
The script needs IDA Pro v4.6 SP1
or above!

What does the script do?
------------------------
The script is meant to be used in vulnerability
research by parsing user supplied input.
IDA's tracing mode will cause the currently
debugged program to pause after each instruction.
This is where the script comes into play:
It checks if any register is pointing
to a string matching the string supplied
by the user (both ascii and unicode strings).
It then creates a little .lmf file in your IDA directory,
supplying (hopefully) valuable information.
You can also tell the script to pause the automatic
tracer in order to inspect the code immediately.


history:
--------
  07.04.2004 - initial release




usage:
------
The script can only be used with the integrated
debugger in IDA 4.60 SP1 and above!

Usage is as follows:

Go to the 'Stop condition' field in the menu
'Debugger > Tracing > Tracing options..' and
enter:

lm(userstring,condition)

where 'userstring' is a string to look for and
'condition' is either '0' or '1'.
'0' means, the script will let the debugger
continue after each condition met
'1' means, the script will cause the debugger to
pause/halt after each condition met and you'll be able to
examine the code immediately.


Example usage:
--------------
Let's say you are examining an ftpd which you
suspect to contain a buffer overflow vulnerability
in its string-handling routines:

1. Load the ftpd into IDA.
2. Run the process using IDA's integrated
   debugger.
3. Pause the running process.
4. Specify a stop condition like:
   lm("PWD",1).
5. Enable 'instruction tracing" in IDA.
6. Resume the process.
7. Connect to the running ftpd using an
   ftp client.
8. Send "PWD" over the ftp client to the
   ftpd.
9. IDA will pause the running ftpd as soon
   as any register is pointing to the "PWD" string.
   You'll most probably land in or near a routine that
   parses user input (your "PWD" string), ready
   to be examined.



Credits go to Greg Hoglund and Gary McGraw
(I picked up your idea of parsing user input
from your book
"Exploiting Software - How to break code")
and to Ilfak Guilfanov for providing help
with the IDC language
--------------------------------------------------------

*/







//LEVEL = recursion/dereference depth
//the higher the number of levels is, the slower
//the IDA tracer will be.
//LEVEL = 1 should fit all your needs
//  *(esp)   would be LEVEL 0
//*(*(esp))  would be LEVEL 1
//and so on...
#define LEVEL	1



//********************
//*
//*      MAIN
//*
//********************

// lm() is the main function to call
// as explained in the 'usage' section
// of this script
static lm(s,condition)
{
auto triggered;
auto addr;
auto fhandle;

auto reg_eax;
auto reg_ebx;
auto reg_ecx;
auto reg_edx;
auto reg_esi;
auto reg_edi;
auto reg_ebp;
auto reg_esp;


reg_eax="   ";
reg_ebx="   ";
reg_ecx="   ";
reg_edx="   ";
reg_esi="   ";
reg_edi="   ";
reg_ebp="   ";
reg_esp="   ";

triggered=0;

  if( (addr=IsPointerTo(Eax,s,LEVEL)) != 0 )
  {
    reg_eax="eax";
    triggered=1; 
    //return condition;
  }
  if( (addr=IsPointerTo(Ebx,s,LEVEL)) != 0 )
  {
    reg_ebx="ebx";
    triggered=1;
    //return condition;
  }
  if( (addr=IsPointerTo(Ecx,s,LEVEL)) != 0 )
  {
    reg_ecx="ecx";
    triggered=1;
    //return condition;
  }
  if( (addr=IsPointerTo(Edx,s,LEVEL)) != 0 )
  {
    reg_edx="edx";
    triggered=1;
    //return condition;
  }
  if( (addr=IsPointerTo(Esi,s,LEVEL)) != 0 )
  {
    reg_esi="esi";
    triggered=1;
    //return condition;
  }
  if( (addr=IsPointerTo(Edi,s,LEVEL)) != 0 )
  {
    reg_edi="edi";
    triggered=1;
    //return condition;
  }
  if( (addr=IsPointerTo(Ebp,s,LEVEL)) != 0 )
  {
    reg_ebp="ebp";
    triggered=1;
    //return condition;
  }
  if( (addr=IsPointerTo(Esp,s,LEVEL)) != 0 )
  {
    reg_esp="esp";
    triggered=1;
    //return condition;
  }
  if(triggered)
  {
    Message("%08X: %s %s %s %s %s %s %s %s -> %s\n",
    	Eip,
    	reg_eax,
    	reg_ebx,
    	reg_ecx,
    	reg_edx,
    	reg_esi,
    	reg_edi,
    	reg_ebp,
    	reg_esp,
    	GetDisasm(Eip));
    	
    fhandle=fopen(BuildFilename(),"a+");
    fprintf(fhandle,"%08X: %s %s %s %s %s %s %s %s -> %s\n",
    	Eip,
    	reg_eax,
    	reg_ebx,
    	reg_ecx,
    	reg_edx,
    	reg_esi,
    	reg_edi,
    	reg_ebp,
    	reg_esp,
    	GetDisasm(Eip));
    fclose(fhandle);
    return condition;
  }
  return 0;
}


static BuildFilename()
{
  return GetIdaDirectory() + "\\" + GetInputFile() + ".lmf";
}

//returns !=0 if 'reg' is a pointer
//to the user supplied string 's'
// returns 0 otherwise
//'level' is the number of indirect
//pointers to scan for in a loop
static IsPointerTo(reg,s,level)
{
auto pStr;
auto i;

pStr=reg;
for(i=0;i<=level;i++)
{
  if( Compare(pStr,s,strlen(s)) )
    return pStr;
  pStr=Dword(pStr);
}
return 0;
}


//compares strings (both ASCII and UNICODE)
//returns 1 if strings match
//        0 if they mismatch
static Compare(str1,str2,len)
{
   if( StrCmp(str1,str2,len)  || UniStrCmp(str1,str2,len) )
   {
     return 1;
   }
   return 0;
}

//ASCII string comparison / bytewise
//returns 0 if strings mismatch
//        1 if strings match
static StrCmp(str1,str2,len)
{
  auto i;
  auto ascii;
  
  ascii = GetString(str1,len);
  
  for(i=0;i<len;i++)
  {
    //Message("%s",Byte(reg));
    if( Index(ascii,i) != Index(str2,i) ) return 0;
  }
  return 1;
}

//returns the string 'reg' is pointing to
static GetString(reg,len)
{
  auto s;
  auto i;
  
  s="";
  for(i=0;i<len;i++) s=s+Byte(reg+i);
  
  return s;
}

//returns the index'th character
static Index(s,index)
{
  return substr(s, index, index+1);
}

//Compares a unicode string with an
//ascii string.
//str1 is expected to be a unicode string,
//str2 is expected to be an ascii string.
//returns 0 if strings mismatch
//        1 if strings match
static UniStrCmp(str1,str2,len)
{
  auto i;
  auto x;
  auto ascii;
  
  ascii=Unicode2Ascii(str1,len);
 
  for(i=0;i<len;i++)
  {
    if( Index(ascii,i) != Index(str2,i) ) return 0;
  }
  return 1;
}


//converts a unicode string to an ascii
//string
//str1 is expected to be a unicode string
//returns the converted ascii string
static Unicode2Ascii(str1,len)
{
  auto s;
  auto i;
  
  s="";
  for(i=0;i<(len*2);i++)
  {
  	if(Byte(str1+i)!='0') s=s+Byte(str1+i);
  }
  
  return s;
  
}