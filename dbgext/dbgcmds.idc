#include <idc.idc>

/*
dbgcmds IDC script v1.05 - written by Dennis Elser
---------------------------------------------------
This is an IDC script for the
Disassembler IDA Pro by Datarescue.


What does the script do?
------------------------
The script extends the IDA debugger by useful commands,
but it can also be used on a regular database (idb).

See 'supported commands' for detailed usage
and examples.

history:
--------
  13.04.2004 - initial release
  16.04.2004 - bugfixes, added dumpseg() and dumpsegs()
  19.04.2004 - saveregs(), loadregs(), fillmem() and help() added


usage:
------
Load and compile the IDC script (dbgcmds.idc).
Run the debugger and suspend the process.
Select the 'File>IDC command' menu and enter
any command supported by this script.


Supported commands:
-------------------

dumpmem(filename, address, size)
		dumps "size" bytes starting at "address" to "filename"

patchmem(filename, address)
		patches memory starting at "address" with the contents
		of "filename"

dumpseg(filename,segname)
		dumps a whole segment named "segname" to "filename"

dumpsegs(path)
		dumps all available segments to "path"

saveregs(filename)
		saves all the standard x86 registers to a file
		(including Eflags)

loadregs(filename)
		restores all the standard x86 registers from a file
		(including Eflags)

fillmem(address, count, character)
		fills memory starting at "address" with "count" number of
		"character"s
		
help()
		display list of all supported commands
		

Examples:
---------
dumpmem("c:\\dump.bin",0x401000,0x100);

This command will dump 0x100 bytes starting at address 0x401000
to the file c:\dump.bin

patchmem("c:\\dump.bin",0x401000);

This command will patch memory of a running process starting
at address 0x401000 with the contents of c:\dump.bin


*/



static help()
{
	Message("\n"
	"command:                              example:\n"
	"----------------------------------------------------------------------------------\n"
	"dumpmem(filename, address, size)    - dumpmem(\"c:\\\\dump.bin\", Esp, 0x10);\n"
	"patchmem(filename, address)         - patchmem(\"c:\\\\dump.bin\", 0x401000);\n"
	"dumpseg(filename,segname)           - dumpseg(\"c:\\\\codesegment.bin\", \".text\");\n"
	"dumpsegs(path)                      - dumpsegs(\"c:\\\\\");\n"
	"saveregs(filename)                  - saveregs(\"c:\\\\registers.bin\");\n"
	"loadregs(filename)                  - loadregs(\"c:\\\\registers.bin\");\n"
	"fillmem(address, count, character)  - fillmem(0x402000, 0x50, \'x\');\n"
	"help()                              - help();\n\n"
	);
	
	return;
}

static fillmem(address, count, character)
{
	auto ea;
	
	for(ea=address;ea<address+count;ea++)
	{
		PatchByte(ea,character);
	}
	return;
}

static loadregs(filename)
{
	auto fp;
	auto temp_efl;

	if( !fileexist(filename) )
	{
		Message("loadregs() ERROR: File does not exist!\n");
		return;
	}
	fp=fopen(filename,"rb");
	if(fp==0)
	{
		Message("saveregs() ERROR: File could not be opened!\n");
		return;
	}
	// I think readlong() doesn't support any errorhandling :-(
	// No need to check for errors in writelong() then ;-)
	Eax=readlong(fp,0);
	Ebx=readlong(fp,0);
	Ecx=readlong(fp,0);
	Edx=readlong(fp,0);
	Esi=readlong(fp,0);
	Edi=readlong(fp,0);
	Ebp=readlong(fp,0);
	Esp=readlong(fp,0);
	Eip=readlong(fp,0);
	temp_efl=readlong(fp,0);
	SetRegValue(temp_efl,"Efl");		//temporary
	fclose(fp);
	Message("saveregs() SUCCESS: Registers loaded from %s\n",filename);
}

static saveregs(filename)
{
	auto fp;

	if( fileexist(filename) )
	{
		Message("saveregs() ERROR: File exists!\n");
		return;
	}
	fp=fopen(filename,"wb");
	if(fp==0)
	{
		Message("saveregs() ERROR: File could not be created!\n");
		return;
	}
	writelong(fp,Eax,0);
	writelong(fp,Ebx,0);
	writelong(fp,Ecx,0);
	writelong(fp,Edx,0);
	writelong(fp,Esi,0);
	writelong(fp,Edi,0);
	writelong(fp,Ebp,0);
	writelong(fp,Esp,0);
	writelong(fp,Eip,0);
	writelong(fp,GetRegValue("Efl"),0);	//temporary
	Message("saveregs() SUCCESS: File saved to %s\n",filename);
	fclose(fp);
}

static dumpsegs(path)
{
	auto i;
	auto filename;
	
	for(i=0;i<GetSegQty();i++)
	{
		//Message("%08X %s (%d)\n",GetSegEA(i),SegName(GetSegEA(i)),i);
		filename=path+"\\"+SegName(GetSegEA(i));
		dumpseg(filename,SegName(GetSegEA(i)));
	}
}

static dumpseg(filename,segname)
{
	auto segstart;
	auto segend;
	auto seglen;
	
	segstart = GetSegByName(segname);
	segend = SegEnd(segstart);
	seglen = segend - segstart;
	
	//Message("%x %x %x\n",segstart, segend, seglen);
	dumpmem(filename, segstart, seglen);
	return;
}


static dumpmem(filename, ea, size)
{
	auto fp;
	auto maxea;
	auto data;

	maxea = ea+size;
	
	if(fileexist(filename))
	{
		Message("dumpmem() ERROR: File exists!\n");
		return;
	}
	
	fp=fopen(filename,"wb");
	if(fp==0)
	{
		Message("dumpmem() ERROR: File could not be created!\n");
		return;
	}
	
	for(ea;ea<maxea;ea++)
	{
		if(!hasValue(GetFlags(ea))) Message("dumpmem() WARNING: Byte at %08X undefined!\n",ea);
		data=Byte(ea);
		fputc(data,fp);
	}
	fclose(fp);
	Message("dumpmem() SUCCESS! %s\n",filename);
}

static patchmem(filename, ea)
{
	auto fp;
	auto maxea;
	auto data;

	data=0;

	if(!fileexist(filename))
	{
		Message("patchmem() ERROR: File does not exist!\n");
		return;
	}
	
	fp=fopen(filename,"rb");
	if(fp==0)
	{
		Message("patchmem() ERROR: File could not be opened!\n");
		return;
	}
	
	maxea = ea+filelength(fp);

	for(ea;ea<maxea;ea++)
	{
		if(!hasValue(GetFlags(ea)))
		{
			Message("patchmem() WARNING: Byte at %08X undefined!\n",ea);
		}
		//Message("%08X\n",ftell(fp));
		data=fgetc(fp);
		if(data==-1)
		{
			Message("patchmem() WARNING: Could not read from file at %08X!\n",ftell(fp));
		}
		else PatchByte(ea,data);
	}
	fclose(fp);
	Message("patchmem() SUCCESS! %s\n",filename);
}

static fileexist(filename)
{
	auto fp;

	fp=fopen(filename,"rb");
	if(fp!=0)
	{
		fclose(fp);
		return 1;
	}
	return 0;
}

static GetSegByName(segname)
{
	auto ea;

	for(ea=MinEA(); ea <= MaxEA(); ea++)
	{
		if(SegName(ea)==segname) return ea;
	}
return BADADDR;
}

static GetSegQty()
{
	auto ea;
	auto segqty;
	
	segqty=0;
	ea = FirstSeg();

	if(ea==BADADDR) return segqty;
	
	segqty++;
	while(ea!=BADADDR)
	{
		ea=NextSeg(ea);
		if(ea!=BADADDR) segqty++;
	}
	return segqty;
}

static GetSegEA(index) //0 till GetSegQty()-1
{
	auto i;
	auto ea;
	
	ea = FirstSeg();
	if(index==0) return ea;
	
	for(i=1;i<=GetSegQty();i++)
	{
		ea = NextSeg(ea);
		if(i==index) return ea;
	}
	return BADADDR;
}