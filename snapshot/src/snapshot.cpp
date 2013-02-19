//////////////////////////////////////////////////
//
//  Snapshot! plugin for IDA PRO
//  written by Dennis Elser.
// 
//  -------------------------------------------
//
//	This plugin creates a snapshot of a
//	running process on your harddisk, which
//	can later be restored again.
//	You can also analyse and compare different
//	dumps.
//
//
//	-------------------------------------------
//
//	history:
//	--------
//	-	10.10.2004:
//		initial version
//
//
//	(c) 2004, Dennis Elser
//
//////////////////////////////////////////////////


#include <ida.hpp>
#include <idp.hpp>
#include <expr.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <dbg.hpp>
#include <kernwin.hpp>
#include <diskio.hpp>


const char dlg[] =							//Taken from J.C.Roberts' Examples, thanks!
    "STARTITEM 0\n"
    "HELP\n"                                                    // Help
    "This plugin can create a snapshot of the current process\n"             
    "and revert to this state at a later point of time.\n"
    "ENDHELP\n"

    "Snapshot!\n"                                       // Title
    "Snapshot! plugin by Dennis Elser.\n\n"                    // Dialog Text

    " Please select\n"                                               // Dialog Text
     //  Group #1 Radio Buttons NOTE: using capital "R"
    "<#Create a snapshot of the current process.#"               // hint radio0
    "Create a snapshot:R>"                                 // text radio0

    "<#Create a complete dump of the current process.#"               // hint radio0
    "Create a complete snapshot:R>"                                 // text radio0

    "<#Revert to a previous state.#"               // hint radio1
    "Revert:R>>\n\n\n\n\n"                      // text radio1
    
    ; // End Dialog Format String




uchar *free_data(uchar *mem)
{
	if(mem!=NULL) free(mem);
	return NULL;
}


uchar *get_segment_data(ea_t s_a, ea_t e_a, ea_t size)
{
	int i;
	uchar *mem;

	mem = (uchar *)malloc(size+1);
	
	get_many_bytes(s_a,mem,size);
	return mem;
	for(i=s_a;i<=e_a;i++)
	{
		mem[i-s_a]=get_byte(i);
	}
	return mem;
}

uchar *get_file_data(FILE *file, ea_t size)
{
	uchar *mem;

	mem = (uchar *)malloc(size+1);
	eread(file,mem,size);
	return mem;
}


int getsegsize(segment_t *segment)
{
	return (segment->endEA - segment->startEA);
}

ea_t getreg(char *regname)
{
	regval_t eip;
	get_reg_val(regname,&eip);
	return eip.ival;
}

void setreg(const char *regname, ea_t regval)
{
	set_reg_val(regname, regval);
}

bool save_reg(char *filename)
{
	FILE *reg;
	ea_t regval;
	char regfile[MAXSTR];

	strcpy(regfile,filename);

	strcat(regfile,".reg");

	reg = fopenWB(regfile);
	ewrite(reg, &(regval=getreg("eax")),sizeof(ea_t));
	ewrite(reg, &(regval=getreg("ebx")),sizeof(ea_t));
	ewrite(reg, &(regval=getreg("ecx")),sizeof(ea_t));
	ewrite(reg, &(regval=getreg("edx")),sizeof(ea_t));
	ewrite(reg, &(regval=getreg("esi")),sizeof(ea_t));
	ewrite(reg, &(regval=getreg("edi")),sizeof(ea_t));
	ewrite(reg, &(regval=getreg("ebp")),sizeof(ea_t));
	ewrite(reg, &(regval=getreg("esp")),sizeof(ea_t));
	ewrite(reg, &(regval=getreg("eip")),sizeof(ea_t));
	ewrite(reg, &(regval=getreg("efl")),sizeof(ea_t));
	eclose(reg);

	return true;
}


bool load_reg(char *filename)
{
	FILE *reg;
	ea_t regval;
	char regfile[MAXSTR];

	strcpy(regfile,filename);

	if(hasExt(regfile) != NULL)
		strcpy ((char *)hasExt(regfile),"reg");

	reg = fopenRB(regfile);

	eread(reg, &regval,4);
	setreg("eax",regval);
	eread(reg, &regval,4);
	setreg("ebx",regval);
	eread(reg, &regval,4);
	setreg("ecx",regval);
	eread(reg, &regval,4);
	setreg("edx",regval);
	eread(reg, &regval,4);
	setreg("esi",regval);
	eread(reg, &regval,4);
	setreg("edi",regval);
	eread(reg, &regval,4);
	setreg("ebp",regval);
	eread(reg, &regval,4);
	setreg("esp",regval);
	eread(reg, &regval,4);
	setreg("eip",regval);
	eread(reg, &regval,4);
	setreg("efl",regval);

	eclose(reg);

	return true;
}

bool save_cfgdata(char *filename, bool dumpall)
{
	segment_t *curseg;
	int segqty;
	ea_t i;
	FILE *cfg;
	FILE *snp;
	uchar *segdata;
	char cfgfile[MAXSTR];
	char snpfile[MAXSTR];


	strcpy(cfgfile,filename);
	strcpy(snpfile,filename);

	strcat(cfgfile,".cfg");
	strcat(snpfile,".snp");

	cfg = fopenWB(cfgfile);
	snp = fopenWB(snpfile);

	segqty = get_segm_qty();
	for(i=0;i<segqty;i++)
	{
		curseg = getnseg(i);
		if( (curseg->perm & SEGPERM_WRITE) && (curseg->perm & SEGPERM_READ) )
		{
			msg("Saving %s [%08X %08X]...",get_true_segm_name(curseg),curseg->startEA,curseg->endEA);
			ewrite(cfg, &curseg->startEA,sizeof(curseg->startEA) );
			ewrite(cfg, &curseg->endEA,sizeof(curseg->endEA) );
			segdata = get_segment_data(curseg->startEA, curseg->endEA, getsegsize(curseg));
			ewrite(snp, segdata, getsegsize(curseg));
			free_data(segdata);
			msg("done\n");
		}
		else if(dumpall)
		{
			msg("Saving %s [%08X %08X]...",get_true_segm_name(curseg),curseg->startEA,curseg->endEA);
			ewrite(cfg, &curseg->startEA,sizeof(curseg->startEA) );
			ewrite(cfg, &curseg->endEA,sizeof(curseg->endEA) );
			segdata = get_segment_data(curseg->startEA, curseg->endEA, getsegsize(curseg));
			ewrite(snp, segdata, getsegsize(curseg));
			free_data(segdata);
			msg("done\n");
		}
	}
	eclose(cfg);
	eclose(snp);
	return true;
}


bool is_segment(ea_t start_address, ea_t end_address)
{
	segment_t *curseg;
	int segqty;
	int i;

	segqty = get_segm_qty();
	for(i=0;i<segqty;i++)
	{
		curseg = getnseg(i);
		if( (curseg->perm & SEGPERM_WRITE) && (curseg->perm & SEGPERM_READ) )
		{
			if(start_address == curseg->startEA && end_address == curseg->endEA)
			{
				return true;
			}
		}

	}
	return false;

}

bool eof(FILE *file)
{
	if(qftell(file) == efilelength(file))
		return true;

	return false;
}


int get_probs_qty(char *filename)
{
	long offset=0;
	ea_t size;
	FILE *cfg;
	int probs=0;
	ea_t start_address;
	ea_t end_address;

	cfg = fopenRB(filename);

	while(!eof(cfg))
	{
		eread(cfg,&start_address,4);
		eread(cfg,&end_address,4);
		size = end_address-start_address-1;
		
		if(!is_segment(start_address, end_address))
		{	
			probs++;
		}
		offset+=size;
	}
	eclose(cfg);
	return probs;
}

bool load_cfgdata(char *filename)
{
	//ea_t i;
	FILE *cfg;
	FILE *snp;
	ea_t start_address;
	ea_t end_address;
	long offset=0;
	ea_t size;
	uchar *mem;
	char snpfile[MAXSTR];

	strcpy(snpfile,filename);

	if(hasExt(snpfile ) != NULL)
		strcpy((char *)hasExt(snpfile),"snp");

	cfg = fopenRB(filename);
	snp = fopenRB(snpfile);

	while(!eof(cfg))
	{
		eread(cfg,&start_address,4);
		eread(cfg,&end_address,4);
		size = end_address-start_address;
		
		msg("Restoring %s [%08X %08X]...",get_true_segm_name(getseg(start_address)),start_address,end_address);
		if(is_segment(start_address, end_address))
		{	
			eseek(snp,offset);
			mem = get_file_data(snp,size);
			put_many_bytes(start_address,mem, size);
			/*
			for(i=start_address;i<end_address;i++)
			{
				patch_byte(i,(ulong)*(mem+(i-start_address)));
			//	msg("%X\n",*(mem+(i-start_address)));
			}*/
			free_data(mem); 
			msg("done!\n");
		}
		else
		{
			msg("failure!\n");
		}
		//msg("startaddress: %08X ofs: %08X size: %08X\n",start_address,offset,size);
		offset+=size;
	}

	eclose(cfg);
	eclose(snp);
	return true;
}


bool revert_to_snapshot(char *filename)
{
	int x;

	if( (x=get_probs_qty(filename))>0)
	{
		if ( askyn_c(1,"There were %d mismatches. Restore state anyway?\n",x) != 1)
			return false;
	}
	load_cfgdata(filename);
	load_reg(filename);
	msg("Previous state restored!\n");
	return true;
}

bool make_snapshot(char *filename, bool dumpall)
{
	save_cfgdata(filename,dumpall);
	save_reg(filename);
	msg("Snapshot saved!\n");
	return true;
}

int idaapi init(void)
{
  if ( inf.filetype == f_ELF ) return PLUGIN_SKIP;

  return PLUGIN_KEEP;
}


void idaapi term(void)
{

}

void idaapi run(int arg)
{
	int status=0;
	char *answer;
	char filename[MAXSTR];

	if(get_process_state() == 0)
	{
		msg("This plugin can only take a snapshot of a running process!\n");
		return;
	}


	if ( AskUsingForm_c(dlg,&status) == 0)
	{
		msg("aborted.\n");
		return;
	}
	switch(status)
	{
	case 0:
		answer = askfile_cv(1,NULL,"Enter a filename for the snapshot:",0);
		if(answer == NULL)
		{
			msg("aborted.\n");
			return;
		}
		strncpy(filename,answer,MAXSTR-strlen(".ext")+1);
		make_snapshot(filename,false);
		break;
	case 1:
		answer = askfile_cv(1,NULL,"Enter a filename for the snapshot:",0);
		if(answer == NULL)
		{
			msg("aborted.\n");
			return;
		}
		strncpy(filename,answer,MAXSTR-strlen(".ext")+1);
		make_snapshot(filename,true);
		break;
	case 2:
		answer = askfile_cv(0,"*.cfg","Open a snapshot file:",0);
		if(answer == NULL)
		{
			msg("aborted.\n");
			return;
		}
		strncpy(filename,answer,MAXSTR-strlen(".ext")+1);
		revert_to_snapshot(filename);
		break;
	}
}

//--------------------------------------------------------------------------
char comment[] = "Snapshot! plugin by Dennis Elser";

char help[] =
        "This plugin can create a snapshot of the current process\n";

//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overriden in plugins.cfg file

char wanted_name[] = "Snapshot!";


// This is the preferred hotkey for the plugin module
// The preferred hotkey may be overriden in plugins.cfg file
// Note: IDA won't tell you if the hotkey is not correct
//       It will just disable the hotkey.

char wanted_hotkey[] = "Alt-5";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  0,                    // plugin flags
  init,                 // initialize

  term,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  help,                 // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
