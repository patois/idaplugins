//////////////////////////////////////////////////
//
//  EPF - Entry-Point-Finder plugin for IDA PRO
//  written by Dennis Elser.
// 
//  -------------------------------------------
//
//	This plugin tries to find the
//	Original Entrypoint of a packed/crypted
//	Windows PE Executable.
//	
//
//	N.B.: Since the plugin single-steps through
//	the code, it can take a while to find the
//	Entrypoint. It also strongly depends on the
//	speed of your cpu and on the size of the code.
//	Be also sure to use IDA 4.7 at least!
//
//	Anti-Debugging isn't taken care of, but you
//	are "holding sourcecode in your hands" !
//
//	You might also have figured out that you
//	can do other useful things (starting)
//	with this release of the plugin.
//	If - for example - an address of a string
//	is known to you, but you have no idea
//	where in the binary it is being processed,
//	you can track it down using the option
//	"Trace until any register holds a specific value".
//	
//	-------------------------------------------
//
//	(c) Dennis Elser 
//
//	-------------------------------------------
//
//	history:
//	--------
//	-	05.10.2004:
//		initial version
//
//	-	10.10.2004
//		added new detection method and
//		combobox dialog
//	-	30.10.2004
//		minor speed improvements
//		added progress status
//	-	03.11.2004
//		implemented some new options:
//		- trace until specific mnemonic
//		- trace until register holds value
//		- trace until any register holds value
//		- visually track eip
//
//
//	(c) 2004, Dennis Elser
//
//////////////////////////////////////////////////


#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <dbg.hpp>

#define MAX_STR 260


//function prototype(s)
ea_t get_reg_val(char *regname);
void toggle_tracer(void);
void set_tracer_internal_state(bool state);
//-------------------------------------------------------------


//global constants
const char *onoff[]={"off","on"};
const char *registers[]={"eax","ebx","ecx","edx","esi","edi","ebp","esp","eip"};
const short CHKBX_0001 = 0x0001;        // First Check Box
/*
const short CHKBX_0002 = 0x0002;        // Second Check Box
const short CHKBX_0003 = 0x0004;        // Third Check Box
const short CHKBX_0004 = 0x0008;        // Fourth Check Box
const short CHKBX_0005 = 0x0010;
*/

//The dialogs were made with the help of
//J.C.Roberts' excellent examples, thanks you!
const char dlg[] =
    "STARTITEM 0\n"
    "HELP\n"                                                    // Help
    "EPF - Entry Point Finder\n\n"
	"The plugin's intention is to find the original entry point\n"             
    "of a packed/crypted PE executable (or any file which can be\n"
	"run using IDA's built in debugger).\n\n"
	"The plugin comes with full sourcecode.\n"
	"Parts (the dialogs) of the code have been adapted\n"
	"from J.C.Roberts' excellent examples.\n"
	"The author of EPF can be reached at dennis(at)backtrace(dot)de\n"
    "ENDHELP\n"

    "Entrypoint Finder\n"                                       // Title
    "Entrypoint Finder plugin by Dennis Elser.\n\n"                    // Dialog Text

    " Please select\n"                                               // Dialog Text
     //  Group #1 Radio Buttons NOTE: using capital "R"
    "<#Choose this option if the target section is unknown.#"               // hint radio0
    "Trace until EIP reaches a different section:R>"                                 // text radio0

    "<#Choose this option if the target area is known.#"               // hint radio1
    "Trace until EIP reaches a specific memory area:R>"

    "<#Please enter a mnemonic below.#"               // hint radio1
    "Trace until EIP reaches a specific mnemonic:R>"

    "<#Please enter a register and value below.#"               // hint radio1
    "Trace until a register holds a specific value:R>"

    "<#Please enter a value below.#"               // hint radio1
    "Trace until any register holds a specific value:R>>\n\n\n\n\n\n\n"

	"<#Enter an *exact* mnemonic-string here.#"
	"Mnemonic :A:255:32:::>\n"                      // text radio1

 	"<#Enter a register (eax, ebx..) here.#"
	"Register :A:255:32:::>\n"                      // text radio1
   
	"<#Enter a value here.#"
	"Value    :A:255:32:::>\n"                      // text radio1

	"<#Tracking Eip gives a nice visual effect but slows down!#"
	"Track Eip           :C>>\n\n"

    ; // End Dialog Format String
//-------------------------------------------------------------


//global vars
bool b_switch=false;
char seg[MAXSTR];
int status=0;
ea_t start_address;
ea_t end_address;

char mnem[MAX_STR]="popa";
char temp[MAX_STR];

char reg[MAX_STR]="eax";
char value[MAX_STR]="0xDEADBEEF";

ea_t reg_val;
bool b_trackEip=false;

//-------------------------------------------------------------



void toggle_tracer(void)
{
	char *segname;
	short checkbox;

	if(!b_switch)
	{
		checkbox = (short)(b_trackEip * CHKBX_0001);
		if ( AskUsingForm_c(dlg,&status,&mnem, &reg, &value, &checkbox) == 0)
		{
			msg("-> EPF: aborted.\n");
			return;
		}
		
		b_trackEip = (bool)(checkbox & CHKBX_0001);

		switch(status)
		{
		case 0:
			segname = get_segm_name(get_reg_val("eip"));
			if(segname!=NULL)
			{
				strncpy(seg,segname,MAXSTR-1);
			}
			break;
		case 1:
			if (askaddr(&start_address,"Please enter start address:\n") == 0)
			{
				msg("-> EPF: aborted.\n");
				return;
			}

			if (askaddr(&end_address,"Please enter end address [inclusive]:\n") == 0)
			{
				msg("-> EPF: aborted.\n");
				return;
			}
			break;
/*		case 2:
			break;*/
		case 3:
		case 4:
			if ( !str2ea(value, &reg_val, get_screen_ea()) ||
				 !atoea(value, &reg_val))
			{
				msg("-> EPF: %s is not a valid value (use \"0x\" for HEX values)!\n",value);
				return;
			}
			break;
		}
		
	}
	b_switch^=1;
	enable_step_trace(b_switch);
	msg("-> EPF is now %s\n",onoff[b_switch]);
	if( b_switch ) msg ("-> EPF: Please resume the process now!\n");
}
//-------------------------------------------------------------


void set_tracer_internal_state(bool state)
{
	b_switch=state;
	msg("-> EPF is now %s\n",onoff[b_switch]);
}
//-------------------------------------------------------------


//(personal comment)
//dbg.hpp has the following function, which I might use
//in future versions of this plugin
//bool idaapi get_reg_val(const char *regname, regval_t *regval);
ea_t get_reg_val(char *regname)
{
	regval_t eip;
	get_reg_val(regname,&eip);
	return eip.ival;
}
//-------------------------------------------------------------


static int idaapi dbg_callback(void * /*user_data*/, int event_id, va_list /*va*/)
{
	ea_t eip;
	int i;

	if(!b_switch) return 0;
	
	if(event_id==dbg_trace)
	{
		eip = get_reg_val("eip");
		if (b_trackEip) jumpto(eip);
		showAddr(eip);
		switch(status)
		{
		case 0:
			if( strcmp(seg, get_segm_name(get_reg_val("eip"))) != 0 )
			{
				msg("-> EPF: EIP is pointing into a different section at: %08X.\n",eip);
				suspend_process();
				toggle_tracer();
			}
			break;
		case 1:
			if( eip >= start_address && eip <= end_address)
			{
				msg("-> EPF: EIP is pointing into given memory area at %08X.\n",eip);
				suspend_process();
				toggle_tracer();
			}
			break;
		case 2:
			//(personal comment)
			//this can be speed-optimized by converting the mnemonic
			//into a cmd.itype state before... (consider it as "to be done")
			ua_mnem(eip, temp, MAX_STR);
			if( strcmp(temp, mnem) == 0)
			{
				msg("-> EPF: Mnemonic found at %08X.\n",eip);
				suspend_process();
				toggle_tracer();
			}
			break;
		case 3:
			if( reg_val == get_reg_val(reg) )
			{
				msg("-> EPF: %s == %08X at %08X.\n",reg, reg_val, eip);
				suspend_process();
				toggle_tracer();
			}
			break;
		case 4:
			for(i=0;i<9;i++)
			{
				if( reg_val == get_reg_val((char *)registers[i]) )
				{
					msg("-> EPF: %s == %08X at %08X.\n",registers[i], reg_val, eip);
					suspend_process();
					toggle_tracer();
				}
			}
			break;
		}
	}
	else if(event_id==dbg_process_exit)
	{
		set_tracer_internal_state(false);
	}
	return 0;
}
//-------------------------------------------------------------


//init, run, term
int idaapi init(void)
{
   //(personal comment)
   //can/should be changed since the debugger
   //can debug more than PE files ;-)
   if ( inf.filetype != f_PE ) return PLUGIN_SKIP;

   //register the debugger callback
   hook_to_notification_point(HT_DBG, dbg_callback, NULL);

  return PLUGIN_KEEP;
}

void idaapi term(void)
{
	//unregister callback
	unhook_from_notification_point(HT_DBG, dbg_callback);
}

void idaapi run(int arg)
{
	//is_debugger_on(void) ?
	if(get_process_state() == 0)
	{
		msg("-> EPF: No process is currently being debugged.\n"
			"   Please run and suspend the process first!\n");
		return;
	}

	toggle_tracer();
}

//-------------------------------------------------------------

char comment[] = "Entry point finder plugin for IDA PRO";
char help[] = "This plugin can find the entry point of packed executables.\n";
char wanted_name[] = "Toggle EPF tracer on or off";
char wanted_hotkey[] = "Alt-7";

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  0,
  init, 
  term, 
  run, 
  comment, 
  help, 
  wanted_name, 
  wanted_hotkey 
};
