// * Very Simple Code Profiling plugin by Dennis Elser
// *
// * This plugin shows you how often a function
// * during a runtime debugging session is called.
// *
// * This code is (C) by Dennis Elser
// *


#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <dbg.hpp>
#include <funcs.hpp>


bool profile=true;

static int idaapi dbg_callback(void * /*user_data*/, int event_id, va_list /*va*/)
{
	regval_t eip;
	int numfuncs;
	int i;
	func_t *f;
	bpt_t cur_bp;

	//is the process about to start?
	if(event_id==dbg_process_start)
	{
		if( askyn_cv(1,"VSCP - Want to profile the process?",0) !=1)
		{
			//only profile, if user clicked "yes"
			profile=false;
			return 0;
		}
		else profile=true;
		
		//get number of total functions from the idb
		numfuncs=get_func_qty();

		msg("Setting %d breakpoints, please wait..",numfuncs);

		//set breakpoint on each function, with flagtype = BPT_TRACE
		//these are breakpoints which don't suspend the debugger
		for (i=0;i<=numfuncs-1;i++)
		{
			f = getn_func(i);
			add_bpt(f->startEA,0,-1);
			getn_bpt(i, &cur_bp);
			cur_bp.flags=BPT_TRACE;
			update_bpt(&cur_bp);
		}
		msg("done!\n");
	}

	//this code makes sure that the process is being
	//resumed if a breakpoint triggers, which the user didnt set
	else if(event_id==dbg_breakpoint && profile)
	{
		continue_process();
	}

	//Notify the user to clear the breakpoints if he doesn't need them
	//anymore
	else if(event_id==dbg_process_exit && profile)
	{
		msg(
			"Process terminated.. be sure to check out the breakpoint list!\n"
			"Press alt-8 to delete the breakpoint list.\n"
			);
	}

	return 0;
}


int idaapi init(void)
{
   //skip plugin if a non-pe file has been loaded
   //since the debugger supports PE files only
   //at the time of this writing
   if ( inf.filetype != f_PE ) return PLUGIN_SKIP;

   //register the debugger callback
   hook_to_notification_point(HT_DBG, dbg_callback, NULL);
   msg("VSCP is active.\n");

  return PLUGIN_KEEP;
}

void idaapi term(void)
{
	//unregister callback
	unhook_from_notification_point(HT_DBG, dbg_callback);
}

void idaapi run(int arg)
{
	int numfuncs;
	int i;
	func_t *f;
	numfuncs=get_func_qty();

	//this function will be run if the user presses alt-8
	//or selects the plugin from the menu
	//it deletes all the breakpoints and clears the bp-list
	msg("Deleting %d breakpoints, please wait..",numfuncs);
	for (i=0;i<=numfuncs-1;i++)
	{
		f = getn_func(i);
		del_bpt(f->startEA);
	}
	msg("done!\n");
}

//--------------------------------------------------------------------------
char comment[] = "VSCP";
char help[] = "VSCP\n";
char wanted_name[] = "VSCP - Erase all profiling breakpoints";
char wanted_hotkey[] = "Alt-8";

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
