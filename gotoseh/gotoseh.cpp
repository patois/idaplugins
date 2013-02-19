// gotoSEH IDA Pro plugin
//
// (c) Dennis Elser
//
// history:
//
// 17.11.2006 - initial release
// 20.02.2007 - public release

#include <ida.hpp>
#include <idp.hpp>
#include <expr.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <dbg.hpp>
#include <auto.hpp>

extern plugin_t PLUGIN;



int idaapi init(void)
{
  if ( inf.filetype != f_PE ) return PLUGIN_SKIP;

  return PLUGIN_OK;
}

void idaapi term(void)
{
}


void idaapi run(int arg)
{
    thread_id_t tid;
    char segname[0x20];
    segment_t *tibseg;
    ulong ptr_seh;
    ulong seh_handler;

    tid = get_current_thread(); //use "getn_thread(0)" for IDA releases below 5.1
    if( tid == PROCESS_NO_THREAD )
    {
        warning( "Thread does not exist!" );
        return;
    }
    
    qsnprintf( segname, sizeof( segname ), "TIB[%08X]", tid );
    tibseg = get_segm_by_name( segname );

    if( tibseg == NULL )
    {
        warning( "Could not get segment pointer!" );
        return;
    }

    ptr_seh = get_long( tibseg->startEA );
    seh_handler = get_long( ptr_seh + 4 );
    auto_make_proc( seh_handler );
    jumpto( seh_handler );
}

//--------------------------------------------------------------------------
char comment[] = "gotoSEH";
char help[] = "no help ;)";
char wanted_name[] = "gotoSEH";
char wanted_hotkey[] = "0";


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