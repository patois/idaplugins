/*
 *	Graphtest 2 - pegraph
 *  
 *  Author: Dennis Elser, 06/2006
 *
 *  This example displays parts of the pe header in a graph.
 *	Feel free to modify!
 *
 *  Released on The IDA Palace (www.backtrace.de).
 *
 */


#include <windows.h>

#include <ida.hpp>
#include <idp.hpp>
#include <graph.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <../ldr/pe.h>

//--------------------------------------------------------------------------
static bool hooked = false;
static std::vector<string> graph_text;
static 	peheader_t pe;


//--------------------------------------------------------------------------
static int idaapi callback(void *, int code, va_list va)
{
  int result = 0;
  switch ( code )
  {

     case grcode_user_refresh: // refresh user-defined graph nodes and edges
                              // in:  mutable_graph_t *g
                              // out: success
     {
       mutable_graph_t *g = va_arg(va, mutable_graph_t *);

	   if ( !g->empty() )
		   break;
		
	   for( int i=0; i<=get_segm_qty(); i++ )
	   {
		   g->add_node( NULL );
	   }


	   for( int i = 0; i<get_segm_qty(); i++ )
	   {
           if( getnseg(i)->contains(pe.imagebase32 + pe.entry) )
				g->add_edge(0, i+1, NULL);
	   }

       result = true;
     }
     break;

    case grcode_user_gentext: // generate text for user-defined graph nodes
                              // in:  mutable_graph_t *g
                              // out: must return 0
     {
       mutable_graph_t *g = va_arg(va, mutable_graph_t *);
       graph_text.resize(g->size());

	   char buf[MAXSTR];
	   char temp[MAXSTR];


     qsnprintf( buf,
				sizeof(buf),
				COLSTR("PE Header\n",SCOLOR_UNAME) 
				"--------------------\n"
				"Imagebase : %08X\n"
				"Entrypoint: %08X\n"
				"EA        : %08X\n",
				pe.imagebase32,
				pe.entry,
				pe.imagebase32 + pe.entry );
	 
	 graph_text[0] = buf;


	 for( int i = 0; i<get_segm_qty(); i++ )
	 {
		 get_segm_name( getnseg( i ), temp, sizeof(temp) );
		 qsnprintf( buf,
			 sizeof( buf ),
			 "SegName   : "COLSTR("%s\n",SCOLOR_SEGNAME)
			 "StartEA   : %08X\n"
			 "EndEA     : %08X\n"
			 "Exec perm : %s\n",
			 temp,
			 getnseg(i)->startEA,
			 getnseg(i)->endEA,
			 (getnseg(i)->perm & SEGPERM_EXEC) ? COLSTR("yes", SCOLOR_CREFTAIL) : COLSTR("no",SCOLOR_DNUM) );
		 graph_text[i+1] = buf;
	 }

       result = true;
     }
     break;

    case grcode_user_text:    // retrieve text for user-defined graph node
                              // in:  mutable_graph_t *g
                              //      int node
                              //      const char **result
                              //      bgcolor_t *bg_color (maybe NULL)
                              // out: must return 0, result must be filled
                              // NB: do not use anything calling GDI!
     {
       mutable_graph_t *g = va_arg(va, mutable_graph_t *);
       int node           = va_arg(va, int);
       const char **text  = va_arg(va, const char **);
       bgcolor_t *bgcolor = va_arg(va, bgcolor_t *);
       *text = graph_text[node].c_str();
       if ( bgcolor != NULL )
         *bgcolor = DEFCOLOR;
       result = true;
       qnotused(g);
     }
     break;


    }
  return result;
}



//--------------------------------------------------------------------------
int idaapi init(void)
{
  if ( inf.filetype != f_PE )
	  return PLUGIN_SKIP;
  return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
void idaapi term(void)
{
  if ( hooked )
    unhook_from_notification_point(HT_GRAPH, callback);
}

//--------------------------------------------------------------------------
void idaapi run(int /*arg*/)
{
	netnode penode;
	
	penode.create(PE_NODE);
	
	if ( penode.valobj(&pe, sizeof(pe)) <= 0 )
	{
		msg("Could not get PE Header from IDB!\n");
		return;
	}
	
	HWND hwnd = NULL;
	TForm *form = create_tform("pegraph", &hwnd);
	if ( hwnd != NULL )
	{
		if ( !hooked )
		{
			hooked = true;
			hook_to_notification_point(HT_GRAPH, callback, NULL);
		}
		// get a unique graph id
		netnode id;
		id.create();
		graph_viewer_t *gv = create_graph_viewer(form,  id);
		open_tform(form, FORM_MDI|FORM_TAB|FORM_MENU);
		if ( gv != NULL )
		{
			viewer_fit_window(gv);
		}
	}
	else
	{
		close_tform(form, 0);
	}
}

//--------------------------------------------------------------------------
char comment[] = "pegraph.";

char help[] =
        "A sample graph plugin module\n"
        "\n"
        "This module shows you how to create a graph viewer.";


//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overriden in plugins.cfg file

char wanted_name[] = "pegraph";


// This is the preferred hotkey for the plugin module
// The preferred hotkey may be overriden in plugins.cfg file
// Note: IDA won't tell you if the hotkey is not correct
//       It will just disable the hotkey.

char wanted_hotkey[] = "7";


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
