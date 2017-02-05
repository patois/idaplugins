/*
 *	layout.cpp
 *	----------
 *	This example plugin for IDA 5.0 (and above)
 *	shows you how to use the new graphing interface
 *	and some of its new callbacks.
 *	The plugin adds an item to the graph's popup-menu
 *	and lets you choose between one of three layout
 *	algorithms (circle, tree and digraph).
 *
 *	Author: Dennis Elser
 *
 *	Hint: This plugin is an extension to the ugraph
 *	sample plugin provided with the IDA sdk.
 *
 *	history:
 *	--------
 *
 *	19.03.2006 - initial release
 *
 */


#include <windows.h>

#include <ida.hpp>
#include <idp.hpp>
#include <graph.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

//--------------------------------------------------------------------------
static bool hooked = false;
static bool newmenu = false;
static int layout = layout_digraph;
static TForm *form = NULL;
static graph_viewer_t *gv = NULL;


#define MENU_ITEM_CAPTION "Set layout"

//--------------------------------------------------------------------------
void doCircleLayout(mutable_graph_t *g, point_t center, int radius)
{
		  g->current_layout = layout_circle;
		  g->circle_center = center;
		  g->circle_radius = radius;
		  g->create_circle_layout(center, radius);
		  g->redo_layout(); 
		  return;
}


//--------------------------------------------------------------------------
void doTreeLayout(mutable_graph_t *g)
{
		  g->current_layout = layout_tree;
		  g->create_tree_layout();  
		  g->redo_layout(); 
		  return;
}



//--------------------------------------------------------------------------
void doDigraphLayout(mutable_graph_t *g)
{
	      g->current_layout = layout_digraph;
		  g->create_digraph_layout();
		  g->redo_layout(); 
		  return;
}



//--------------------------------------------------------------------------
// callback function for layout selection
bool idaapi menu_callback(void *ud)
{
	mutable_graph_t *g = get_viewer_graph(gv);
	if( g == NULL )
		return false;
	
	int code = askbuttons_c("Circle", "Tree", "Digraph", 1, "Please select layout type");
	
	// code is being converted to a globally "useful" variable
	switch( code  )
	{
	case 1: // circle
		layout = layout_circle;
		// use 200,200 (x/y) as center by default
		// 2000 as radius by default
		doCircleLayout(g, point_t(200, 200), 2000);
		break;
	case 0: // tree
		layout = layout_tree;
		doTreeLayout(g);
		break;  
	case -1: // digraph
		layout = layout_digraph;
		doDigraphLayout(g);
		break;
	}
	
	refresh_viewer(gv);
	return true;
}



//--------------------------------------------------------------------------
// callback for graph
static int idaapi callback(void *, int code, va_list va)
{
	int result = 0;
	switch ( code )
	{
		// gotfocus is used to get global form- and graphview pointers
	case grcode_gotfocus:
		{
			// always get current form and gv
			// because "reset desktop" may close
			// the current form and thus invalidate
			// its old handle.
			form = get_current_tform();
			if(form == NULL)
				break;
			gv = get_graph_viewer(form);
			if ( gv != NULL && (!newmenu) )
			{
				if(viewer_add_menu_item(gv, MENU_ITEM_CAPTION, menu_callback, gv, 0))
					newmenu = true;
			}
			break;
		}
		break;
		// user selected a different graph / function
		// -> render graph with layout chosen by user
	case grcode_changed_graph:
		{
			if( gv == NULL )
				break;
			
			mutable_graph_t *g = get_viewer_graph(gv);
			
			if( g == NULL )
				break;
			
			switch( layout  )
			{
			case layout_circle: // circle
				doCircleLayout(g, point_t(200, 200), 2000);
				break;
			case layout_tree: // tree
				doTreeLayout(g);
				break;  
			case layout_digraph: // digraph
				doDigraphLayout(g);
				break;
			}	
		}
		break;
	}
	return result;
}


//--------------------------------------------------------------------------
int idaapi init(void)
{
	if ( !hooked )
		hooked = hook_to_notification_point(HT_GRAPH, callback, NULL);

	return ( hooked ) ? PLUGIN_KEEP : PLUGIN_SKIP;
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
	msg("Additional graph layouts are %s.\n"
		"Right click on a graph and select \"%s\".",
		(newmenu) ? "enabled" : "disabled",
		MENU_ITEM_CAPTION);
}

//--------------------------------------------------------------------------
char comment[] = "This plugin allows you to switch the current graph's layout";

char help[] =
        "This plugin allows you to switch the current graph's layout";


//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overriden in plugins.cfg file

char wanted_name[] = "Set graph layout";


// This is the preferred hotkey for the plugin module
// The preferred hotkey may be overriden in plugins.cfg file
// Note: IDA won't tell you if the hotkey is not correct
//       It will just disable the hotkey.

char wanted_hotkey[] = "";


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
