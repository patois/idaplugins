//////////////////////////////////////////////////
//
//  Segdump plugin for IDA PRO
//  written by Dennis Elser.
// 
//  -------------------------------------------
//
//	This plugin can create dumps of (memory)
//	segments on your harddisk.
//	This can be useful when unpacking packed
//	executables.
//
//
//	-------------------------------------------
//
//	history:
//	--------
//	-	12.10.2004:
//		* initial version
//
//	-	13.10.2004
//		* fixed a bug in bool dump_seg_to_disk()
//		  where the filehandle wasn't closed.
//		* The dialog now shows start and
//		  end addresses.
//		* commented the code ;-)
//
//	(c) 2004, Dennis Elser
//
//////////////////////////////////////////////////

#include <ida.hpp>
#include <idp.hpp>
#include <expr.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <diskio.hpp>
#include "segdump.hpp"

//headline for the listbox
const char *headline[]={"Name of segment","Start address","End address"};
//popup menu strings
const char *popupnames[]={"x","y","Dump segment to disk","Refresh"};


//returns the size of a segment in bytes
int getsegsize(segment_t *segment)
{
	return (segment->endEA - segment->startEA);
}

//allocates memory and stores a copy of each
//byte of the given area
uchar *get_segment_data(ea_t s_a, ea_t e_a, ea_t size)
{
	uchar *mem;

	mem = (uchar *)malloc(size+1);
	
	get_many_bytes(s_a,mem,size);
	return mem;
}


//saves a segment to harddisk
bool dump_seg_to_disk(ulong n)
{
	segment_t *curseg;
	uchar *segdata;
	char *answer;
	FILE *file;

	curseg = getnseg(n);
	
	//show "save file" dialog
	answer = askfile_cv(1,get_segm_name(curseg),"Enter a filename for the segment:",0);
	if(answer == NULL)
	{
		return false;
	}

	//get copy of segment and save it to disk
	segdata = get_segment_data(curseg->startEA, curseg->endEA, getsegsize(curseg));
	file = fopenWB(answer);
	ewrite(file, segdata, getsegsize(curseg));
	eclose(file);
	free(segdata);
	return true;
}

//callback function for choose2() / popup menu item
void dump_seg(void *obj,ulong n)
{
	line *ptr = (line *)obj;
	bool dumped;

	msg("Dumping segment %s to disk...", (char *)ptr[n].segname);
	//dump
	dumped = dump_seg_to_disk(n-1);
	
	msg("%s\n",dumped?"done":"failed");
}


//build an object for the listbox
//and fill it with appropriate data:
//headline        | headline      | headline
//name of segment   start address   end address
//...               ...             ...
line *build_segm_obj(void)
{
	int i;
	int seg_qty = get_segm_qty();
	line *obj;
	char addrbuf[10];
	segment_t *curseg;

	//allocate seg_qty lines +1 (for the header line)
	obj = (line *)malloc(sizeof(line)*(seg_qty+1));
	
	//first line will be filled with headline captions
	strcpy( (char *)obj[0].segname, headline[0]);
	strcpy( (char *)obj[0].startEA,headline[1]);
	strcpy( (char *)obj[0].endEA,headline[2]);
	
	//the following lines will contain name of segment,
	//start- and end address of segments
	for(i=1;i<=seg_qty;i++)
	{
		curseg = getnseg(i-1);
		strcpy( (char *)obj[i].segname,	get_true_segm_name(curseg));
		sprintf(addrbuf,"%08X",curseg->startEA);
		strcpy( (char *)obj[i].startEA,	addrbuf);
		sprintf(addrbuf,"%08X",curseg->endEA);
		strcpy( (char *)obj[i].endEA,	addrbuf);

	}
	//return pointer to object
	return obj;
}

//callback function for choose2() -> number of lines
ulong get_item_qty(void *obj)
{
	return get_segm_qty();
}

//callback function for choose2() -> returns the n-th line
void getn_item_text(void *obj,ulong n,char * const*buf)
{
	line *ptr = (line *)obj;
	line *bufptr = (line *)buf;

	strcpy((char *)buf[0],(char *)ptr[n].segname);
	strcpy((char *)buf[1],(char *)ptr[n].startEA);
	strcpy((char *)buf[2],(char *)ptr[n].endEA);
	return;
}


int idaapi init(void)
{
  return PLUGIN_KEEP;
}


void idaapi term(void)
{

}

void idaapi run(int arg)
{

	//Credits to Halvar for his choose2() example code!

	//build the listbox object!
	line *obj = build_segm_obj();

	choose2(
        CH_MODAL,
        -1,30,                  // x0=-1 for autoposition
        50,70,
        obj,                      // our listbox object
        3,                       // Number of columns
        NULL,              // Widths of columns (may be NULL)
        get_item_qty,// Number of items
        getn_item_text, // get string of n-th item (1..n)
                                        // 0-th item if header line
        "DumpSeg Plugin by Dennis Elser",  // menu title (includes ptr to help)
        21,                       // number of icon to display
        1,                  // starting item
        NULL, // multi-selection callback for "Delete" (may be NULL)
        NULL,         // callback for "New"    (may be NULL)
        NULL,// callback for "Update"(may be NULL)
                                                // update the whole list
                                                // returns the new location of item 'n'
        dump_seg,   // callback for "Edit"   (may be NULL)
        NULL, // callback for non-modal "Enter" (may be NULL)
        NULL,  // callback to call when the window is closed (may be NULL)
        popupnames,   // Default: insert, delete, edit, refresh
        NULL);

//free and destroy listbox object
free(obj);
return;

}

//--------------------------------------------------------------------------
char comment[] = "Segment dumper plugin by Dennis Elser";

char help[] =
        "With this plugin you can dump (memory) segments to disc\n";

char wanted_name[] = "Dump segment to disk";

char wanted_hotkey[] = "Alt-4";


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
