/*
Callgraph IDC script v1.0 - written by Dennis Elser
---------------------------------------------------
This is an IDC script for the
Disassembler IDA Pro by Datarescue.
The script needs IDA Pro v4.6 SP1
or above!

What does the script do?
------------------------
The script creates a callgraph of a process
being debugged/traced by the IDA debugger.
You can create multiple graphs and compare
them using an external comparison tool/parser
in order to find differences in the behaviour
of the process/executable.


history:
--------
  13.04.2004 - initial release


usage:
------
The script can only be used with the integrated
debugger in IDA 4.60 SP1 and above!

Usage is as follows:
Load and compile the IDC script (callgraph.idc).
Go to the 'Stop condition' field in the menu
'Debugger > Tracing > Tracing options..' and
enter:

call()

Run the process and stop at a specific location
(for example using a breakpoint or 'run to cursor'
and enable tracing mode). Resume the process.
The plugin will create a .vcg file in your IDA
directory.

Careful: You need to rename existing VCG files
if you plan to rerun the IDC script !


Commercial usage is strictly prohibited without
asking for permission!
If you plan to use this script commercially,
write an email to dennis(at)backtrace.de
*/

static call(/*start_ea, end_ea*/)
{
   auto filename;
   auto eof;


   //if(Eip < start_ea || Eip > end_ea) return 0;
   
   eof = 0;
   
   filename = form("%s\\%s%s",GetIdaDirectory(),GetInputFile(),".vcg");
	
   if(!CreateGraph(filename))
   {
   	RemEofComment(filename);
   }
   
   if(GetMnem(Eip)=="call")
   {
	Message("%08X: %s is calling %s\n", Eip, GetFunctionName(Eip), GetOpnd(Eip,0));
	
	if(IsNewNode(filename,GetFunctionName(Eip)))
	{
		CreateNode(filename,GetFunctionName(Eip),GetFunctionName(Eip),"color: lightblue");
		eof = 1;
	}
	if(IsNewNode(filename,GetOpnd(Eip,0)))
	{
		CreateNode(filename,GetOpnd(Eip,0),GetOpnd(Eip,0),"color: lightblue");
		eof = 1;
	}
	if(IsNewEdge(filename,GetFunctionName(Eip),GetOpnd(Eip,0)))
	{
		CreateEdge(filename,GetFunctionName(Eip),GetOpnd(Eip,0),"color: black");
		eof = 1;
	}
	if(eof)
	{
		WriteEofComment(filename);
	}
   }
   return 0;
}

static IsNewNode(filename, node)
{
	return !Exists(filename,
		               form("node: { title: \"%s\"",
		               node)
		               );
}

static IsNewEdge(filename, src,dst)
{
	return !Exists(filename,
		               form("edge: { sourcename: \"%s\" targetname: \"%s",
		         src,
		         dst)
		               );
}


static Exists(filename, line)
{
	auto fhandle;
	auto fline;
	
	fhandle=fopen(filename,"a+");
     while( filelength(fhandle) != ftell(fhandle) )
     {
     	fline=freadln(fhandle);
         	if(strstr(fline,line) != -1)
     	{
     		fclose(fhandle);
     		return 1;
     	}
     }
     fclose(fhandle);
	return 0;
}

static WriteEofComment(filename)
{
	auto fhandle;
	fwriteln(filename,"}");
return;
}


static RemEofComment(filename)
{
	auto fhandle;
	auto fc;
	
	fhandle=fopen(filename,"r+");
	fseek(fhandle,filelength(fhandle)-1,0);
	fc=fgetc(fhandle);
	if(fc=='}')
	{
		fseek(fhandle,filelength(fhandle)-1,0);
		fprintf(fhandle,"\n");
	}
	fclose(fhandle);
return;
}


static CreateGraph(filename)
{
	auto fhandle;
	auto fline;
	auto header;

header= form("graph:\n"
	   "{\n"
	   "title: \"Flow graph of functions called during a debugging session (%s)\"\n"
	   "manhattan_edges: yes\n"
	   "layoutalgorithm: maxdepthslow\n"
	   "finetuning: yes\n"
	   //"layout_downfactor: 100\n"
	   //"layout_upfactor: 100\n"
	   //"layout_nearfactor: 100\n"
	   "color: lightyellow\n"
	   "xlspace: 30\n"
	   "yspace: 100\n\n",GetInputFile());


	
	fhandle=fopen(filename,"a+");
	fline=freadln(fhandle);
	fclose(fhandle);
	if(strstr(fline,"graph") != -1)
	{
		return 0;
	}

	fwriteln(filename,header);
	return 1;
}


static freadln(handle)
{
	auto line;
	auto c;
	
	line="";	
	while( ((c=fgetc(handle)) != '\n') )
	{
		if(c==-1) return line;
		line=line+c;
	}
	return line;
}

static CreateNode(filename,node,label, color)
{
	fwriteln(filename,
		    form("node: { title: \"%s\" label: \"%s\" %s}\n",
		    node,
		    label,
		    color)
	         );
}

static CreateEdge(filename,src,dst,color)
{
	fwriteln(filename,
		    form("edge: { sourcename: \"%s\" targetname: \"%s\" %s}\n",
		         src,
		         dst,
		         color)
	         );
}



static fwriteln(filename,line)
{
	auto fhandle;
	
	fhandle=fopen(filename,"a+");
     fprintf(fhandle,line);
     fclose(fhandle);
}
