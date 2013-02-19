#include <idc.idc>

static GetExtfunFlags (flags)
{
  auto s = 0;

  if ((flags & 1) == 1)
    s = "EXTFUN_BASE";
  if ((flags & 2) == 2)
  {
    if (s)
      s = s + ", EXTFUN_NORET";
    else
      s = "EXTFUN_NORET";
  }
  return s;
}

static GetIDCFuncFlags (ea)
{
  auto flags = 0;
  if (ea)
    flags = Dword (ea);
  return GetExtfunFlags (flags);
}

static GetVT (vt)
{
  auto t = 0;
  if (vt == 1)
    t = "VT_STR";
  else if (vt == 2)
    t = "VT_LONG";
  else if (vt == 3)
    t = "VT_FLOAT";
  else if (vt == 4)
    t = "VT_WILD";
  else if (vt == 5)
    t = "VT_OBJ";
  else if (vt == 6)
    t = "VT_FUNC";
  else if (vt == 7)
    t = "VT_STR2";
  else if (vt == 8)
    t = "VT_PVOID";
  else if (vt == 9)
    t = "VT_INT64";
  else if (vt == 10)
    t = "VT_REF";

  return t;
}

static GetIDCFuncArgs (ea)
{
  auto args = "";
  auto b, t, _ea;
  _ea = ea;
  if (_ea)
  {
    while ((b=Byte (_ea)) != 0)
    {
      _ea = _ea + 1;
      t = GetVT (b);
      args = args + t;
      if (Byte (_ea) != 0)
        args = args+ ", ";
    }
  }
  return args;
}

static ParseExtfunTable (ea, count)
{
  auto _ea = ea;
  auto i;
  auto ExtfunAddr, ExtfunName, ExtfunArgs, ExtfunFlags;

  if (ea && count)
  {
    auto extfun = object ();
    for (_ea; _ea < ea+count*4*4; _ea = _ea + 4*4)
    {
      for (i=0; i<4; i++)
        MakeDword (_ea+i*4);
      extfun.name = GetString (Dword(_ea), -1, GetStringType (Dword (_ea)));
      extfun.fp = Dword (_ea+4);
      extfun.args = GetIDCFuncArgs (Dword (_ea+8));
      extfun.flags = GetIDCFuncFlags (_ea+0xC);
      
      MakeFunction (extfun.fp, BADADDR); 
      MakeName (extfun.fp, "idcfunc_" + extfun.name);
      MakeRptCmt (Dword (_ea+8), extfun.args);
      MakeComm (_ea+0xC, extfun.flags);
      Message ("%x: %s (%s)\n", extfun.fp, extfun.name, extfun.args);
    }
  }
}

static ParseFuncSetTable ()
{
  auto ea = LocByName ("IDCFuncs");
  if (ea != BADADDR)
  {
    auto funcSetTable = object();
    
    // for now, manually parsing the structure
    // is favored over deserializing it (o.retrieve())
    funcSetTable.qnty = Dword (ea);
    funcSetTable.extfun_t_ptr = Dword (ea+4);
    MakeName (ea+4, "p_Extfuntable");
    funcSetTable.idcengine_startup_ptr = Dword (ea+8);
    MakeName (ea+8, "p_idcengine_startup");
    funcSetTable.idcengine_shutdown_ptr = Dword (ea+0xC);
    MakeName (ea+0xC, "p_idcengine_shutdown");
    funcSetTable.idcengine_init_ptr = Dword (ea+0x10);
    MakeName (ea+0x10, "p_idcengine_init");
    funcSetTable.idcengine_term_ptr = Dword (ea+0x14);
    MakeName (ea+0x14, "p_idcengine_term");
    funcSetTable.is_database_open_ptr = Dword (ea+0x18);
    MakeName (ea+0x18, "p_is_database_open");
    funcSetTable.ea2str_ptr = Dword (ea+0x1C);
    MakeName (ea+0x1C, "p_ea2str");
    funcSetTable.undeclared_variable_ok_ptr = Dword (ea+0x20);
    MakeName (ea+0x20, "p_undeclared_variable_ok");
    funcSetTable.get_unkvar_ptr = Dword (ea+0x24);
    MakeName (ea+0x24, "p_get_unkvar");
    funcSetTable.set_unkvar_ptr = Dword (ea+0x28);
    MakeName (ea+0x28, "p_set_unkvar");
    funcSetTable.exec_resolved_func_ptr = Dword (ea+0x2C);
    MakeName (ea+0x2C, "p_exec_resolved_func");
    funcSetTable.calc_sizeof_ptr = Dword (ea+0x30);
    MakeName (ea+0x30, "p_calc_sizeof");
    funcSetTable.get_field_ea_ptr = Dword (ea+0x34);
    MakeName (ea+0x34, "p_get_field_ea");

    MakeName (funcSetTable.extfun_t_ptr, "Extfuntable");
    MakeName (funcSetTable.idcengine_startup_ptr, "idcengine_startup");
    MakeName (funcSetTable.idcengine_shutdown_ptr, "idcengine_shutdown");
    MakeName (funcSetTable.idcengine_init_ptr, "idcengine_init");
    MakeName (funcSetTable.idcengine_term_ptr, "idcengine_init");
    MakeName (funcSetTable.is_database_open_ptr, "is_database_open");
    MakeName (funcSetTable.ea2str_ptr, "ea2str");
    MakeName (funcSetTable.undeclared_variable_ok_ptr, "undeclared_variable_ok");
    MakeName (funcSetTable.get_unkvar_ptr, "get_unkvar");
    MakeName (funcSetTable.set_unkvar_ptr, "set_unkvar");
    MakeName (funcSetTable.exec_resolved_func_ptr, "exec_resolved_func");
    MakeName (funcSetTable.calc_sizeof_ptr, "calc_sizeof");
    MakeName (funcSetTable.get_field_ea_ptr, "get_field_ea");
        
    Message("%08X: FuncSetTable\n", ea);
    ParseExtfunTable (funcSetTable.extfun_t_ptr, funcSetTable.qnty); 
  }
}

static main()
{
  if (GetInputFile () == "ida.wll")
  {
    ParseFuncSetTable ();
  }
  else
    Message ("This script can only operate on an ida.wll idb.\n");
}