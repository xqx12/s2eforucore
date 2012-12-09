/*
 * S2E Selective Symbolic Execution Framework For Ucore OS
 *
 * Addbyxqx 20121030
 *
 */

// XXX: qemu stuff should be included before anything from KLEE or LLVM !
extern "C" {
#include "config.h"
//#include "cpu.h"
//#include "exec-all.h"
#include "qemu-common.h"
#include "disas.h"
}

#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include <s2e/ConfigFile.h>
#include "UCoreMonitor.h"

#define _XQX_DEBUG
//#define _XQX_PRINT_MON
#define _XQX_PRINT_FILE


using namespace std;

using namespace s2e;
using namespace s2e::plugins;

//global var
FILE *outfile = NULL;

//
S2E_DEFINE_PLUGIN(UCoreMonitor, "Plugin for monitoring UCore Func", "UCoreInterceptor");



UCoreMonitor::~UCoreMonitor()
{
	
    return;
}

void UCoreMonitor::initialize()
{
	s2e()->getDebugStream() << "Hello, UCoreMonitor \n " ;
   
   outfile = fopen("out.txt", "w");
   if( outfile == NULL){
	  s2e()->getWarningsStream() << "open out file error \n";
   }
   debug_print("Hello, UCoreMonitor %d\n", 1);
   
   /*******addbyxqx20121205 for functionMonitor*********
   m_func_monitor = static_cast<FunctionMonitor*>(s2e()->getPlugin("FunctionMonitor"));
   s2e()->getCorePlugin()->onTranslateBlockStart.connect(
	   sigc::mem_fun(*this, &UCoreMonitor::slotTranslateBlockStart));
   --------------------end--------------------------****/
   
   m_MonitorFunction = s2e()->getConfig()->getBool(getConfigKey() + ".MonitorFunction");
   m_KernelBase = 0xc0100000;
   
   //get the symbols file path
   bool ok;
   system_map_file = s2e()->getConfig()->getString(getConfigKey() + ".system_map_file", "", &ok);
   if(!ok){
	   s2e()->getWarningsStream() << "No kernel.sym file provided. System.map is needed for UCoreMonitor to work properly. Quit.\n";
	   exit(-1);
   }
   parseSystemMapFile();
   
   debug_print( system_map_file );
   
   //Get STAB section address
   m_StabStart = sMap[STAB_BEGIN_ADDR_SYMBOL];
   m_StabEnd = sMap[STAB_END_ADDR_SYMBOL];
   m_StabStrStart = sMap[STABSTR_BEGIN_ADDR_SYMBOL];
   m_StabStrEnd = sMap[STABSTR_END_ADDR_SYMBOL];
   first = true;
  
  
   if(m_MonitorFunction){
	   s2e()->getCorePlugin()->onTranslateBlockEnd
			.connect(sigc::mem_fun(*this, &UCoreMonitor::onTranslateBlockEnd));
	   
			
	   this->onFunctionCalling.connect(sigc::mem_fun(*this, &UCoreMonitor::slotFunctionCalling));
   }
   
   
   return;
}


void UCoreMonitor::parseSystemMapFile(){
	ifstream system_map_stream;
	system_map_stream.open(system_map_file.c_str());
	if(!system_map_stream){
		s2e()->getWarningsStream() << "Unable to open System.map file"
								   << system_map_file << ".\n";
		exit(1);
	}

	char line[255];
	uint64_t addr;
	string kernel_symbol;
	while(system_map_stream){
		system_map_stream.getline(line, 255);
//		debug_print(line);
		char temp[200];
		sscanf(line, "%lx %s", &addr, temp);
		symbol_struct sym;
		sym.addr = addr;
		sym.type = 's';
		sym.name = temp;
		sTable[addr] = sym;
		sMap[temp] = addr;
	}
	return;
}

uint64_t UCoreMonitor::getKernelStart() const {
	return m_KernelBase;
}


/**********For FunctionMonitor Test ******************
// use FunctionMonitor plugin to get a function call and ret.
void UCoreMonitor::slotTranslateBlockStart(ExecutionSignal *signal,
                                      S2EExecutionState *state,
                                      TranslationBlock *tb,
                                      uint64_t pc)
{
	FunctionMonitor::CallSignal *callSignal;
	
    //4. Obtain the address of the function to be monitored
    //The hard-coded value can be specified in the configuration file your plugin
    uint64_t functionAddress = sMap["set_proc_name"]; // get the proc_run addr,  s//0xC00F0120;
	
	
	if(pc != functionAddress ) return ;
	
	debug_print("StartMonitor set_proc_name: %x\n", functionAddress );
	
    //5. Register a function call monitor at program counter 0xC00F0120.
    //This is done in two steps:
    //  a. Register a call signal for the specified address
    //  b. Connect as many signal handlers as needed
	
    //a. Register a call signal for address 0xC00F0120
    callSignal = m_func_monitor->getCallSignal(state, functionAddress, -1); //-1 present monitor all processes
	
    //b. Register one signal handler for the function call.
    //Whenever a call instruction whose target is 0xC00F0120 is detected, FunctionMonitor
    //will invoke myFunctionCallMonitor
    callSignal->connect(sigc::mem_fun(*this, &UCoreMonitor::myFunctionCallMonitor));
}

//This handler is called after the call instruction is executed, and before the first instruction
//of the called function is run.
void UCoreMonitor::myFunctionCallMonitor(S2EExecutionState* state, FunctionMonitorState *fns)
{
    s2e()->getMessagesStream() << "My function handler is called \n" ;
	debug_print("set_proc_name called\n" );
    //...
    //Perform here any analysis or state manipulation you wish
    //...

    //6. Register the return handler
    //The FunctionMonitor plugin invokes this method whenever the return instruction corresponding
    //to this call is executed.
    FUNCMON_REGISTER_RETURN(state, fns, UCoreMonitor::myFunctionRetMonitor)
}

//FunctionMonitor invokes this handler right after the return instruction is executed, and
//before the next instruction is run.
void UCoreMonitor::myFunctionRetMonitor(S2EExecutionState *state)
{
	debug_print("set_proc_name ret\n" );
    //...
    //Perform here any analysis or state manipulation you wish
    //...
}
*********For FunctionMonitor Test End ******************/


//catch call inst
void UCoreMonitor::onTranslateBlockEnd(ExecutionSignal *signal,
                                       S2EExecutionState *state,
                                       TranslationBlock *tb,
                                       uint64_t pc, bool static_target
                                       , uint64_t target_pc){
  uint64_t vpc = pc;
//  uint64_t vpcget = state->getPc();
//  debug_print("onTranslateBlockEnd: %llx %llx, %llx\n", pc,target_pc, vpcget);
  

  //when pc < 0x00100000, run in noprotect mode. and in protect mode, 
  //the pc to vpc is += 0xc0000000.
  if (vpc >= 0x00100000 && vpc <= 0x3fffffff)
    vpc += 0xc0000000;

  if(vpc >= getKernelStart()){
	  //if tb is call or tb_call_IND, what is the difference??
    if(tb->s2e_tb_type == TB_CALL || tb->s2e_tb_type == TB_CALL_IND){
      signal->connect(sigc::mem_fun(*this, &UCoreMonitor::slotCall));
    }
	/*
	  if(tb->s2e_tb_type == TB_CALL ){
		  signal->connect(sigc::mem_fun(*this, &UCoreMonitor::slotCall));
	  }
	  if( tb->s2e_tb_type == TB_CALL_IND){
		  signal->connect(sigc::mem_fun(*this, &UCoreMonitor::slotCall_IND));
	  }
	 */
  }
  
}

//slot call inst
//if a call instruction be called, we can do sth here
void UCoreMonitor::slotCall(S2EExecutionState *state, uint64_t pc)
{
	//read 5bytes ins opcode from pc, and disasm ?
	/*unsigned char szIns[10] = {0};
	if(!state->readMemoryConcrete(pc, szIns, 5)){
		s2e()->getWarningsStream(state) << "[slotCall ERROR]Get PC OPcode!\n";
		return ;
	}
	debug_print("[slotCall] %llx: %02x %02x %02x %02x %02x \n",pc, szIns[0],szIns[1],szIns[2],szIns[3],szIns[4]);
	//xtarget_disas(outfile, pc, 1, 0);
	*/
	
	if(pc > getKernelStart() && first){
		parseUCoreStab(state);
		first = false;
	}	
	
	uint64_t vpc = state->getPc();
	if (vpc >= 0x00100000 && vpc <= 0x3fffffff)
		vpc += 0xc0000000;
	
	//added by Nuk
	ExecutionSignal onFunctionCallingSignal;
	onFunctionCalling.emit(&onFunctionCallingSignal, state,
						   sTable[vpc].name, pc);
	onFunctionCallingSignal.emit(state, pc);
	
	
	return;
}

void UCoreMonitor::slotFunctionCalling(ExecutionSignal *signal,
									   S2EExecutionState *state,
									   string fname, uint64_t pc){
	/** addbyxqx20121107 for function test**  
	if(fname=="cputch"||fname=="cprintf"||fname=="check_safe_kmalloc"||
	              fname=="check_tree"||fname=="check_compare1"||
				  fname=="set_page_ref") 
	{
		return;
	}
	if(fname != "")
	 debug_print("[slotFunctionCalling]: fname=%s %llx\n", fname.c_str(), pc);
	** Fuction test end*  **/
	
	
	if(fname == "proc_run"){
		debug_print("[slotFunctionCalling]: fname=%s %llx\n", fname.c_str(), pc);
		//Proc switch
//		signal->connect(sigc::mem_fun(*this, &UCoreMonitor::slotKmThreadSwitch));
	}else if(fname == "set_proc_name"){
		debug_print("[slotFunctionCalling]: fname=%s %llx\n", fname.c_str(), pc);
		//Thread create
//		signal->connect(sigc::mem_fun(*this, &UCoreMonitor::slotKmThreadInit));
	}else if(fname == "do_exit"){
		debug_print("[slotFunctionCalling]: fname=%s %llx\n", fname.c_str(), pc);
		//Thread exit
//		signal->connect(sigc::mem_fun(*this, &UCoreMonitor::slotKmThreadExit));
	}
	
	
	
}


void UCoreMonitor::parseUCoreStab(S2EExecutionState *state){
	//parse stab
	int n = (m_StabEnd - m_StabStart) / sizeof(UCoreStab) - 1;
	stab_array = new UCoreStab[n];
	for(int i = 0; i < n;i ++){
		int addr = m_StabStart + i * sizeof(UCoreStab);
		if(!state->readMemoryConcrete(addr,
									  (void*)(stab_array + i),
									  sizeof(UCoreStab))){
			s2e()->getWarningsStream() << "[ERROR]Parsing UCoreStab\n";
			exit(-1);
		}
	}
	stab_array_end = stab_array + n;
	//parse stabstr
	n = (m_StabStrEnd - m_StabStrStart) / sizeof(char) - 1;
	stabstr_array = new char[n];
	if(!state->readMemoryConcrete(m_StabStrStart,
								  (void*)(stabstr_array),
								  sizeof(char) * n)){
		s2e()->getWarningsStream() << "[ERROR]Parsing UCoreStab\n";
		exit(-1);
	}
	//print result
	//printUCoreStabs();
	return;
}
//Printing Stabs
void UCoreMonitor::printUCoreStabs(){
	s2e()->getWarningsStream() << "Start:";
	s2e()->getWarningsStream().write_hex(m_StabStart);
	s2e()->getWarningsStream() << "\n";
	s2e()->getWarningsStream() << "End:";
	s2e()->getWarningsStream().write_hex(m_StabEnd);
	s2e()->getWarningsStream() << "\n";
	s2e()->getWarningsStream() << "N:";
	s2e()->getWarningsStream() << ((m_StabEnd - m_StabStart) / sizeof(UCoreStab) - 1);
	s2e()->getWarningsStream() << "\n";
	for(int i = 0; i < 10; i ++){
		int index = i * 100 + 1;
		s2e()->getWarningsStream() << "index: ";
		s2e()->getWarningsStream() << index;
		s2e()->getWarningsStream() << " n_strx: ";
		s2e()->getWarningsStream() << stab_array[index].n_strx;
		s2e()->getWarningsStream() << " n_type: ";
		s2e()->getWarningsStream() << (uint64_t)stab_array[index].n_type;
		s2e()->getWarningsStream() << " n_other: ";
		s2e()->getWarningsStream() << (uint64_t)stab_array[index].n_other;
		s2e()->getWarningsStream() << " n_desc: ";
		s2e()->getWarningsStream() << (uint64_t)stab_array[index].n_desc;
		s2e()->getWarningsStream() << " v_value: ";
		s2e()->getWarningsStream().write_hex(stab_array[index].n_value);
		s2e()->getWarningsStream() << "\n";
	}
	if(stabstr_array != NULL)
		s2e()->getWarningsStream() << "stabstr_array: " << stabstr_array << "\n";
	return;
}



//addbyxqx20121103 for a test
void UCoreMonitor::slotCall_IND(S2EExecutionState *state, uint64_t pc)
{
	//read 5bytes ins opcode from pc, and disasm ?
	unsigned char szIns[10] = {0};
	if(!state->readMemoryConcrete(pc, szIns, 5)){
		s2e()->getWarningsStream(state) << "[slotCall ERROR]Get PC OPcode!\n";
		return ;
	}
	debug_print("[slotCall_IND] %llx: %02x %02x %02x %02x %02x \n",pc, szIns[0],szIns[1],szIns[2],szIns[3],szIns[4]);
	
	xtarget_disas(outfile, pc, 1, 0);
	
	return;
}


void UCoreMonitor::debug_print(string str)
{
#ifdef  _XQX_DEBUG
	s2e()->getDebugStream() << str << "\n";
	cout << str << "\n" ;
#endif
	return ;
}
void UCoreMonitor::debug_print(const char* fmt, ...)
{
#ifdef  _XQX_DEBUG
	va_list ap;
#ifdef  _XQX_PRINT_MON
	
	va_start(ap,fmt);
	vprintf(fmt, ap);
	va_end(ap);
#endif

#ifdef  _XQX_PRINT_FILE
	//log in file
	va_start(ap,fmt);
	if(outfile!=NULL) vfprintf(outfile,fmt,ap);
	va_end(ap);
#endif		
#endif
	return ;
}



bool UCoreMonitor::getImports(S2EExecutionState *s, const ModuleDescriptor &desc, Imports &I)
{
    
    return true;
}

bool UCoreMonitor::getExports(S2EExecutionState *s, const ModuleDescriptor &desc, Exports &E)
{
    
    return true;
}


bool UCoreMonitor::isKernelAddress(uint64_t pc) const
{
    //XXX: deal with large address space awareness
    return true;
}

uint64_t UCoreMonitor::getPid(S2EExecutionState *s, uint64_t pc)
{
    
    return 0;
}

bool UCoreMonitor::getCurrentStack(S2EExecutionState *state, uint64_t *base, uint64_t *size)
{
    

    return true;
}

///////////////////////////////////////////////////////////////////////
/*
UCoreMonitorState::UCoreMonitorState()
{
    m_CurrentPid = -1;
}

UCoreMonitorState::~UCoreMonitorState()
{
	return;
}

//addbyxqx 
//what the difference between clone and factory?
UCoreMonitorState* UCoreMonitorState::clone() const
{
    return new UCoreMonitorState(*this);
}

PluginState *UCoreMonitorState::factory(Plugin *p, S2EExecutionState *state)
{
    return new UCoreMonitorState();
}
*/
