/*
 * S2E Selective Symbolic Execution Framework For Ucore OS
 *
 * Add by xqx 20121030
 *
 */

#ifndef _UCORE_PLUGIN_H

#define _UCORE_PLUGIN_H


#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/Plugins/OSMonitor.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/ModuleDescriptor.h>
#include "UCoreStab.h"

#include <s2e/Plugins/FunctionMonitor.h>


namespace s2e {
namespace plugins {


typedef std::set<uint64_t> PidSet;
typedef std::map<std::string, uint64_t> ModuleSizeMap;

class UCoreMonitor:public OSMonitor
{
    S2E_PLUGIN


public:
    UCoreMonitor(S2E* s2e): OSMonitor(s2e) {}  //what is meaning?
    virtual ~UCoreMonitor();
    void initialize();
	void debug_print(std::string str);
	void debug_print(const char* fmt, ...);

	//addbyxqx20121030
	//NOTE: if you declare a class from a base class, you should add virtual functions of the base class.
	virtual bool getImports(S2EExecutionState *s, const ModuleDescriptor &desc, Imports &I);
    virtual bool getExports(S2EExecutionState *s, const ModuleDescriptor &desc, Exports &E);
	
	virtual bool isKernelAddress(uint64_t pc) const;
    virtual uint64_t getPid(S2EExecutionState *s, uint64_t pc);
    virtual bool getCurrentStack(S2EExecutionState *s, uint64_t *base, uint64_t *size);

	//addbyxqx20121101 copy from ucores2e 
	void slotCall(S2EExecutionState* state, uint64_t pc);
	void slotCall_IND(S2EExecutionState* state, uint64_t pc);
	
	/*-------------signals------------------*/
	/* For funtion monitor */
	typedef sigc::signal<void, ExecutionSignal *, S2EExecutionState*, std::string, uint64_t> TransitionSignal;
	//TransitionSignal onFunctionTransition;
	TransitionSignal onFunctionCalling;	
	
private:
	
	std::string system_map_file;
	//Symbol table
      typedef struct __symbol_struct{
        uint64_t addr;
        char type;
        std::string name;
      } symbol_struct;
      typedef std::map<uint64_t, symbol_struct> SymbolTable;
      typedef std::map<std::string, uint64_t> SymbolMap;
	
	//UCore System Map
    SymbolMap sMap;
    SymbolTable sTable;
	
	//mointor switch
    bool m_MonitorThreads;
    bool m_MonitorFunction;
	
	//Kernel Addresses
    uint64_t m_KernelBase;
	uint64_t getKernelStart() const;
	
	//STAB Section Address, sysbomls table maybe
    uint64_t m_StabStart;
    uint64_t m_StabEnd;
    uint64_t m_StabStrStart;
    uint64_t m_StabStrEnd;
	bool first;
	//Stab Array
    UCoreStab* stab_array;
    UCoreStab* stab_array_end;
    char* stabstr_array;
    char* stabstr_array_end;
	
	//plugins 
	FunctionMonitor *m_func_monitor;
	
	
	//Functions
	
	// parse files
    void parseSystemMapFile();
	void parseUCoreStab(S2EExecutionState *state);
	
	//print functions
    //void printUCorePCB(UCorePCB* ucorePCB);
    void printUCoreStabs();
	
	//Signal connectors 
    void onTranslateBlockEnd(ExecutionSignal* signal, S2EExecutionState *state,
                               TranslationBlock *tb, uint64_t pc,
                               bool, uint64_t);
	
	// signal slot functions
    void slotFunctionCalling(ExecutionSignal *signal, S2EExecutionState *state
                               ,std::string fname, uint64_t pc);
	
	/**********For FunctionMonitor Test ******************
	void slotTranslateBlockStart(ExecutionSignal *signal,
			S2EExecutionState *state,
			TranslationBlock *tb,
			uint64_t pc);
	void myFunctionCallMonitor(S2EExecutionState* state, FunctionMonitorState *fns);
	void myFunctionRetMonitor(S2EExecutionState *state);
	*********For FunctionMonitor Test End ******************/
	
};

//why need this class? what does it do ?
/*
class UCoreMonitorState:public PluginState
{
private:
    uint64_t m_CurrentPid;

public:
    UCoreMonitorState();
    virtual ~UCoreMonitorState();
    virtual UCoreMonitorState* clone() const;
    static PluginState *factory(Plugin *p, S2EExecutionState *state);

    friend class UCoreMonitor;
};
*/
} // namespace plugins
} // namespace s2e


#endif
