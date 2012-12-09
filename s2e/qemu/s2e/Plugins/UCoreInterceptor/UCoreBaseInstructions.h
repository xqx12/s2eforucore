/*
 * S2E Selective Symbolic Execution Framework For Ucore OS
 *
 * Add by xqx 20121108
 *
 */

#ifndef _UCORE_BASEINSTRUCTIONS_H_20121108

#define _UCORE_BASEINSTRUCTIONS_H_20121108


#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>

#include <s2e/S2EExecutionState.h>

//#include <s2e/Plugins/ModuleDescriptor.h>
//#include "UCoreStab.h"


namespace s2e {
namespace plugins {



class UCoreBaseInstructions:public Plugin
{
    S2E_PLUGIN


public:
    UCoreBaseInstructions(S2E* s2e): Plugin(s2e) {}  //what is meaning?
    virtual ~UCoreBaseInstructions();
    void initialize();
	void debug_print(std::string str);
	void debug_print(const char* fmt, ...);

	//handle custom opcode just for ucore
	void handleBuiltInUCoreOps(S2EExecutionState* state, 
						  uint64_t opcode);
	
	
private:
	//first handle custom symbol opcode when a custom symbol accur
	void onUCoreCustomInstruction(S2EExecutionState* state, 
							 uint64_t opcode);
	
	void makeSymbolic(S2EExecutionState *state, bool makeConcolic);
    void concretize(S2EExecutionState *state, bool addConstraint);
	void killState(S2EExecutionState *state);
	void printMessage(S2EExecutionState *state, bool isWarning);
	void printExpression(S2EExecutionState *state);
	
//	std::string system_map_file;
	
	
};


}

}


#endif
