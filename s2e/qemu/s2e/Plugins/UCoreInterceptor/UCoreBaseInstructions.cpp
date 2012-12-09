/*
 * S2E Selective Symbolic Execution Framework For Ucore OS
 *
 * Addbyxqx 20121108
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
#include "UCoreBaseInstructions.h"

#include <s2e/S2EExecutor.h>

#define _XQX_DEBUG
//#define _XQX_PRINT_MON
#define _XQX_PRINT_FILE


//namespace s2e {
//namespace plugins {

using namespace s2e;
using namespace plugins;
using namespace std;
using namespace klee;

//global var
FILE *ofBI = NULL;

//
S2E_DEFINE_PLUGIN(UCoreBaseInstructions, "Plugin for monitoring UCore Inst", "UCoreBaseInstructions");



UCoreBaseInstructions::~UCoreBaseInstructions()
{
	
    return;
}

void UCoreBaseInstructions::initialize()
{
	s2e()->getDebugStream() << "Hello, UCoreBaseInstructions \n " ;
   
   ofBI = fopen("outBI.txt", "w");
   if( ofBI == NULL){
	  s2e()->getWarningsStream() << "open out file error \n";
   }
   debug_print("Hello, UCoreBaseInstructions %d\n", 1);	
   
   s2e()->getCorePlugin()->onCustomInstruction.connect(
	   sigc::mem_fun(*this, &UCoreBaseInstructions::onUCoreCustomInstruction));
   
   return;
}

void UCoreBaseInstructions::onUCoreCustomInstruction(S2EExecutionState* state, 
        uint64_t opcode)
{
    uint8_t opc = (opcode>>8) & 0xFF;
	//debug_print("[onUCoreCustomInstruction] opc=%x\n", opc);
	//handle the custom symbol opcode 
    if (opc <= 0x70) {
        handleBuiltInUCoreOps(state, opcode);
    }
}

void UCoreBaseInstructions::handleBuiltInUCoreOps(S2EExecutionState* state, uint64_t opcode)
{
	debug_print("[UCORE]handleBuiltInUCoreOps opcode=%x\n", opcode);
	//copy from s2ecode  addbyxqx20121108
	uint8_t opc = (opcode>>8) & 0xFF;
	switch(opc){
		//first enable forking
        case 9:
            state->enableForking();
            break;
        case 3: { /* s2e_make_symbolic */
            makeSymbolic(state, false);
            break;
        }
        case 10:
            state->disableForking();
            break;
        case 0x21: { /* replace an expression by one concrete example */
            concretize(state, false);
            break;
        }		
		case 6: { /* s2e_kill_state */
            killState(state);
            break;
		}
		case 0x10: { /* s2e_print_message */
            printMessage(state, opcode >> 16);
            break;
        }
        case 7: { /* s2e_print_expression */
            printExpression(state);
            break;
        }
		
	}
	
}

void UCoreBaseInstructions::makeSymbolic(S2EExecutionState *state, bool makeConcolic)
{
	debug_print("[UCORE]makeSymbolic makeConcolic=%d\n", makeConcolic);
    uint32_t address, size, name; // XXX
    bool ok = true;
    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]),
                                         &address, 4);
    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EBX]),
                                         &size, 4);
    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_ECX]),
                                         &name, 4);

//	debug_print("[UCORE]makeSymbolic name=%x \n", name);
	
    if(!ok) {
        s2e()->getWarningsStream(state)
				<< "ERROR: symbolic argument was passed to s2e_op "
				" insert_symbolic opcode\n";
        return;
    }

    std::string nameStr = "unnamed";
    if(name && !state->readString(name, nameStr)) {
        s2e()->getWarningsStream(state)
                << "Error reading string from the guest\n";
    }

    s2e()->getMessagesStream(state)
            << "Inserting symbolic data at " << hexval(address)
            << " of size " << hexval(size)
            << " with name '" << nameStr 
			<< " guestpc '" <<  hexval(state->getPc()) << "'\n";

    std::vector<unsigned char> concreteData;
    vector<ref<Expr> > symb;

    if (makeConcolic) {
        for (unsigned i = 0; i< size; ++i) {
            uint8_t byte = 0;
            if (!state->readMemoryConcrete8(address + i, &byte)) {
                s2e()->getWarningsStream(state)
						<< "Can not concretize/read symbolic value"
						<< " at " << hexval(address + i) << ". System state not modified.\n";
                return;
            }
            concreteData.push_back(byte);
        }
        symb = state->createConcolicArray(nameStr, size, concreteData);
    } else {
        symb = state->createSymbolicArray(nameStr, size);
    }


    for(unsigned i = 0; i < size; ++i) {
        if(!state->writeMemory8(address + i, symb[i])) {
            s2e()->getWarningsStream(state)
					<< "Can not insert symbolic value"
					<< " at " << hexval(address + i)
					<< ": can not write to memory\n";
        }
    }
}


void UCoreBaseInstructions::concretize(S2EExecutionState *state, bool addConstraint)
{
	debug_print("[UCORE]concretize addConstraint=%d\n", addConstraint);
    uint32_t address, size;

    bool ok = true;
    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]),
                                         &address, 4);
    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EBX]),
                                         &size, 4);

    if(!ok) {
        s2e()->getWarningsStream(state)
				<< "ERROR: symbolic argument was passed to s2e_op "
				" get_example opcode\n";
        return;
    }

    for(unsigned i = 0; i < size; ++i) {
        if (!state->readMemoryConcrete8(address + i, NULL, S2EExecutionState::VirtualAddress, addConstraint)) {
            s2e()->getWarningsStream(state)
					<< "Can not concretize memory"
					<< " at " << hexval(address + i) << '\n';
        }
    }
}


void UCoreBaseInstructions::killState(S2EExecutionState *state)
{
	debug_print("[UCORE]killState \n");
    std::string message;
    uint32_t messagePtr;
    bool ok = true;
    klee::ref<klee::Expr> status = state->readCpuRegister(CPU_OFFSET(regs[R_EAX]), klee::Expr::Int32);
    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EBX]), &messagePtr, 4);

    if (!ok) {
        s2e()->getWarningsStream(state)
				<< "ERROR: symbolic argument was passed to s2e_kill_state \n";
    } else {
        message="<NO MESSAGE>";
        if(messagePtr && !state->readString(messagePtr, message)) {
            s2e()->getWarningsStream(state)
					<< "Error reading message string from the guest\n";
        }
    }

    //Kill the current state
    s2e()->getMessagesStream(state) << "Killing state "  << state->getID() << '\n';
    std::ostringstream os;
    os << "State was terminated by opcode\n"
       << "            message: \"" << message << "\"\n"
       << "            status: " << status;
    s2e()->getExecutor()->terminateStateEarly(*state, os.str());
}


void UCoreBaseInstructions::printMessage(S2EExecutionState *state, bool isWarning)
{
    uint32_t address = 0; //XXX
    bool ok = state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]),
			  &address, 4);
    if(!ok) {
        s2e()->getWarningsStream(state)
				<< "ERROR: symbolic argument was passed to s2e_op "
				" message opcode\n";
        return;
    }

    std::string str="";
    if(!address || !state->readString(address, str)) {
        s2e()->getWarningsStream(state)
                << "Error reading string message from the guest at address "
                << hexval(address) << '\n';
    } else {
        llvm::raw_ostream *stream;
        if(isWarning)
            stream = &s2e()->getWarningsStream(state);
        else
            stream = &s2e()->getMessagesStream(state);
        (*stream) << "Message from guest (" << hexval(address) <<
				  "): " <<  str << '\n';
    }
}

void UCoreBaseInstructions::printExpression(S2EExecutionState *state)
{
	debug_print("[UCORE]printExpression \n");
    //Print the expression
    uint32_t name; //xxx
    bool ok = true;
    ref<Expr> val = state->readCpuRegister(offsetof(CPUX86State, regs[R_EAX]), klee::Expr::Int32);
    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_ECX]),
                                         &name, 4);

//	debug_print("[UCORE]printExpression name=%x \n", name);
	
    if(!ok) {
        s2e()->getWarningsStream(state)
				<< "ERROR: symbolic argument was passed to s2e_op "
				"print_expression opcode\n";
        return;
    }

    std::string nameStr = "<NO NAME>";
    if(name && !state->readString(name, nameStr)) {
        s2e()->getWarningsStream(state)
                << "Error reading string from the guest\n";
    }


    s2e()->getMessagesStream() << "SymbExpression " << nameStr << " - "
                               <<val << ", pc=" << hexval(state->getPc())  << '\n';
}



void UCoreBaseInstructions::debug_print(string str)
{
#ifdef  _XQX_DEBUG
	s2e()->getDebugStream() << str << "\n";
	cout << str << "\n" ;
#endif
	return ;
}


void UCoreBaseInstructions::debug_print(const char* fmt, ...)
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
	if(ofBI!=NULL) vfprintf(ofBI,fmt,ap);
	va_end(ap);
#endif		
#endif
	return ;
}


//}//end namespace plugins

//}//end namespace s2e


