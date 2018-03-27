#include "pin.H"
#include <iostream>
#include <fstream>
#include <string>
#include <set>

using namespace std;

#define ARG_SIZE 5
FILE* log_file;
set<string> free_call;

KNOB<string> workspace(KNOB_MODE_WRITEONCE, "pintool", "Workspace-Directory",
                       "/home/yancai/Research/vulnerability_detection/dis/workspace/", "Please specify a workspace dir/folder");

INT32 Usage()
{
    cerr << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

VOID onFini(INT32 code, VOID *v)
{
    set<string>::iterator iter = free_call.begin();
    while(iter!=free_call.end())
    {
        string name = *iter;
        fprintf(log_file, "%s\n", name.c_str());
        iter++;
    }
}

#define ignoredIMGNo 8
char ignoredIMG[ignoredIMGNo][50] = {"/lib/i386", "ld-", "libpthread", "libc.so", "libstdc++.so", "libm.so", "libcrypto.so", "/lib/ld-linux.so.2"};

static bool ignoreIMG(IMG img)
{
    string name = IMG_Name(img);

    for(int i=0; i< ignoredIMGNo; i++)
    {
        if( name.find(ignoredIMG[i]) != string::npos) return true;
    }
    return false;
}
#undef ignoredIMGNo

////////////////////////
#define ignoredRTNNo 9
char ignoreRTNs[ignoredRTNNo][52] = {"malloc_trim", "__kernel_vsyscall",
                                     "malloc_usable_size", "malloc_set_state", "pthread_exit", "_start", "frame_dummy", "_init", "_fini"
                                    };

static bool ignoreRTN(RTN rtn)
{
    string name = RTN_Name(rtn);

    for(int i=0; i< ignoredRTNNo; i++)
    {
        if( name.find(ignoreRTNs[i]) != string::npos) return true;
    }
    return false;
}
#undef ignoredRTNNo

////////////////////////
static inline bool ignoreSEC(SEC sec)
{
    //TODO: only instrument code section ".text"?
    return SEC_Name(sec).find(".text") == string::npos;
}

static UINT32 operandToMemoryOperand(INS inst, UINT32 operand)
{
    UINT32  memOp = 0;
    UINT32  opCount = INS_MemoryOperandCount( inst );

    for( UINT32 i = 0; i < opCount; i++ )
    {
        UINT32 k = INS_MemoryOperandIndexToOperandIndex( inst, i );

        if( k == operand )
            memOp = i;
    }

    return memOp;
}


#define DISTANCE 20

// test
static void instrumentTEST(INS ins)
{
    if( !INS_IsOriginal(ins))
        //|| !INS_IsMov(inst))
        return;

    // cmp?????
    if(INS_Opcode(ins) == XED_ICLASS_CMP && INS_OperandIsMemory(ins, 0) && INS_OperandIsImmediate(ins, 1))
    {
        if(INS_OperandImmediate(ins, 1)!=0)
            return;

        int counter = 0;
        INS next_ins = INS_Next(ins);

        while(counter < DISTANCE && INS_Valid(next_ins)
                && !(INS_IsBranch(next_ins) && !INS_HasFallThrough(next_ins))     // unconditional braches
                && !INS_IsRet(next_ins) && !INS_IsSysret(next_ins))
        {
            if(INS_IsDirectCall(next_ins))
            {
                ADDRINT target_addr = INS_DirectBranchOrCallTargetAddress(next_ins);
                string rtn_name = RTN_FindNameByAddress(target_addr);
                if(rtn_name.find("free")!= string::npos)
                {
                    free_call.insert(rtn_name);
                    return;
                }
            }
            counter++;
            next_ins = INS_Next(next_ins);
        }
        return;
    }

    // test instruction
    string rtn_name;
    ADDRINT target_addr;
    if(INS_Opcode(ins) == XED_ICLASS_TEST && INS_OperandCount(ins) >= 2
            && REG_valid(INS_OperandReg(ins, 0)) && REG_valid(INS_OperandReg(ins, 1)))
    {
        int counter = 0;
        bool free_found = false;
        INS next_ins = INS_Next(ins);
        string nextIns[DISTANCE] = {""};

        while(counter < DISTANCE && INS_Valid(next_ins)
                && !(INS_IsBranch(next_ins) && !INS_HasFallThrough(next_ins))
                && !INS_IsRet(next_ins) && !INS_IsSysret(next_ins))
        {
            nextIns[counter] = INS_Disassemble(next_ins);
            if(INS_IsDirectCall(next_ins))
            {
                target_addr = INS_DirectBranchOrCallTargetAddress(next_ins);
                rtn_name = RTN_FindNameByAddress(target_addr);

                if(rtn_name.find("free") != string::npos)
                {
                    free_found = true;
                    break;
                }
            }
            counter++;
            next_ins = INS_Next(next_ins);
        }

        if(!free_found)
            return;

        // search for the possible same pointer
        counter = 0;

        INS prev_ins = INS_Prev(ins);
        while(counter<ARG_SIZE && INS_Valid(prev_ins) && !INS_IsBranchOrCall(prev_ins) && !INS_IsRet(prev_ins) && !INS_IsSysret(prev_ins))
        {
            if(INS_IsMemoryRead(prev_ins))
            {
                UINT32  memop = 0;
                for(UINT32 i = 0; i < INS_OperandCount(prev_ins); i++ )
                {
                    if( INS_OperandIsMemory( prev_ins, i ) )
                    {
                        memop = operandToMemoryOperand(prev_ins, i);
                        if(INS_MemoryOperandIsRead( prev_ins, memop ))
                            break;
                    }
                }
                counter++;
                string dis = INS_Disassemble(prev_ins);
                for(int i=0; i<DISTANCE; i++)
                {
                    if(dis.compare(nextIns[i])==0)
                    {
                        free_call.insert(rtn_name);
                        break;
                    }
                }
            }
            prev_ins = INS_Prev(prev_ins);
        }
    }
}

VOID onRoutine(RTN rtn, VOID *v)
{
    if (!RTN_Valid(rtn))
        return;

    SEC sec = RTN_Sec(rtn);
    if (!SEC_Valid(sec))
        return;

    IMG img = SEC_Img(sec);
    if (!IMG_Valid(img))
        return;

    //puts("valid ");
    if (ignoreIMG(img) || ignoreRTN(rtn) || ignoreSEC(sec))
        return;

    RTN_Open(rtn);

    for(INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
    {
        instrumentTEST(ins);
    }
    RTN_Close(rtn);
}


void initWorkspace()
{
    log_file = fopen("free_log", "a+");
}

int main(int argc, char *argv[])
{
    if (PIN_Init(argc, argv))
        return Usage();

    PIN_InitSymbols();

    initWorkspace();

    RTN_AddInstrumentFunction(onRoutine, 0);

    PIN_AddFiniFunction(onFini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}

