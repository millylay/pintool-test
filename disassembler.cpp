#include "pin.H"
#include <iostream>
#include <string>

/*void dis(string s)
{
    //string disassemble = INS_Disassemble(ins);
    puts(s.c_str());
}*/

/*VOID Instruction(INS ins)
{
    if(INS_IsMemoryRead(ins) || INS_IsMemoryWrite(ins) && INS_OperandIsReg(ins, 0) && INS_OperandIsMemory(ins, 1))
        INS_InsertCall(ins,
                       IPOINT_BEFORE,
                       (AFUNPTR)dis,
                       IARG_PTR, new string(INS_Disassemble(ins)),
                       IARG_END);
}*/

/*VOID onTrace(TRACE trace, VOID *v)
{
    RTN rtn = TRACE_Rtn(trace);
    if (!RTN_Valid(rtn))
        return;

    //puts(RTN_Name(rtn).c_str());
    //return;

    if(RTN_Name(rtn).compare("main")!=0 )
        return;



}*/

/*void Address(ADDRDELTA displacement, ADDRINT baseReg, ADDRINT indexReg, UINT32 scale)
{
    ADDRINT addr = displacement + baseReg + indexReg * scale;
    cout << "memory = " << std::hex << addr << endl;
}

void regValue(ADDRINT reg)
{
    cout << "reg = " << std::hex << reg << endl;
}

void Target(ADDRINT target)
{
    cout << "target = " << std::hex << target << endl;
}*/

void onLea(ADDRINT addr)
{
    cout << std::hex << addr << endl;
}

VOID instrumentINS(INS ins, VOID *v)
{
    /*if(INS_Opcode(ins) == XED_ICLASS_CMP && INS_OperandIsMemory(ins, 0) )
    {
       // for(int i=0; i<10 && INS_Valid(ins); ins = INS_Next(ins),i++)
            INS_InsertCall(ins,
                           IPOINT_BEFORE,
                           (AFUNPTR)dis,
                           IARG_PTR, new string(INS_Disassemble(ins)),
                           IARG_END);
    }*/

    if(INS_IsOriginal(ins) /*&& INS_Opcode(ins) == XED_ICLASS_CMP*/)
    {

        RTN rtn = INS_Rtn(ins);

        if(RTN_Valid(rtn))
        {
            string name = RTN_Name(rtn);
            if(name.find("fun2")!=string::npos/* || name.find("fun")!=string::npos*/)
            {
                ADDRINT addr = INS_Address(ins);
                cout << std::hex << addr << ": " << INS_Disassemble(ins) << endl;
                /*if(INS_IsUJmp(ins))
                    puts("unconditional branch");
                else if(INS_IsCJmp(ins))
                    puts("conditional branch");*/
                if(INS_IsMemoryRead(ins))
                    puts("read");
            }

            /*if(name.find("fun")!=std::string::npos)
            {
                if((INS_IsMemoryWrite(ins) || INS_IsMemoryRead(ins)) && INS_IsMov(ins))
                {
                    cout << INS_Disassemble(ins) << endl;
                    int n = INS_OperandCount(ins);
                    cout << "operand number: " << n << endl;
                    for(int i=0; i<n; i++)
                    {
                        if(INS_OperandIsReg(ins,i))
                        {
                            REG reg = INS_OperandReg(ins, i);
                            if(reg!=REG_INVALID())
                                printf("operand %d is %s\n", i, REG_StringShort(reg).c_str());
                        }
                    }
                }

            }*/
        }

    }


    //if(INS_IsCall(ins) /*&& INS_OperandIsImmediate(ins, 0)*/)
    //{
        //puts("biu");
        //string dis = INS_Disassemble(ins);

        //cout << INS_Disassemble(ins) << endl;
        //cout << INS_OperandCount(ins) << endl;
        //uint number = INS_OperandCount(ins);
       /* for(uint i = 0; i< number; i++)
        {
            if(INS_OperandIsMemory(ins, i))
            {
                printf("operand %u is memory\n", i);
                REG baseReg = INS_OperandMemoryBaseReg(ins, i);
                REG indexReg = INS_OperandMemoryIndexReg(ins, i);
                UINT32 scale = INS_OperandMemoryScale(ins, i);
                ADDRDELTA displacement = INS_OperandMemoryDisplacement(ins, i);

                if(REG_valid(baseReg) && REG_valid(indexReg))
                    cout << displacement << " + " << REG_StringShort(baseReg) << " + " << REG_StringShort(indexReg) << " * " << scale << endl;
                else if(REG_valid(indexReg))
                    cout << displacement << " + 0" << " + " << REG_StringShort(indexReg) << " * " << scale << endl;
                else if(REG_valid(baseReg))
                {
                    cout << displacement << " + " << REG_StringShort(baseReg) << " + 0 * " << scale << endl;
                    INS_InsertCall( ins,
                                    IPOINT_BEFORE,
                                    AFUNPTR(Address),
                                    IARG_UINT32, displacement,
                                    IARG_REG_VALUE, baseReg,
                                    IARG_UINT32, 0,
                                    IARG_UINT32, scale,
                                    IARG_END);
                }
                else
                    cout << displacement << endl;

            }
            else if(INS_OperandIsReg(ins, i))
            {
                printf("operand %u is reg\n", i);
                REG reg = INS_OperandReg(ins, i);
                if(REG_valid(reg))
                {
                    cout << REG_StringShort(reg) << endl;
                    INS_InsertCall( ins,
                                    IPOINT_BEFORE,
                                    AFUNPTR(regValue),
                                    IARG_REG_VALUE, reg,
                                    IARG_END);
                }
            }
            else if(INS_OperandIsImplicit(ins, i))
                printf("operand %u is implicit\n", i);
            else if(INS_OperandIsImmediate(ins, i))
            {
                printf("operand %u is immediate, value = %x\n", i, (UINT32)INS_OperandImmediate(ins, i));
            }
            else if(INS_OperandIsFixedMemop(ins, i))
                printf("operand %u is fixed memop\n", i);
            else if(INS_OperandIsBranchDisplacement(ins, i))
            {
                printf("operand %u is branch displacement \n", i);
                INS_InsertCall( ins,
                                IPOINT_BEFORE,
                                AFUNPTR(Target),
                                IARG_BRANCH_TARGET_ADDR,
                                IARG_END);
            }
            else
            {
                printf("operand %u is unknown\n", i);
            }
        }*/
        /*if(INS_OperandIsImmediate(ins, 1))
        {
            puts("biubiu");
            ADDRINT addr = INS_OperandImmediate(ins, 1);
            cout << std::hex << addr << endl;
        }*/


        /*string  rtn_name = RTN_FindNameByAddress(0x8048523);
        if(rtn_name.find("free") != std::string::npos)
            cout << rtn_name << endl;*/
    //}
}



    KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
                                "o", "inscount.out", "specify output file name");

    VOID Fini(INT32 code, VOID *v)
    {
        puts("Exit");
    }

    INT32 Usage()
    {
        cerr << KNOB_BASE::StringKnobSummary() << endl;
        return -1;
    }

    int main(int argc, char* argv[])
    {
        if (PIN_Init(argc, argv))
            return Usage();

        PIN_InitSymbols();

        //TRACE_AddInstrumentFunction(onTrace, 0);

        INS_AddInstrumentFunction(instrumentINS, 0);

        PIN_AddFiniFunction(Fini, 0);

        PIN_StartProgram();

        return 0;
    }
