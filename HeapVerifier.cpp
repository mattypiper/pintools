#include "pin.H"

#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <syscall.h>
#include <memory>
#include <iostream>
#include <sstream>
#include <fstream>
#include <unordered_map>
#include <mutex>
#include <iomanip>
#include <cassert>
#include <string.h>

#define MMAP 	"mmap"
#define REALLOC "realloc"
#define CALLOC 	"calloc"
#define MALLOC 	"malloc"
#define MALLOC_USABLE_SIZE 	"malloc_usable_size"
#define SBRK 	"sbrk"
#define FREE 	"free"

using namespace std;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
	"o", "HeapTrace.txt", "Heap Verifier Output Filename");

ofstream TraceFile;
// beginning and end of main binary load address
pair<ADDRINT, ADDRINT> gMainImageAddress;

struct RegionAttributes {
	RegionAttributes(size_t s, int prot, string name = "") :
		Size(s), Prot(prot), Name(name) {}
	size_t Size;
	int Prot;
	string Name;
};
typedef shared_ptr<RegionAttributes> RegionAttributesPtr;
typedef pair<ADDRINT, RegionAttributesPtr> MapPair;
typedef unordered_map<ADDRINT, RegionAttributesPtr> MemoryMap;
typedef MemoryMap::iterator MapIter;
typedef unordered_map<ADDRINT, string> StringMap;
typedef StringMap::const_iterator StringMapCIter;
typedef unordered_map<pid_t, MapPair> ThreadedMemoryMap;
typedef ThreadedMemoryMap::iterator ThreadedMemoryMapIter;
typedef pair<pid_t, MapPair> ThreadedMapPair;

MemoryMap gImageMap;
ThreadedMemoryMap gStackMap;
MemoryMap gHeapMap;
MemoryMap gFreeMap;

mutex gHeapMutex;
mutex gFreeMutex;
mutex gImageMutex;

StringMap gInstructions;

// Used in before/after callbacks to track heap allocs
// TODO this doesn't work for multiple threads... convert to map<threadid,pair<addr,size>>
size_t gAllocSize = 0;
ADDRINT gMallocRetAddr = 0;
ADDRINT gMallocUsableAddress = 0;
ADDRINT gMallocUsableRet = 0;
int gAllocProt = 0;

// TODO move to utility file
const char COLOR_RED[] = "\033[1;31m";
const char COLOR_YELLOW[] = "\033[1;33m";
const char COLOR_LIGHT_CYAN[] = "\033[1;36m";
const char COLOR_RESET[] = "\033[0m";
void hexdump(ostringstream& ss, const char *p, size_t len)
{
	size_t r, c;
	ss << hex;
	ss << "+==== 0x" << p << " ====+" << endl;
	for (r = 0; r < len/8; ++r) {
		ss << "| ";
		for (c = 0; c < 8; ++c) {
			ss << (unsigned char)p[r*8+c];
			if (c == 3) ss << " ";
		} ss << " |" << endl;
	}
}

pid_t gettid (void)
{
	return syscall(__NR_gettid);
}

/* Check if address belongs to main executable */
bool isMain(ADDRINT ret)
{
	PIN_LockClient();
	IMG im = IMG_FindByAddress(ret);
	PIN_UnlockClient();
	return IMG_Valid(im) ? IMG_IsMainExecutable(im) : false;
}

bool IsAddressInMap(MemoryMap map, ADDRINT addr)
{
	for (MapIter it = map.begin(); it != map.end(); ++it) {
		ADDRINT start = it->first;
		ADDRINT end = start + it->second->Size;
		if (addr >= start && addr < end) {
			return true;
		}
	}
	return false;
}

bool IsStackMemory(MapPair stackMap, ADDRINT testaddr)
{
	ADDRINT top = stackMap.first;
	ADDRINT bottom = top + stackMap.second->Size;
	if (testaddr < top && testaddr > bottom) return true;
	else return false;
}

/* check if an address is part of allocated chunk  */
bool IsAllocatedAddress(ADDRINT addr)
{
	pid_t tid = gettid();
	ThreadedMemoryMapIter tmmi = gStackMap.find(tid);
	if (tmmi != gStackMap.end()) {
		if (IsStackMemory(tmmi->second, addr))
			return true;
	}
	return IsAddressInMap(gImageMap, addr) || IsAddressInMap(gHeapMap, addr);
}

bool IsFreedAddress(ADDRINT addr)
{
	return IsAddressInMap(gFreeMap, addr);
}

/* for malloc, sbrk, realloc allocations */
void AllocBefore(string* name, size_t size, ADDRINT ret)
{
	// cout << "malloc: " << name << " 0x" << hex << size << " 0x" << ret << endl;
	gMallocRetAddr = ret;
	gAllocSize = size;
	gAllocProt = PROT_READ | PROT_WRITE;
	// TraceFile << (ret-5) << "@" << *name << "[" << size << "]" << endl;
	// TODO this crashes? delete name;
}

/* for mmap allocations */
void MmapBefore(string* name, size_t size, int prot, ADDRINT ret)
{
	// cout << "mmap: " << name << " 0x" << hex << size << " 0x" << ret << endl;
	gMallocRetAddr = ret;
	gAllocSize = size;
	gAllocProt = prot;
	// TraceFile << (ret-5) << "@" << *name << "[" << size << "]" << endl;
	// TODO delete name crashes?
}

/* for calloc allocation */
void CallocBefore(string* name, size_t nmemb, size_t size, ADDRINT ret)
{
	// cout << "calloc: " << name << " 0x" << hex << size << " 0x" << ret << endl;
	gMallocRetAddr = ret;
	gAllocSize = nmemb * size;
	gAllocProt = PROT_READ | PROT_WRITE;
	// TraceFile << (ret-5) << "@" << *name << "[" << nmemb*size << "]" << endl;
	// TODO delete name crashes?
}

void MallocUsableBefore(string* name, ADDRINT pointer, ADDRINT ret)
{
	if (isMain(ret)) {
		gMallocUsableAddress = pointer;
		gMallocUsableRet = ret;
	}
}

// malloc_usable_size is potentially usable to determine how much
// chunk data is available and write to the chunk legally (eg plaiddb)
void MallocUsableAfter(size_t size)
{
	// cout << "malloc usable: " << size << endl;
	if (size == 0)
		return;

	{
		lock_guard<mutex> lk(gHeapMutex);
		MapIter it = gHeapMap.find(gMallocUsableAddress);
		if (it != gHeapMap.end()) {
			// TraceFile << "Updating heap map @ " << gMallocUsableAddress << " from " << it->second->Size << " to " << size << endl;
			it->second->Size = size;	
		}
	}
}

void AllocAfter(ADDRINT newalloc)
{
	if (!newalloc)
		return;
	ostringstream oss;
	oss << hex << setfill('0');
	oss << "Allocation @ 0x" << setw(8) << newalloc << ", size 0x" << gAllocSize << endl;
	TraceFile << oss.str();
	// cout << oss.str();

	{
		lock_guard<mutex> lk(gHeapMutex);
		MapIter it = gHeapMap.find(newalloc);
		if (it == gHeapMap.end()) {
			// new allocation, track it
			gHeapMap.insert(make_pair(newalloc,
				RegionAttributesPtr(new RegionAttributes(gAllocSize, gAllocProt))));
		} else {
			// allocation already exists, update size
			it->second->Size = gAllocSize;
		}
	}

	{
		lock_guard<mutex> lk(gFreeMutex);
		for (MapIter it = gFreeMap.begin(); it != gFreeMap.end(); ++it) {
			ADDRINT start = it->first;
			shared_ptr<RegionAttributes> pAttr = it->second;
			ADDRINT end = start + pAttr->Size;
			if (newalloc >= start && newalloc <= end) {
				// reusing a free chunk
				if (newalloc == start && pAttr->Size == gAllocSize) {
					// full chunk reuse
					gFreeMap.erase(it);
				} else if (newalloc == start && gAllocSize < pAttr->Size) {
					// partial chunk reuse, case 1 (start of chunk)
					gFreeMap.erase(it);
					gFreeMap.insert(make_pair(newalloc + gAllocSize,
						RegionAttributesPtr(new RegionAttributes(
							pAttr->Size - gAllocSize, pAttr->Prot))));
				} else if (newalloc > start && gAllocSize < pAttr->Size) {
					// partial chunk reuse, case 2 (middle of chunk)
					ADDRINT oldChunk = it->first;
					gFreeMap.erase(it);
					// always have a before chunk
					gFreeMap.insert(make_pair(oldChunk,
						RegionAttributesPtr(new RegionAttributes(
							newalloc - start, pAttr->Prot))));
					// sometimes have an after chunk
					if (newalloc + gAllocSize < end) {
						gFreeMap.insert(make_pair(newalloc + gAllocSize,
							RegionAttributesPtr(new RegionAttributes(end - newalloc - gAllocSize, pAttr->Prot))));
					}
				} else if (newalloc == end) {
					// shouldn't really happen, I don't think
					assert(newalloc != end);
				}
			}
		}
	}
}

/* filter stack based read/write operations */
/* TODO check stack access */
bool INS_has_sp(INS ins) 
{
	for (unsigned int i = 0; i < INS_OperandCount(ins); i++) {
		REG op = INS_OperandMemoryBaseReg(ins, i);
		if ((op == REG_STACK_PTR) || (op == REG_GBP)) return true;
	}
	return false;
}

/* filter tls reads and writes */
/* TODO check tls access */
bool INS_has_tls(INS ins)
{
#ifdef __i386__ 
	if (INS_RegRContain(ins, REG_SEG_GS)) return true;
#else
	if (INS_RegRContain(ins, REG_SEG_FS)) return true;
#endif
	return false;
}

void RtnInsertCall(IMG img, const string &funcname)
{
	RTN rtn = RTN_FindByName(img, funcname.c_str());

	if (!RTN_Valid(rtn))
		return;

	RTN_Open(rtn);
	
	string* pFuncName(new string(funcname));

	/* On function call */
	if (funcname == CALLOC) {
		RTN_InsertCall(rtn,
			IPOINT_BEFORE,
			(AFUNPTR)CallocBefore,
			IARG_PTR,
			pFuncName,
			IARG_FUNCARG_CALLSITE_VALUE, 0,
			IARG_FUNCARG_CALLSITE_VALUE, 1,
			IARG_RETURN_IP,
			IARG_END
		);
	} else if ((funcname == MALLOC) || (funcname == SBRK) || (funcname == FREE)) {
		RTN_InsertCall(rtn,
			IPOINT_BEFORE,
			(AFUNPTR)AllocBefore,
			IARG_PTR,
			pFuncName,
			IARG_FUNCARG_CALLSITE_VALUE, 0,
			IARG_RETURN_IP,
			IARG_END
		);
	} else if (funcname == REALLOC) {
		RTN_InsertCall(rtn,
			IPOINT_BEFORE,
			(AFUNPTR)AllocBefore,
			IARG_ADDRINT,
			pFuncName,
			IARG_FUNCARG_CALLSITE_VALUE, 1,
			IARG_RETURN_IP,
			IARG_END
		);
	} else if (funcname == MALLOC_USABLE_SIZE) {
		RTN_InsertCall(rtn,
			IPOINT_BEFORE,
			(AFUNPTR)MallocUsableBefore,
			IARG_ADDRINT,
			pFuncName,
			IARG_FUNCARG_CALLSITE_VALUE, 0,
			IARG_RETURN_IP,
			IARG_END
		);
	} else if (funcname == MMAP) {
		RTN_InsertCall(rtn,
			IPOINT_BEFORE,
			(AFUNPTR)MmapBefore,
			IARG_ADDRINT,
			pFuncName,
			IARG_FUNCARG_CALLSITE_VALUE, 1,
			IARG_FUNCARG_CALLSITE_VALUE, 2,
			IARG_RETURN_IP,
			IARG_END
		);
	}
	RTN_Close(rtn);
}

void Image(IMG img, void *v)
{
	TraceFile << "[+] New Image Loaded" << endl << left << IMG_Name(img) << " @ " <<
		IMG_LowAddress(img) << " - " << IMG_HighAddress(img) << endl;

	// populate gImageMap
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
		if ((!SEC_Valid(sec)) || (SEC_Address(sec) == 0)) continue;
		int prot = 0;
		prot |= SEC_IsReadable(sec) ? PROT_READ : 0;
		prot |= SEC_IsWriteable(sec) ? PROT_WRITE : 0;
		prot |= SEC_IsExecutable(sec) ? PROT_EXEC : 0;
		pair<MapIter, bool> insert_ret =
			gImageMap.insert(make_pair(SEC_Address(sec),
				shared_ptr<RegionAttributes>(new RegionAttributes(
					SEC_Size(sec),
					prot,
					string(IMG_Name(img) + "::" + SEC_Name(sec))
				))
			));
		if (insert_ret.second == false) {
			TraceFile << "WARNING: " << SEC_Address(sec) << " already exists in ImageMap!" << endl;
		}
		TraceFile << "  " << setw(20) << SEC_Name(sec) << ": " << setw(20) << SEC_Address(sec) << " " << setw(10) << SEC_Size(sec) << " ";
		if (prot & PROT_READ) TraceFile << "R";
		if (prot & PROT_WRITE) TraceFile << "W";
		if (prot & PROT_EXEC) TraceFile << "X";
		TraceFile << endl;
	}

	// Get main binary load address
	if (IMG_IsMainExecutable(img)) {
		gMainImageAddress = pair<ADDRINT, ADDRINT>(IMG_LowAddress(img), IMG_HighAddress(img));
	}

	RtnInsertCall(img, SBRK);
	RtnInsertCall(img, MALLOC);
	RtnInsertCall(img, FREE);
	RtnInsertCall(img, MMAP);
	RtnInsertCall(img, REALLOC);
	RtnInsertCall(img, CALLOC);
	RtnInsertCall(img, MALLOC_USABLE_SIZE);
}

// This function logs writes to allocated areas.
// @arg type "WRREG" or "WRIMM"
void write_instruction(ADDRINT address, ADDRINT write_address, ADDRINT regval, char *type)
{
	StringMapCIter it = gInstructions.find(address);
	if (it == gInstructions.end()) assert(0);
	//ADDRINT offset = address - gMainImageAddress.first;
	ostringstream oss;
	oss << hex;

	if (IsFreedAddress(write_address)) {
		oss << "[!] Write to free address: 0x";
		oss << left << setw(6) << address << setw(36)  << it->second;
		oss << type << " MEM[0x" << setfill('0') << setw(8) << write_address << "] VAL[0x" << regval << "]" << endl;
		TraceFile << oss.str();
		cerr << COLOR_RED << oss.str() << COLOR_RESET;
	} else if (!IsAllocatedAddress(write_address)) {
		oss << "[!] Write OOB: 0x";	
		oss << left << setw(6) << address << setw(36)  << it->second;
		oss << type << " MEM[0x" << setfill('0') << setw(8) << write_address << "] VAL[0x" << regval << "]" << endl;
		TraceFile << oss.str();
		cerr << COLOR_RED << oss.str() << COLOR_RESET;
	}
}

void read_instruction(ADDRINT address, ADDRINT read_address, ADDRINT size)
{
	ostringstream oss; oss << hex;
	StringMapCIter it = gInstructions.find(address);
	if (it == gInstructions.end()) assert(0);

	//ADDRINT offset = address - gMainImageAddress.first;
	ADDRINT value = 0;
	if ((size == 8) || (size == 4)) {
		value = *(ADDRINT *)read_address;
	} else if (size == 1) {
		value = *(char *) read_address;
	}

	if (IsFreedAddress(read_address)) {
		oss << "[!] Read free: 0x";
		oss << left << setw(6) << address << " " << setw(36)  << it->second;
		oss << "MREAD VAL[0x" << value << "] MEM[0x" << hex << setfill('0') << setw(8) << read_address << "]" << endl;
		TraceFile << oss.str();
		cerr << COLOR_YELLOW << oss.str() << COLOR_RESET;
	} else if (!IsAllocatedAddress(read_address)) {
		oss << "[!] Read OOB: 0x";
		oss << left << setw(6) << address << " " << setw(36)  << it->second;
		oss << "MREAD VAL[0x" << value << "] VAL[0x" << hex << setfill('0') << setw(8) << read_address << "]" << endl;
		TraceFile << oss.str();
		cerr << COLOR_YELLOW << oss.str() << COLOR_RESET;
		oss.clear();
		hexdump(oss, (const char*)read_address, 32);
	}
}

void stackptr_instruction(ADDRINT addr, ADDRINT sp, string *mnemonic)
{
	static ADDRINT lowestSp = (ADDRINT)-1;
	if (sp < lowestSp) lowestSp = sp;
	ostringstream oss;
	oss << hex;
	oss << "SP changed: " << left << setw(8) << addr << ", " << *mnemonic
		<< "$SP=" << (void*)sp << ", " << (void*)lowestSp << endl;
	TraceFile << oss;
}

void update_stack(pid_t thread_id, ADDRINT sp, INT offset)
{
	pid_t tid = gettid();
	ThreadedMemoryMapIter tmmi = gStackMap.find(tid);
	ostringstream oss; oss << thread_id << "-stack";
	string stack_name; stack_name = oss.str();
	if (tmmi == gStackMap.end()) {
		// cout << "Initialized new stack with SP at " << hex << "0x" << sp << endl;
		RegionAttributesPtr rap = RegionAttributesPtr(new RegionAttributes(sp + offset, 6, stack_name));
		pair<pid_t, MemoryMap> tp(thread_id, { MapPair(sp, rap) } );
		gStackMap.insert(ThreadedMapPair(thread_id, MapPair(sp, rap)));
	} else {
		ADDRINT orig_sp = tmmi->second.first;
		//cout << hex << "Updating sp 0x" << orig_sp << " to 0x" << sp << endl;
		RegionAttributesPtr rap = RegionAttributesPtr(new RegionAttributes(orig_sp - sp + offset, 6, stack_name));
		tmmi->second = MapPair(orig_sp, rap);
	}
}

void stackptr_add(ADDRINT address, ADDRINT sp, ADDRINT operand, string *mnemonic)
{
#if 0
	ostringstream oss;
	oss << hex << COLOR_LIGHT_CYAN;
	oss << "stackptr_add (" << gettid() << "): " << left << "PC=0x" << setw(8) << address <<
		" SP=0x" << sp << ": " << *mnemonic << COLOR_RESET << endl;
	cout << oss.str();
	TraceFile << oss;
#endif
	update_stack(gettid(), sp, operand);
}

void stackptr_sub(ADDRINT address, ADDRINT sp, ADDRINT operand, string *mnemonic)
{
#if 0
	ostringstream oss;
	oss << hex << COLOR_LIGHT_CYAN;
	oss << "stackptr_sub (" << gettid() << "): " << left << "PC=0x" << setw(8) << address <<
		" SP=0x" << sp << ": " << *mnemonic << COLOR_RESET << endl;
	cout << oss.str();
	TraceFile << oss.str();
#endif
	update_stack(gettid(), sp, operand);
}

void TraceInstruction(INS ins, void *v)
{
	ADDRINT insaddr = INS_Address(ins);

	// instrument malloc calls
	if (insaddr == gMallocRetAddr) {
		INS_InsertCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)AllocAfter,
			IARG_REG_VALUE, REG_GAX,
			IARG_END
		);
	} else if (insaddr == gMallocUsableRet) {
		INS_InsertCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)MallocUsableAfter,
			IARG_REG_VALUE, REG_GAX,
			IARG_END
		);
	}

	// instrument memory accesses that use mov
	// TODO support other memory accesses (push, pop, [deref] math, lea)
	// TODO support code outside of primary image text
	if (isMain(insaddr) &&
		(INS_Opcode(ins) == XED_ICLASS_MOV) &&
		(INS_has_sp(ins) == false) &&
		(INS_has_tls(ins) == false))
	{
		StringMapCIter it = gInstructions.find(insaddr);
		if (it == gInstructions.end()) {
			gInstructions.insert(make_pair(insaddr, INS_Disassemble(ins)));
		}
	
		if (INS_IsMemoryWrite(ins)) {
			if (INS_OperandIsReg(ins, 1)) {
				REG src = INS_OperandReg(ins, 1);
				if (REG_valid(src)) {	
					INS_InsertCall(
						ins,
						IPOINT_BEFORE,
						(AFUNPTR)write_instruction,
						IARG_ADDRINT, insaddr,
						IARG_MEMORYWRITE_EA,   	// target address of memory write
						IARG_REG_VALUE, src, 	// register value to be written
						IARG_PTR, "WRREG",
						IARG_END
					);
	        	}
			} else if (INS_OperandIsImmediate(ins, 1)) {
				ADDRINT src = (ADDRINT)INS_OperandImmediate(ins, 1);
				INS_InsertCall(
					ins,
					IPOINT_BEFORE,
					(AFUNPTR)write_instruction,
					IARG_ADDRINT, insaddr,
					IARG_MEMORYWRITE_EA,   	// target address of memory write
					IARG_ADDRINT, src, 	// immediate value to be written
					IARG_PTR, "WRIMM",
					IARG_END
				);
			}
		} else if (INS_IsMemoryRead(ins)) {
			INS_InsertCall(
				ins,
				IPOINT_BEFORE,
				(AFUNPTR)read_instruction,
				IARG_ADDRINT, insaddr,
				IARG_MEMORYREAD_EA,   // effective address of memory read
				IARG_MEMORYREAD_SIZE, // size in bytes
				IARG_END);
		}
	}

	// instrument stack ptr adjustments using add/sub
	if (INS_Opcode(ins) == XED_ICLASS_SUB &&
		INS_OperandReg(ins, 0) == REG_STACK_PTR &&
		INS_OperandIsImmediate(ins, 1)) {
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)stackptr_sub,
			IARG_ADDRINT, insaddr,
			IARG_REG_VALUE, REG_STACK_PTR,
			IARG_ADDRINT, (UINT32)INS_OperandImmediate(ins, 1),
			IARG_ADDRINT, new string(INS_Disassemble(ins)), IARG_END);
	} else if (INS_Opcode(ins) == XED_ICLASS_ADD &&
		INS_OperandReg(ins, 0) == REG_STACK_PTR &&
		INS_OperandIsImmediate(ins, 1)) {
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)stackptr_add,
			IARG_ADDRINT, insaddr,
			IARG_REG_VALUE, REG_STACK_PTR,
			IARG_ADDRINT, (UINT32)INS_OperandImmediate(ins, 1),
			IARG_ADDRINT, new string(INS_Disassemble(ins)), IARG_END);
	}
#if 0
	// other stack ptr modifications?
	if (INS_RegWContain(ins, REG_STACK_PTR)) {
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)stackptr_instruction,
			IARG_ADDRINT, insaddr,
			IARG_ADDRINT, new string(INS_Mnemonic(ins)),
			IARG_REG_VALUE, REG_STACK_PTR, IARG_END);
	}
#endif
}

void Fini(INT32 code, void *v)
{
	TraceFile.close();
}

int main(int argc, char **argv)
{
	PIN_InitSymbols();
	if (PIN_Init(argc,argv)) return -1;

	// tracefile for PIN    
	TraceFile.open(KnobOutputFile.Value().c_str());
	TraceFile << hex;
	TraceFile.setf(ios::showbase);

	IMG_AddInstrumentFunction(Image, 0);
	INS_AddInstrumentFunction(TraceInstruction, 0);
	PIN_AddFiniFunction(Fini, 0);

	PIN_StartProgram();
	return 0;
}
