#include "pin.H"

#include <sys/mman.h>
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
		Size(s), Prot(prot), Name(name)
	{}
	size_t Size;
	int Prot;
	string Name;
};
typedef shared_ptr<RegionAttributes> RegionAttributesPtr;
typedef unordered_map<ADDRINT, RegionAttributesPtr> MemoryMap;
typedef MemoryMap::iterator MapIter;
typedef unordered_map<ADDRINT, string> StringMap;
typedef StringMap::const_iterator StringMapCIter;

MemoryMap gImageMap;
MemoryMap gHeapMap;
MemoryMap gFreeMap;

mutex gHeapMutex;
mutex gFreeMutex;
mutex gImageMutex;

StringMap gInstructions;

// Used in before/after callbacks to track heap allocs
// TODO this doesn't work for multiple threads... convert to map<threadid,pair<addr,size>>
size_t gAllocSize = 0;
ADDRINT gRetAddress = 0;
ADDRINT gMallocUsableAddress = 0;
ADDRINT gMallocUsableRet = 0;
int gAllocProt = 0;

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

/* check if an address is part of allocated chunk  */
bool IsAllocatedAddress(ADDRINT addr)
{
	return IsAddressInMap(gImageMap, addr) || IsAddressInMap(gHeapMap, addr);
}

bool IsFreedAddress(ADDRINT addr)
{
	return IsAddressInMap(gFreeMap, addr);
}

/* for malloc, sbrk, realloc allocations */
void AllocBefore(string* name, size_t size, ADDRINT ret)
{
	if (isMain(ret)) {
		gRetAddress = ret;
		gAllocSize = size;
		gAllocProt = PROT_READ | PROT_WRITE;
		// TraceFile << (ret-5) << "@" << *name << "[" << allocsize << "]" << endl;
	}
	// TODO this crashes? delete name;
}

/* for mmap allocations */
void MmapBefore(string* name, size_t size, int prot, ADDRINT ret)
{
	if (isMain(ret)) {
		gRetAddress = ret;
		gAllocSize = size;
		gAllocProt = prot;
		// TraceFile << (ret-5) << "@" << *name << "[" << allocsize << "]" << endl;
	}
	// TODO this crashes? delete name;
}

/* for calloc allocation */
void CallocBefore(string* name, size_t nmemb, size_t size, ADDRINT ret)
{
	if (isMain(ret)) {
		gRetAddress = ret;
		gAllocSize = nmemb * size;
		gAllocProt = PROT_READ | PROT_WRITE;
		// TraceFile << (ret-5) << "@" << *name << "[" << allocsize << "]" << endl;
	}
	// TODO this crashes? delete name;
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
	
	// TraceFile << "Allocation @ " << newalloc << ", size " << gAllocSize << endl;
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
#ifdef __i386__ 
		if ((op == REG_ESP) || (op == REG_EBP))  return true;
#else
		if ((op == REG_RSP) || (op == REG_RBP))  return true;
#endif
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

const char redTerm[] = "\033[1;31m";
const char resetTerm[] = "\033[0m";

// This function logs writes to allocated areas.
// @arg type "WRREG" or "WRIMM"
void write_instruction(ADDRINT address, ADDRINT write_address, ADDRINT regval, char *type)
{
	StringMapCIter it = gInstructions.find(address);
	if (it == gInstructions.end()) assert(0);
	ADDRINT offset = address - gMainImageAddress.first;
	ostringstream oss;
	oss << hex;

	if (IsFreedAddress(write_address)) {
		oss << "[!] Write to free address: 0x";
		oss << left << setw(12) << offset << "@" << setw(40)  << it->second;
		oss << "   : " << type << " MEM[" << write_address << "] VAL[" << regval << "]" << endl;
		TraceFile << oss.str();
		cerr << redTerm << oss.str() << resetTerm;
	} else if (!IsAllocatedAddress(write_address)) {
		oss << "[!] Write OOB: 0x";	
		oss << left << setw(12) << offset << "@" << setw(40)  << it->second;
		oss << "   : " << type << " MEM[" << write_address << "] VAL[" << regval << "]" << endl;
		TraceFile << oss.str();
		cerr << redTerm << oss.str() << resetTerm;
	}
}

void read_instruction(ADDRINT address, ADDRINT read_address, ADDRINT size)
{
	ostringstream oss; oss << hex;
	StringMapCIter it = gInstructions.find(address);
	if (it == gInstructions.end()) assert(0);

	ADDRINT offset = address - gMainImageAddress.first;
	ADDRINT value = 0;
	if ((size == 8) || (size == 4)) {
		value = *(ADDRINT *)read_address;
	} else if (size == 1) {
		value = *(char *) read_address;
	}

	if (IsFreedAddress(read_address)) {
		oss << "[!] Read from free address: 0x";
		oss << left << setw(12) << offset << "@" << setw(40)  << it->second;
		oss << "   : MREAD VAL[" << value << "] MEM[" << read_address << "]" << endl;
		TraceFile << oss.str();
		cerr << redTerm << oss.str() << resetTerm;
	} else if (!IsAllocatedAddress(read_address)) {
		oss << "[!] Read OOB: 0x";
		oss << left << setw(12) << offset << "@" << setw(40)  << it->second;
		oss << "   : MREAD VAL[" << value << "] MEM[" << read_address << "]" << endl;
		TraceFile << oss.str();
		cerr << redTerm << oss.str() << resetTerm;
	}
}

void TraceInstruction(INS ins, void *v)
{
	ADDRINT insaddr = INS_Address(ins);
	
	if (insaddr == gRetAddress) {
		INS_InsertCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)AllocAfter,
#ifdef __i386__ 
			IARG_REG_VALUE, LEVEL_BASE::REG_EAX,
#else
			IARG_REG_VALUE, LEVEL_BASE::REG_RAX,
#endif
			IARG_END
		);
	} else if (insaddr == gMallocUsableRet) {
		INS_InsertCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)MallocUsableAfter,
#ifdef __i386__ 
			IARG_REG_VALUE, LEVEL_BASE::REG_EAX,
#else
			IARG_REG_VALUE, LEVEL_BASE::REG_RAX,
#endif
			IARG_END
		);
	}

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
			if(INS_OperandIsReg(ins, 1)) {
				REG src = INS_OperandReg(ins, 1);
				if (REG_valid(src)) {	
					INS_InsertCall(
						ins,
						IPOINT_BEFORE,
						(AFUNPTR)write_instruction,
						IARG_ADDRINT, insaddr,
						IARG_MEMORYWRITE_EA,   	// target address of memory write
						IARG_REG_VALUE, src, 	// register value to be written
						IARG_PTR , "WRREG",
						IARG_END
					);
	        	}
			} else if(INS_OperandIsImmediate(ins, 1)) {
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
		} else if(INS_IsMemoryRead(ins)) {
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
}

void Fini(INT32 code, void *v)
{
	TraceFile.close();
}

int main(int argc, char **argv)
{
	PIN_InitSymbols();
	if(PIN_Init(argc,argv)) return -1;

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
