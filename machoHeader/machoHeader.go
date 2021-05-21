package machoHeader

/*
	An update to look into:
		https://golang.org/cmd/cgo/
 */

import (
	"cycle1/errorHandling"
	"debug/macho"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
)

type machoHeader macho.FileHeader

//Taken from Jonathan Levin's OSX Internals book page 163. Could be expanded by looking at the OSX internal header files.
const (
	CPU_SUBTYPE_ARM64_ALL		= 0
	CPU_SUBTYPE_ARM64_V8 		= 1
	CPU_SUBTYPE_X86_64_ALL 		= 3
	CPU_SUBTYPE_X86_64_H 		= 8
	CPU_SUBTYPE_ARMV7 			= 9
	CPU_SUBTYPE_ARMV7S 			= 11
)

//Includes for the Command and CommandSize fields
const (
	MACH_HEADER_SIZE 			= 72
	SECTION_HEADER_SIZE			= 80
)

//Copied from:
//	Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/usr/include/mach-o/loader.h

/*
 * After MacOS X 10.1 when a new load command is added that is required to be
 * understood by the dynamic linker for the image to execute properly the
 * LC_REQ_DYLD bit will be or'ed into the load command constant.  If the dynamic
 * linker sees such a load command it it does not understand will issue a
 * "unknown load command required for execution" error and refuse to use the
 * image.  Other load commands without this bit that are not understood will
 * simply be ignored.
 */

const(
	LC_REQ_DYLD 				= 0x80000000
	LC_SEGMENT					= 0x1	/* segment of this file to be mapped */
	LC_SYMTAB					= 0x2	/* link-edit stab symbol table info */
	LC_SYMSEG					= 0x3	/* link-edit gdb symbol table info (obsolete) */
	LC_THREAD					= 0x4	/* thread */
	LC_UNIXTHREAD				= 0x5	/* unix thread (includes a stack) */
	LC_LOADFVMLIB				= 0x6	/* load a specified fixed VM shared library */
	LC_IDFVMLIB					= 0x7	/* fixed VM shared library identification */
	LC_IDENT					= 0x8	/* object identification info (obsolete) */
	LC_FVMFILE					= 0x9	/* fixed VM file inclusion (internal use) */
	LC_PREPAGE     				= 0xa     /* prepage command (internal use) */
	LC_DYSYMTAB					= 0xb	/* dynamic link-edit symbol table info */
	LC_LOAD_DYLIB				= 0xc	/* load a dynamically linked shared library */
	LC_ID_DYLIB					= 0xd	/* dynamically linked shared lib ident */
	LC_LOAD_DYLINKER 			= 0xe	/* load a dynamic linker */
	LC_ID_DYLINKER				= 0xf	/* dynamic linker identification */
	LC_PREBOUND_DYLIB 			= 0x10	/* modules prebound for a dynamically */
	/*  linked shared library */
	LC_ROUTINES					= 0x11	/* image routines */
	LC_SUB_FRAMEWORK 			= 0x12	/* sub framework */
	LC_SUB_UMBRELLA 			= 0x13	/* sub umbrella */
	LC_SUB_CLIENT				= 0x14	/* sub client */
	LC_SUB_LIBRARY  			= 0x15	/* sub library */
	LC_TWOLEVEL_HINTS			= 0x16	/* two-level namespace lookup hints */
	LC_PREBIND_CKSUM  			= 0x17	/* prebind checksum */
	LC_SEGMENT_64 				= 0x19	/* 64-bit segment of this file to be mapped */
	LC_ROUTINES_64				= 0x1a	/* 64-bit image routines */
	LC_UUID						= 0x1b	/* the uuid */
	LC_RPATH					= (0x1c | LC_REQ_DYLD)    /* runpath additions */
	LC_CODE_SIGNATURE			= 0x1d	/* local of code signature */
	LC_SEGMENT_SPLIT_INFO		= 0x1e /* local of info to split segments */
	LC_REEXPORT_DYLIB 			= (0x1f | LC_REQ_DYLD) /* load and re-export dylib */
	LC_LAZY_LOAD_DYLIB 			= 0x20	/* delay load of dylib until first use */
	LC_ENCRYPTION_INFO 			= 0x21	/* encrypted segment information */
	LC_DYLD_INFO 				= 0x22	/* compressed dyld information */
	LC_DYLD_INFO_ONLY 			= (0x22|LC_REQ_DYLD)	/* compressed dyld information only */
	LC_LOAD_UPWARD_DYLIB 		= (0x23 | LC_REQ_DYLD) /* load upward dylib */
	LC_VERSION_MIN_MACOSX 		= 0x24   /* build for MacOSX min OS version */
	LC_VERSION_MIN_IPHONEOS 	= 0x25 /* build for iPhoneOS min OS version */
	LC_FUNCTION_STARTS 			= 0x26 /* compressed table of function start addresses */
	LC_DYLD_ENVIRONMENT 		= 0x27 /* string for dyld to treat like environment variable */
	LC_MAIN 					= (0x28|LC_REQ_DYLD) /* replacement for LC_UNIXTHREAD */
	LC_DATA_IN_CODE 			= 0x29 /* table of non-instructions in __text */
	LC_SOURCE_VERSION 			= 0x2A /* source version used to build binary */
	LC_DYLIB_CODE_SIGN_DRS 		= 0x2B /* Code signing DRs copied from linked dylibs */
	LC_ENCRYPTION_INFO_64 		= 0x2C /* 64-bit encrypted segment information */
	LC_LINKER_OPTION 			= 0x2D /* linker options in MH_OBJECT files */
	LC_LINKER_OPTIMIZATION_HINT = 0x2E /* optimization hints in MH_OBJECT files */
	LC_VERSION_MIN_TVOS 		= 0x2F /* build for AppleTV min OS version */
	LC_VERSION_MIN_WATCHOS 		= 0x30 /* build for Watch min OS version */
	LC_NOTE 					= 0x31 /* arbitrary data included within a Mach-O file */
	LC_BUILD_VERSION 			= 0x32 /* build for platform min OS version */
	LC_DYLD_EXPORTS_TRIE 		= (0x33 | LC_REQ_DYLD) /* used with linkedit_data_command, payload is trie */
	LC_DYLD_CHAINED_FIXUPS 		= (0x34 | LC_REQ_DYLD) /* used with linkedit_data_command */
)

type LoadCommand struct{
	Command uint32
	CommandSize uint32
	SegmentName string
	VmAddress uint64
	VmSize uint64
	FileOffset uint64
	FileSize uint64
	MaxVMProtectionFlag uint32
	InitVMProtectionFlag uint32
	NumOfSections uint32
	Flags uint32
	Sections []SectionHeader
}

//taken from Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/usr/include/mach-o/loader.h
type SectionHeader struct{
	SectionName string
	SegmentName string
	Address uint64
	Size uint64
	Offset uint32
	Alignment uint32
	RelocOffset uint32
	NumReloc uint32
	Flags uint32
	Special1 uint32
	Special2 uint32
	Special3 uint32
}

type FileHeader struct{
	Header machoHeader
	LoadCommands []LoadCommand
}

/*
		//////////////////////////////////////// PUBLIC METHODS ////////////////////////////////////////
 */

func LoadStruct(inputFilename string)FileHeader{
	var myHeader FileHeader

	inputFile, err := os.Open(inputFilename)
	errorHandling.CheckErr(err)

	fromFile := make([]byte, binary.Size(myHeader.Header))
	err = binary.Read(inputFile, binary.LittleEndian, fromFile)
	errorHandling.CheckErr(err)

	myHeader.populateHeader(fromFile)

	//must read in the next 4 bytes as they are reserved
	fromFile = make([]byte, 4)
	err = binary.Read(inputFile, binary.LittleEndian, fromFile)

	myHeader.populateCommands(inputFile)

	inputFile.Close()

	return myHeader
}

//TODO: Associate with the structure FileHeader.
func PrintSection(header SectionHeader){
	fmt.Println("\tSection name: ", header.SectionName)
	fmt.Println("\tSegment name: ", header.SegmentName)
	fmt.Printf("\tAddress: 0x%x\n", header.Address)
	fmt.Printf("\tSize: 0x%x\n", header.Size)
	fmt.Printf("\tOffset: 0x%x\n", header.Offset)
	fmt.Println("\tAlignment: ", header.Alignment)
	fmt.Println("\tRelocation Offset: ", header.RelocOffset)
	fmt.Println("\tNumber of Realocations: ", header.NumReloc)
	fmt.Printf("\tFlags: 0x%x\n", header.Flags)
	fmt.Println("\tReserved1: ", header.Special1)
	fmt.Println("\tReserved2: ", header.Special2)
	fmt.Println("\tReserved3: ", header.Special3)
}

//TODO: Associate with the structure FileHeader.
func PrintSegment(command LoadCommand, indent int){

	fmt.Println(strings.Repeat("-",25))
	fmt.Println(strings.Repeat("-",indent), "command: ", command.Command)
	fmt.Println(strings.Repeat("-",indent),"command Size: ", command.CommandSize)
	fmt.Println(strings.Repeat("-",indent),"segment name: ", command.SegmentName)
	fmt.Printf("%s VMAddress: 0x%x\n", strings.Repeat("-",indent), command.VmAddress)
	fmt.Printf("%s VMSize: 0x%x\n", strings.Repeat("-",indent),command.VmSize)
	fmt.Println(strings.Repeat("-",indent),"FileOffset: ", command.FileOffset)
	fmt.Println(strings.Repeat("-",indent),"Max VM Prot: ", command.MaxVMProtectionFlag)
	fmt.Println(strings.Repeat("-",indent),"Init VM Prot: ", command.InitVMProtectionFlag)
	fmt.Println(strings.Repeat("-",indent),"Num of Sections: ", command.NumOfSections)
	fmt.Println(strings.Repeat("-",indent),"Flags: ", command.Flags)
}

/*
	//////////////////////////////////////// PRIVATE METHODS ////////////////////////////////////////
*/

func handleLC(command uint32, indent int){
	if LC_SEGMENT == command {
		fmt.Println(strings.Repeat("-",indent),"LC_SEGMENT")
	} else if LC_SYMTAB == command {
		fmt.Println(strings.Repeat("-",indent),"LC_SYMTAB")
	} else if LC_SYMSEG == command {
		fmt.Println(strings.Repeat("-",indent),"LC_SYMSEG")
	} else if LC_THREAD == command {
		fmt.Println(strings.Repeat("-",indent),"LC_THREAD")
	} else if LC_UNIXTHREAD == command {
		fmt.Println(strings.Repeat("-",indent),"LC_UNIXTHREAD")
	} else if LC_LOADFVMLIB == command {
		fmt.Println(strings.Repeat("-",indent),"LC_LOADFVMLIB")
	} else if LC_IDFVMLIB == command {
		fmt.Println(strings.Repeat("-",indent),"LC_IDFVMLIB")
	} else if LC_IDENT == command {
		fmt.Println(strings.Repeat("-",indent),"LC_IDENT")
	} else if LC_FVMFILE == command {
		fmt.Println(strings.Repeat("-",indent),"LC_FVMFILE")
	} else if LC_PREPAGE == command {
		fmt.Println(strings.Repeat("-",indent),"LC_PREPAGE")
	} else if LC_DYSYMTAB == command {
		fmt.Println(strings.Repeat("-",indent),"LC_DYSYMTAB")
	} else if LC_LOAD_DYLIB == command {
		fmt.Println(strings.Repeat("-",indent),"LC_LOAD_DYLIB")
	} else if LC_ID_DYLIB == command {
		fmt.Println(strings.Repeat("-",indent),"LC_ID_DYLIB")
	} else if LC_LOAD_DYLINKER == command {
		fmt.Println(strings.Repeat("-",indent),"LC_LOAD_DYLINKER")
	} else if LC_ID_DYLINKER == command {
		fmt.Println(strings.Repeat("-",indent),"LC_ID_DYLINKER")
	} else if LC_PREBOUND_DYLIB == command {
		fmt.Println(strings.Repeat("-",indent),"LC_PREBOUND_DYLIB")
	} else if LC_ROUTINES == command {
		fmt.Println(strings.Repeat("-",indent),"LC_ROUTINES")
	} else if LC_SUB_FRAMEWORK == command {
		fmt.Println(strings.Repeat("-",indent),"LC_SUB_FRAMEWORK")
	} else if LC_SUB_UMBRELLA == command {
		fmt.Println(strings.Repeat("-",indent),"LC_SUB_UMBRELLA")
	} else if LC_SUB_CLIENT == command {
		fmt.Println(strings.Repeat("-",indent),"LC_SUB_CLIENT")
	} else if LC_SUB_LIBRARY == command {
		fmt.Println(strings.Repeat("-",indent),"LC_SUB_LIBRARY")
	} else if LC_TWOLEVEL_HINTS == command {
		fmt.Println(strings.Repeat("-",indent),"LC_TWOLEVEL_HINTS")
	} else if LC_PREBIND_CKSUM == command {
		fmt.Println(strings.Repeat("-",indent),"LC_PREBIND_CKSUM")
	} else if LC_SEGMENT_64 == command {
		fmt.Println(strings.Repeat("-",indent),"LC_SEGMENT_64")
	} else if LC_ROUTINES_64 == command {
		fmt.Println(strings.Repeat("-",indent),"LC_ROUTINES_64")
	} else if LC_UUID == command {
		fmt.Println(strings.Repeat("-",indent),"LC_UUID")
	} else if LC_RPATH == command {
		fmt.Println(strings.Repeat("-",indent),"LC_RPATH")
	} else if LC_CODE_SIGNATURE == command {
		fmt.Println(strings.Repeat("-",indent),"LC_CODE_SIGNATURE")
	} else if LC_SEGMENT_SPLIT_INFO == command {
		fmt.Println(strings.Repeat("-",indent),"LC_SEGMENT_SPLIT_INFO")
	} else if LC_REEXPORT_DYLIB == command {
		fmt.Println(strings.Repeat("-",indent),"LC_REEXPORT_DYLIB")
	} else if LC_LAZY_LOAD_DYLIB == command {
		fmt.Println(strings.Repeat("-",indent),"LC_LAZY_LOAD_DYLIB")
	} else if LC_ENCRYPTION_INFO == command {
		fmt.Println(strings.Repeat("-",indent),"LC_ENCRYPTION_INFO")
	} else if LC_DYLD_INFO == command {
		fmt.Println(strings.Repeat("-",indent),"LC_DYLD_INFO")
	} else if LC_DYLD_INFO_ONLY == command {
		fmt.Println(strings.Repeat("-",indent),"LC_DYLD_INFO_ONLY")
	} else if LC_LOAD_UPWARD_DYLIB == command {
		fmt.Println(strings.Repeat("-",indent),"LC_LOAD_UPWARD_DYLIB")
	} else if LC_VERSION_MIN_MACOSX == command {
		fmt.Println(strings.Repeat("-",indent),"LC_VERSION_MIN_MACOSX")
	} else if LC_VERSION_MIN_IPHONEOS == command {
		fmt.Println(strings.Repeat("-",indent),"LC_VERSION_MIN_IPHONEOS")
	} else if LC_FUNCTION_STARTS == command {
		fmt.Println(strings.Repeat("-",indent),"LC_FUNCTION_STARTS")
	} else if LC_DYLD_ENVIRONMENT == command {
		fmt.Println(strings.Repeat("-",indent),"LC_DYLD_ENVIRONMENT")
	} else if LC_MAIN == command {
		fmt.Println(strings.Repeat("-",indent),"LC_MAIN")
	} else if LC_DATA_IN_CODE == command {
		fmt.Println(strings.Repeat("-",indent),"LC_DATA_IN_CODE")
	} else if LC_SOURCE_VERSION == command {
		fmt.Println(strings.Repeat("-",indent),"LC_SOURCE_VERSION")
	} else if LC_DYLIB_CODE_SIGN_DRS == command {
		fmt.Println(strings.Repeat("-",indent),"LC_DYLIB_CODE_SIGN_DRS")
	} else if LC_ENCRYPTION_INFO_64 == command {
		fmt.Println(strings.Repeat("-",indent),"LC_ENCRIPTION_INFO_64")
	} else if LC_LINKER_OPTION == command {
		fmt.Println(strings.Repeat("-",indent),"LC_LINKER_OPTION")
	} else if LC_LINKER_OPTIMIZATION_HINT == command {
		fmt.Println(strings.Repeat("-",indent),"LC_LINKER_OPTIMIZATION_HINT")
	} else if LC_VERSION_MIN_TVOS == command {
		fmt.Println(strings.Repeat("-",indent),"LC_VERSION_MIN_TVOS")
	} else if LC_VERSION_MIN_WATCHOS == command {
		fmt.Println(strings.Repeat("-",indent),"LC_VERSION_MIN_WATCHOS")
	} else if LC_NOTE == command {
		fmt.Println(strings.Repeat("-",indent),"LC_NOTE")
	} else if LC_BUILD_VERSION == command {
		fmt.Println(strings.Repeat("-",indent),"LC_BUILD_VERSION")
	} else if LC_DYLD_EXPORTS_TRIE == command {
		fmt.Println(strings.Repeat("-",indent),"LC_DYLD_EXPORTS_TRIE")
	} else if LC_DYLD_CHAINED_FIXUPS == command {
		fmt.Println(strings.Repeat("-",indent),"LC_DYLD_CHAINED_FIXUPS")
	} else {
		fmt.Println(strings.Repeat("-",indent),"UNKNOWN LOAD COMMAND")
	}
}

func parseSection(header *SectionHeader, data []byte){
	header.SectionName	= string(data[0:16])
	header.SegmentName	= string(data[16:32])
	header.Address		= binary.LittleEndian.Uint64(data[32:40])
	header.Size			= binary.LittleEndian.Uint64(data[40:48])
	header.Offset		= binary.LittleEndian.Uint32(data[48:52])
	header.Alignment	= binary.LittleEndian.Uint32(data[52:56])
	header.RelocOffset	= binary.LittleEndian.Uint32(data[56:60])
	header.NumReloc		= binary.LittleEndian.Uint32(data[60:64])
	header.Flags		= binary.LittleEndian.Uint32(data[64:68])
	header.Special1		= binary.LittleEndian.Uint32(data[68:72])
	header.Special2		= binary.LittleEndian.Uint32(data[72:76])
	header.Special3		= binary.LittleEndian.Uint32(data[76:80])
}

func parseSegment(segment *LoadCommand, data []byte){
	segment.SegmentName = string(data[0:16])
	segment.VmAddress = binary.LittleEndian.Uint64(data[16:24])
	segment.VmSize = binary.LittleEndian.Uint64(data[24:32])
	segment.FileOffset = binary.LittleEndian.Uint64(data[32:40])
	segment.FileSize = binary.LittleEndian.Uint64(data[40:48])
	segment.MaxVMProtectionFlag = binary.LittleEndian.Uint32(data[48:52])
	segment.InitVMProtectionFlag = binary.LittleEndian.Uint32(data[52:56])
	segment.NumOfSections = binary.LittleEndian.Uint32(data[56:60])
	segment.Flags = binary.LittleEndian.Uint32(data[60:64])
}

//Values and translation provided by Jonathan Levin's OSX Internals book 1, page 170
func translateFlags(arg uint32){
	if 0x1 == 0x1 & arg{
		fmt.Println("\t0x1 MH_NOUNDEFS")
	}
	if 0x4 == 0x4 & arg{
		fmt.Println("\t0x4 MH_DYLDLINK")
	}
	if 0x16 == 0x10 & arg{
		fmt.Println("\t0x16 MH_PREBOUND")
	}
	if 0x20 == 0x20 & arg{
		fmt.Println("\t0x20 MH_SPLIT_SEGS")
	}
	if 0x80 == 0x80 & arg{
		fmt.Println("\t0x80 MH_TWOLEVEL")
	}
	if 0x100 == 0x100 & arg{
		fmt.Println("\t0x100 MH_FORCE_FLAT")
	}
	if 0x8000 == 0x8000 & arg{
		fmt.Println("\t0x8000 MH_WEAK_DEFINES")
	}
	if 0x10000 == 0x10000 & arg{
		fmt.Println("\t0x10000 MH_BINDS_TO_WEAK")
	}
	if 0x20000 == 0x20000 & arg{
		fmt.Println("\t0x20000 MH_ALLOW_STACK_EXECUTION")
	}
	if 0x100000 == 0x100000 & arg{
		fmt.Println("\t0x100000 NO_NO_REEXPORTED_DYLIBS")
	}
	if 0x200000 == 0x200000 & arg{
		fmt.Println("\t0x200000 MH_PIE")
	}
	if 0x800000 == 0x800000 & arg{
		fmt.Println("\t0x800000 MH_HAS_TLV_DESCRIPTORS")
	}
	if 0x1000000 == 0x1000000 & arg{
		fmt.Println("\t0x1000000 MH_NO_HEAP_EXECUTION")
	}
	if 0x2000000 == 0x2000000 & arg{
		fmt.Println("\t0x2000000 MH_APP_EXTENSION_SAFE")
	}
	if 0x40000000 == 0x40000000 & arg{
		fmt.Println("\t0x40000000 MH_HAS_OBJC")
	}
}

//Values and translation provided by Jonathan Levin's OSX Internals book 1, page 163
func translateSubCPU(arg uint32)(string, error){

	var retValue string
	var localError error
	problem := 0

	if CPU_SUBTYPE_ARM64_ALL == arg{
		retValue = "CPU_SUBTYPE_ARM64_ALL"
	} else if CPU_SUBTYPE_ARM64_V8 == arg{
		retValue = "CPU_SUBTYPE_ARM64_V8"
	} else if CPU_SUBTYPE_X86_64_ALL == arg{
		retValue = "CPU_SUBTYPE_X86_64_ALL"
	} else if CPU_SUBTYPE_X86_64_H == arg{
		retValue = "CPU_SUBTYPE_X86_64_H"
	} else if CPU_SUBTYPE_ARMV7 == arg{
		retValue = "CPU_SUBTYPE_ARMV7"
	} else if CPU_SUBTYPE_ARMV7S == arg{
		retValue = "CPU_SUBTYPE_ARMV7S"
	} else {
		problem = 1
	}

	if 0 != problem{
		localError = errors.New("CPUSub type not recognized or supported")
	} else {
		localError = nil
	}

	return retValue,localError
}


/*
	//////////////////////////////////////// PUBLIC CLASS METHODS ////////////////////////////////////////
*/

///Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/usr/include/mach-o/fat.h
func (m FileHeader) PrintStruct(){

	m.PrintMachoHeader()
	for i:= 0; i < int(m.Header.Ncmd); i++{
		if LC_SEGMENT_64 == m.LoadCommands[i].Command{
			PrintSegment(m.LoadCommands[i], 4)
			if 0 != m.LoadCommands[i].NumOfSections{
				for j:= 0; j < int(m.LoadCommands[i].NumOfSections); j++{
					PrintSection(m.LoadCommands[i].Sections[j])
					fmt.Println(strings.Repeat("-",20))
				}
			}
		} else {
			fmt.Println("Other Segment Type: ")
			handleLC(m.LoadCommands[i].Command, 4)
		}
	}
}

func (m FileHeader) PrintMachoHeader(){
	fmt.Printf("Magic Number:%s%x\n",strings.Repeat("-",25-13), m.Header.Magic)
	fmt.Printf("CPU:%s%s\n", strings.Repeat("-",25-4), m.Header.Cpu.String())
	subCPU, err := translateSubCPU(m.Header.SubCpu)
	errorHandling.CheckErr(err)
	fmt.Printf("SubCPU:%s%s\n", strings.Repeat("-",25-7), subCPU)			//
	fmt.Printf("Type:%s%s\n", strings.Repeat("-",25-5), m.Header.Type.String())			//Type of mach-o
	fmt.Printf("# of Load commands:%s0x%x\n", strings.Repeat("-",25-19), m.Header.Ncmd)				//number of load commands
	fmt.Printf("CMDSZ:%s0x%x\n", strings.Repeat("-",25-6), m.Header.Cmdsz)			//size of load command region
	fmt.Printf("Flags:%s0x%x\n", strings.Repeat("-",25-6), m.Header.Flags)
	translateFlags(m.Header.Flags)
}

/*
	//////////////////////////////////////// PRIVATE CLASS METHODS ////////////////////////////////////////
*/

func (m *FileHeader) populateHeader(h []byte){

	m.Header.Magic = binary.LittleEndian.Uint32(h[0:4])
	m.Header.Cpu = macho.Cpu(binary.LittleEndian.Uint32(h[4:8]))
	m.Header.SubCpu = binary.LittleEndian.Uint32(h[8:12])
	m.Header.Type = macho.Type(binary.LittleEndian.Uint32(h[12:16]))
	m.Header.Ncmd = binary.LittleEndian.Uint32(h[16:20])
	m.Header.Cmdsz = binary.LittleEndian.Uint32(h[20:24])
	m.Header.Flags = binary.LittleEndian.Uint32(h[24:28])
}

func (m *FileHeader) populateCommands(inputFile *os.File){

	m.LoadCommands = make([]LoadCommand, m.Header.Ncmd)

	for i := 0; i < int(m.Header.Ncmd); i++{

		//retrieve Command
		temp := make([]byte, 4)
		err := binary.Read(inputFile,binary.LittleEndian,temp)
		errorHandling.CheckErr(err)
		m.LoadCommands[i].Command = binary.LittleEndian.Uint32(temp)

		//Retrieve Command Size
		err = binary.Read(inputFile,binary.LittleEndian,temp)
		errorHandling.CheckErr(err)
		m.LoadCommands[i].CommandSize = binary.LittleEndian.Uint32(temp)

		//CommandSize counts the Command and CommandSize, which have already been read in.
		if LC_SEGMENT_64 == m.LoadCommands[i].Command{
			temp = make([]byte, MACH_HEADER_SIZE-8)
			err = binary.Read(inputFile, binary.LittleEndian, temp)
			errorHandling.CheckErr(err)

			parseSegment(&m.LoadCommands[i], temp)
			if 0 != m.LoadCommands[i].NumOfSections{
				m.LoadCommands[i].Sections = make([]SectionHeader, m.LoadCommands[i].NumOfSections)
				for j := 0; j < int(m.LoadCommands[i].NumOfSections); j++{
					temp = make([]byte, SECTION_HEADER_SIZE)
					binary.Read(inputFile, binary.LittleEndian, temp)
					parseSection(&m.LoadCommands[i].Sections[j], temp)
				}
			}

		} else {
			temp = make([]byte, m.LoadCommands[i].CommandSize-8)
			err = binary.Read(inputFile,binary.LittleEndian,temp)
			errorHandling.CheckErr(err)
		}
	}

}


