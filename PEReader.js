class IMAGE_DOS_HEADER {
    constructor() {
        this.e_magic        = 0x0000;
        this.e_cblp         = 0x0000;
        this.e_cp           = 0x0000;
        this.e_crlc         = 0x0000;
        this.e_cparhdr      = 0x000;
        this.e_minalloc     = 0x0000;
        this.e_maxalloc     = 0x000;
        this.e_ss           = 0x0000;
        this.e_sp           = 0x0000;
        this.e_csum         = 0x0000;
        this.e_ip           = 0x0000;
        this.e_cs           = 0x0000;
        this.e_lfarlc       = 0x0000;
        this.e_ovno         = 0x0000;
        this.e_res          = new Array(4);
        this.e_oemid        = 0x0000;
        this.e_oeminfo      = 0x0000;
        this.e_res2         = new Array(10);
        this.e_lfanew       = 0x00000000;
    };
};

class IMAGE_DATA_DIRECTORY {
    constructor() {
        this.VirtualAddress     = 0x00000000;
        this.Size               = 0x00000000;
    };
};

class IMAGE_OPTIONAL_HEADER32 {
    constructor() {
        this.Magic                          = 0x0000;
        this.MajorLinkerVersion             = 0x00;
        this.MinorLinkerVersion             = 0x00;
        this.SizeOfCode                     = 0x00000000;
        this.SizeOfInitializedData          = 0x00000000;
        this.SizeOfUninitializedData        = 0x00000000;
        this.AddressOfEntryPoint            = 0x00000000;
        this.BaseOfCode                     = 0x00000000;
        this.BaseOfData                     = 0x00000000;
        this.ImageBase                      = 0x00000000;
        this.SectionAlignment               = 0x00000000;
        this.FileAlignment                  = 0x00000000;
        this.MajorOperatingSystemVersion    = 0x0000;
        this.MinorOperatingSystemVersion    = 0x0000;
        this.MajorImageVersion              = 0x0000;
        this.MinorImageVersion              = 0x0000;
        this.MajorSubsystemVersion          = 0x0000;
        this.MinorSubsystemVersion          = 0x0000;
        this.Win32VersionValue              = 0x00000000;
        this.SizeOfImage                    = 0x00000000;
        this.SizeOfHeaders                  = 0x00000000;
        this.CheckSum                       = 0x0000;
        this.Subsystem                      = 0x00;
        this.DllCharacteristics             = 0x00;
        this.SizeOfStackReverse             = 0x00000000;
        this.SizeOfStackCommit              = 0x00000000;
        this.SizeOfHeapReverse              = 0x00000000;
        this.SizeOfHeapCommit               = 0x00000000;
        this.LoaderFlags                    = 0x00000000;
        this.NumberOfRvaAndSizes            = 0x00000000;
        this.ExportTable                    = new IMAGE_DATA_DIRECTORY();
        this.ImportTable                    = new IMAGE_DATA_DIRECTORY();
        this.ResourceTable                  = new IMAGE_DATA_DIRECTORY();
        this.ExceptionTable                 = new IMAGE_DATA_DIRECTORY();
        this.CertificateTable               = new IMAGE_DATA_DIRECTORY();
        this.BaseRelocationTable            = new IMAGE_DATA_DIRECTORY();
        this.DebugDirectory                 = new IMAGE_DATA_DIRECTORY();
        this.ArchitectureSpecificData       = new IMAGE_DATA_DIRECTORY();
        this.GlobalPointerRegister          = new IMAGE_DATA_DIRECTORY();
        this.TLSTable                       = new IMAGE_DATA_DIRECTORY();
        this.LoadConfigurationTable         = new IMAGE_DATA_DIRECTORY();
        this.BoundImportTable               = new IMAGE_DATA_DIRECTORY();
        this.ImportAddressTable             = new IMAGE_DATA_DIRECTORY();
        this.DelayImportDescription         = new IMAGE_DATA_DIRECTORY();
        this.CLRRuntimeHeader               = new IMAGE_DATA_DIRECTORY();
        this.Reserved                       = new IMAGE_DATA_DIRECTORY();
    };
};

class IMAGE_OPTIONAL_HEADER64 {
    constructor() {
        this.Magic                          = 0x0000;
        this.MajorLinkerVersion             = 0x00;
        this.MinorLinkerVersion             = 0x00;
        this.SizeOfCode                     = 0x00000000;
        this.SizeOfInitializedData          = 0x00000000;
        this.SizeOfUninitializedData        = 0x00000000;
        this.AddressOfEntryPoint            = 0x00000000;
        this.BaseOfCode                     = 0x00000000;
        this.ImageBase                      = 0x0000000000000000;
        this.SectionAlignment               = 0x00000000;
        this.FileAlignment                  = 0x00000000;
        this.MajorOperatingSystemVersion    = 0x0000;
        this.MinorOperatingSystemVersion    = 0x0000;
        this.MajorImageVersion              = 0x0000;
        this.MinorImageVersion              = 0x0000;
        this.MajorSubsystemVersion          = 0x0000;
        this.MinorSubsystemVersion          = 0x0000;
        this.Win32VersionValue              = 0x00000000;
        this.SizeOfImage                    = 0x00000000;
        this.SizeOfHeaders                  = 0x00000000;
        this.CheckSum                       = 0x0000;
        this.Subsystem                      = 0x00;
        this.DllCharacteristics             = 0x00;
        this.SizeOfStackReverse             = 0x0000000000000000;
        this.SizeOfStackCommit              = 0x0000000000000000;
        this.SizeOfHeapReverse              = 0x0000000000000000;
        this.SizeOfHeapCommit               = 0x0000000000000000;
        this.LoaderFlags                    = 0x00000000;
        this.NumberOfRvaAndSizes            = 0x00000000;
        this.ExportTable                    = new IMAGE_DATA_DIRECTORY();
        this.ImportTable                    = new IMAGE_DATA_DIRECTORY();
        this.ResourceTable                  = new IMAGE_DATA_DIRECTORY();
        this.ExceptionTable                 = new IMAGE_DATA_DIRECTORY();
        this.CertificateTable               = new IMAGE_DATA_DIRECTORY();
        this.BaseRelocationTable            = new IMAGE_DATA_DIRECTORY();
        this.DebugDirectory                 = new IMAGE_DATA_DIRECTORY();
        this.ArchitectureSpecificData       = new IMAGE_DATA_DIRECTORY();
        this.GlobalPointerRegister          = new IMAGE_DATA_DIRECTORY();
        this.TLSTable                       = new IMAGE_DATA_DIRECTORY();
        this.LoadConfigurationTable         = new IMAGE_DATA_DIRECTORY();
        this.BoundImportTable               = new IMAGE_DATA_DIRECTORY();
        this.ImportAddressTable             = new IMAGE_DATA_DIRECTORY();
        this.DelayImportDescription         = new IMAGE_DATA_DIRECTORY();
        this.CLRRuntimeHeader               = new IMAGE_DATA_DIRECTORY();
        this.Reserved                       = new IMAGE_DATA_DIRECTORY();
    };
};

class IMAGE_FILE_HEADER {
    constructor() {
        this.Machine                = 0x0000;
        this.NumberOfSections       = 0x0000;
        this.TimeDateStamp          = 0x00000000;
        this.PointerToSymbolTable   = 0x00000000;
        this.NumberOfSymbols        = 0x00000000;
        this.SizeOfOptionalHeader   = 0x0000;
        this.Characteristics        = 0x0000;
    };
};

class IMAGE_NT_HEADER {
    constructor() {
        this.Signature          = 0x00000000;
        this.FileHeader         = new IMAGE_FILE_HEADER();
        // this.OptionalHeader     = new IMAGE_OPTIONAL_HEADER32();
    }
};

class IMAGE_IMPORT_DESCRIPTOR {
    constructor() {
        this.Characteristics        = 0x0000;
        this.OriginalFirstThunk     = 0x0000;
        this.TimeDateStamp          = 0x00000000;
        this.ForwarderChain         = 0x00000000;
        this.Name                   = 0x00000000;
        this.FirstThunk             = 0x00000000;
    };
};

class IMAGE_IMPORT_BY_NAME {
    constructor() {
        this.Hint = 0x0000;
        this.Name = new Array(100);
    };
};

class IMAGE_BASE_RELOCATION {
    constructor() {
        this.VirtualAddress     = 0x00000000;
        this.SizeOfBlock        = 0x00000000;  
    };
};

class IMAGE_SECTION_HEADER {
    constructor() {
        this.Name                   = new Array(8);
        this.VirtualSize            = 0x00000000;
        this.VirtualAddress         = 0x00000000;
        this.SizeOfRawData          = 0x00000000;
        this.PointerToRawData       = 0x00000000;
        this.PointerToRelocations   = 0x00000000;
        this.PointerToLineNumbers   = 0x00000000;
        this.NumberOfRelocations    = 0x0000;
        this.NumberOfLineNumbers    = 0x0000;
        this.Characteristics        = 0x00000000;
    };
};

// https://learn.microsoft.com/ko-kr/windows/win32/sysinfo/image-file-machine-constants
const MachineType = {
    UNKNOWN: 0x00,
    TARGET_HOST: 0x0001,
    I386: 0x014C,
    R3000: 0x0162,
    R4000: 0x0166,
    R10000: 0x0168,
    WCEMIPSV2: 0x0169,
    ALPHA: 0x0184,
    SH3: 0x01A2,
    SH3DSP: 0x01A3,
    SH3E: 0x01A4,
    SH4: 0x01A6,
    SH5: 0x01A8,
    ARM: 0x01C0,
    THUMB: 0x01C2,
    ARMNT: 0x01C4,
    AM33: 0x01D3,
    POWERPC: 0x01F0,
    POWERPCFP: 0x01F1,
    IA64: 0x0200,
    MIPS16: 0x0266,
    ALPHA64: 0x0284,
    MIPSFPU16: 0x0466,
    AXP64: 0x0284,
    TRICORE: 0x0520,
    CEF: 0x0CEF,
    EBC: 0x0EBC,
    AMD64: 0x8664,
    M32R: 0x9041,
    ARM64: 0xAA64,
    CEE: 0xC0EE,
};

// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32
const OtionalImage = {
    NT_HDR32: 0x10B,
    NT_HDR64: 0x20B,
    ROM_HDR: 0x107,
};

const ImageSubsystem = {
    UNKNOWN: 0,
    NATIVE: 1,
    WINDOWS_GUI: 2,
    WINDOWS_CUI: 3,
    OS2_CUI: 5,
    POSIX_CUI: 7,
    NATIVE_WINDOWS: 8,
    WINDOWS_CE_GUI: 9,
    EFI_APPLICATION: 10,
    BOOT_SERVICE_DRIVER: 11,
    EFI_RUNTIME_DRIVER: 12,
    EFI_ROM: 13,
    XBOX: 14,
    WINDOWS_BOOT_APPLICATION: 16,
};

class PEHeaderReader {
    constructor() {
        this.DosHeader = null;
        this.NTHeader = null;
        this.SectionHeaders = [];
    };

    /**
     * 
     * @param {BinaryReader} br 
     */
    Read(br) {
        // Read dos header
        this.DosHeader                  = new IMAGE_DOS_HEADER();
        this.DosHeader.e_magic          = br.ReadDataFromBytes(2);
        this.DosHeader.e_cblp           = br.ReadDataFromBytes(2);
        this.DosHeader.e_cp             = br.ReadDataFromBytes(2);
        this.DosHeader.e_crlc           = br.ReadDataFromBytes(2);
        this.DosHeader.e_cparhdr        = br.ReadDataFromBytes(2);
        this.DosHeader.e_minalloc       = br.ReadDataFromBytes(2);
        this.DosHeader.e_maxalloc       = br.ReadDataFromBytes(2);
        this.DosHeader.e_ss             = br.ReadDataFromBytes(2);
        this.DosHeader.e_sp             = br.ReadDataFromBytes(2);
        this.DosHeader.e_csum           = br.ReadDataFromBytes(2);
        this.DosHeader.e_ip             = br.ReadDataFromBytes(2);
        this.DosHeader.e_cs             = br.ReadDataFromBytes(2);
        this.DosHeader.e_lfarlc         = br.ReadDataFromBytes(2);
        this.DosHeader.e_ovno           = br.ReadDataFromBytes(2);
        
        for (let i = 0; i < this.DosHeader.e_res.length; i++) {
            this.DosHeader.e_res[i]     = br.ReadDataFromBytes(2);
        }

        this.DosHeader.e_oemid          = br.ReadDataFromBytes(2);
        this.DosHeader.e_oeminfo        = br.ReadDataFromBytes(2);

        for (let i = 0; i < this.DosHeader.e_res2.length; i++) {
            this.DosHeader.e_res2[i]    = br.ReadDataFromBytes(2);
        }

        this.DosHeader.e_lfanew         = br.ReadDataFromBytes(4);

        // Passing the MS DOS Stub~
        br.Offset = this.DosHeader.e_lfanew;

        console.log(64)

        // Read NT Headers
        this.NTHeader = new IMAGE_NT_HEADER();

        // Signature
        this.NTHeader.Signature = br.ReadDataFromBytes(4);

        // File Header
        this.NTHeader.FileHeader.Machine                = br.ReadDataFromBytes(2);
        this.NTHeader.FileHeader.NumberOfSections       = br.ReadDataFromBytes(2);
        this.NTHeader.FileHeader.TimeDateStamp          = br.ReadDataFromBytes(4);
        this.NTHeader.FileHeader.PointerToSymbolTable   = br.ReadDataFromBytes(4);
        this.NTHeader.FileHeader.NumberOfSymbols        = br.ReadDataFromBytes(4);
        this.NTHeader.FileHeader.SizeOfOptionalHeader   = br.ReadDataFromBytes(2);
        this.NTHeader.FileHeader.Characteristics        = br.ReadDataFromBytes(2);

        // Optional Header
        if ((this.NTHeader.FileHeader.Characteristics & 0x0100) === 0x0100) { // Check 32bit Version(?)
            this.NTHeader.OptionalHeader = new IMAGE_OPTIONAL_HEADER32();

            this.NTHeader.OptionalHeader.Magic                           = br.ReadDataFromBytes(2);
            this.NTHeader.OptionalHeader.MajorLinkerVersion              = br.ReadDataFromBytes(1);
            this.NTHeader.OptionalHeader.MinorLinkerVersion              = br.ReadDataFromBytes(1);
            this.NTHeader.OptionalHeader.SizeOfCode                      = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.SizeOfInitializedData           = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.SizeOfUninitializedData         = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.AddressOfEntryPoint             = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.BaseOfCode                      = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.BaseOfData                      = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.ImageBase                       = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.SectionAlignment                = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.FileAlignment                   = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.MajorOperatingSystemVersion     = br.ReadDataFromBytes(2);
            this.NTHeader.OptionalHeader.MinorOperatingSystemVersion     = br.ReadDataFromBytes(2);
            this.NTHeader.OptionalHeader.MajorImageVersion               = br.ReadDataFromBytes(2);
            this.NTHeader.OptionalHeader.MinorImageVersion               = br.ReadDataFromBytes(2);
            this.NTHeader.OptionalHeader.MajorSubsystemVersion           = br.ReadDataFromBytes(2);
            this.NTHeader.OptionalHeader.MinorSubsystemVersion           = br.ReadDataFromBytes(2);
            this.NTHeader.OptionalHeader.Win32VersionValue               = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.SizeOfImage                     = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.SizeOfHeaders                   = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.CheckSum                        = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.Subsystem                       = br.ReadDataFromBytes(2);
            this.NTHeader.OptionalHeader.DllCharacteristics              = br.ReadDataFromBytes(2);
            this.NTHeader.OptionalHeader.SizeOfStackReverse              = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.SizeOfStackCommit               = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.SizeOfHeapReverse               = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.SizeOfHeapCommit                = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.LoaderFlags                     = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.NumberOfRvaAndSizes             = br.ReadDataFromBytes(4);

            // Data Directories
            this.NTHeader.OptionalHeader.ExportTable.VirtualAddress              = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.ExportTable.Size                        = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.ImportTable.VirtualAddress              = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.ImportTable.Size                        = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.ResourceTable.VirtualAddress            = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.ResourceTable.Size                      = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.ExceptionTable.VirtualAddress           = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.ExceptionTable.Size                     = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.CertificateTable.VirtualAddress         = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.CertificateTable.Size                   = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.BaseRelocationTable.VirtualAddress      = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.BaseRelocationTable.Size                = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.DebugDirectory.VirtualAddress           = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.DebugDirectory.Size                     = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.ArchitectureSpecificData.VirtualAddress = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.ArchitectureSpecificData.Size           = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.GlobalPointerRegister.VirtualAddress    = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.GlobalPointerRegister.Size              = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.TLSTable.VirtualAddress                 = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.TLSTable.Size                           = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.LoadConfigurationTable.VirtualAddress   = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.LoadConfigurationTable.Size             = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.BoundImportTable.VirtualAddress         = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.BoundImportTable.Size                   = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.ImportAddressTable.VirtualAddress       = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.ImportAddressTable.Size                 = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.DelayImportDescription.VirtualAddress   = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.DelayImportDescription.Size             = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.CLRRuntimeHeader.VirtualAddress         = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.CLRRuntimeHeader.Size                   = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.Reserved.VirtualAddress                 = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.Reserved.Size                           = br.ReadDataFromBytes(4);

        } else {
            this.NTHeader.OptionalHeader = new IMAGE_OPTIONAL_HEADER64();

            this.NTHeader.OptionalHeader.Magic                           = br.ReadDataFromBytes(2);
            this.NTHeader.OptionalHeader.MajorLinkerVersion              = br.ReadDataFromBytes(1);
            this.NTHeader.OptionalHeader.MinorLinkerVersion              = br.ReadDataFromBytes(1);
            this.NTHeader.OptionalHeader.SizeOfCode                      = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.SizeOfInitializedData           = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.SizeOfUninitializedData         = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.AddressOfEntryPoint             = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.BaseOfCode                      = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.ImageBase                       = br.ReadDataFromBytes(8);
            this.NTHeader.OptionalHeader.SectionAlignment                = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.FileAlignment                   = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.MajorOperatingSystemVersion     = br.ReadDataFromBytes(2);
            this.NTHeader.OptionalHeader.MinorOperatingSystemVersion     = br.ReadDataFromBytes(2);
            this.NTHeader.OptionalHeader.MajorImageVersion               = br.ReadDataFromBytes(2);
            this.NTHeader.OptionalHeader.MinorImageVersion               = br.ReadDataFromBytes(2);
            this.NTHeader.OptionalHeader.MajorSubsystemVersion           = br.ReadDataFromBytes(2);
            this.NTHeader.OptionalHeader.MinorSubsystemVersion           = br.ReadDataFromBytes(2);
            this.NTHeader.OptionalHeader.Win32VersionValue               = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.SizeOfImage                     = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.SizeOfHeaders                   = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.CheckSum                        = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.Subsystem                       = br.ReadDataFromBytes(2);
            this.NTHeader.OptionalHeader.DllCharacteristics              = br.ReadDataFromBytes(2);
            this.NTHeader.OptionalHeader.SizeOfStackReverse              = br.ReadDataFromBytes(8);
            this.NTHeader.OptionalHeader.SizeOfStackCommit               = br.ReadDataFromBytes(8);
            this.NTHeader.OptionalHeader.SizeOfHeapReverse               = br.ReadDataFromBytes(8);
            this.NTHeader.OptionalHeader.SizeOfHeapCommit                = br.ReadDataFromBytes(8);
            this.NTHeader.OptionalHeader.LoaderFlags                     = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.NumberOfRvaAndSizes             = br.ReadDataFromBytes(4);

            // Data Directories
            this.NTHeader.OptionalHeader.ExportTable.VirtualAddress              = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.ExportTable.Size                        = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.ImportTable.VirtualAddress              = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.ImportTable.Size                        = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.ResourceTable.VirtualAddress            = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.ResourceTable.Size                      = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.ExceptionTable.VirtualAddress           = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.ExceptionTable.Size                     = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.CertificateTable.VirtualAddress         = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.CertificateTable.Size                   = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.BaseRelocationTable.VirtualAddress      = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.BaseRelocationTable.Size                = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.DebugDirectory.VirtualAddress           = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.DebugDirectory.Size                     = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.ArchitectureSpecificData.VirtualAddress = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.ArchitectureSpecificData.Size           = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.GlobalPointerRegister.VirtualAddress    = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.GlobalPointerRegister.Size              = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.TLSTable.VirtualAddress                 = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.TLSTable.Size                           = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.LoadConfigurationTable.VirtualAddress   = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.LoadConfigurationTable.Size             = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.BoundImportTable.VirtualAddress         = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.BoundImportTable.Size                   = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.ImportAddressTable.VirtualAddress       = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.ImportAddressTable.Size                 = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.DelayImportDescription.VirtualAddress   = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.DelayImportDescription.Size             = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.CLRRuntimeHeader.VirtualAddress         = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.CLRRuntimeHeader.Size                   = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.Reserved.VirtualAddress                 = br.ReadDataFromBytes(4);
            this.NTHeader.OptionalHeader.Reserved.Size                           = br.ReadDataFromBytes(4);
        }

        // Section Headers        
        for(let i = 0; i < this.NTHeader.FileHeader.NumberOfSections; i++) {
            let temp = new IMAGE_SECTION_HEADER();

            for (let j = 0; j < temp.Name.length; j++) {
                temp.Name[j] = br.ReadDataFromBytes(1);
            }
            temp.VirtualSize = br.ReadDataFromBytes(4);
            temp.VirtualAddress = br.ReadDataFromBytes(4);
            temp.SizeOfRawData = br.ReadDataFromBytes(4);
            temp.PointerToRawData = br.ReadDataFromBytes(4);
            temp.PointerToRelocations = br.ReadDataFromBytes(4);
            temp.PointerToLineNumbers = br.ReadDataFromBytes(4);
            temp.NumberOfRelocations = br.ReadDataFromBytes(2);
            temp.NumberOfLineNumbers = br.ReadDataFromBytes(2);
            temp.Characteristics = br.ReadDataFromBytes(4);

            this.SectionHeaders.push(temp);
        }
    };
};
