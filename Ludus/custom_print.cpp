#include <iostream>
#include <Windows.h>
#include <Zydis/Zydis.h>
#include <Zycore/Zycore.h>
#include <unordered_map>
#include <map>

// Console color constants
#define CONSOLE_COLOR_RESET     15
#define CONSOLE_COLOR_RED       12
#define CONSOLE_COLOR_GREEN     10
#define CONSOLE_COLOR_BLUE      9
#define CONSOLE_COLOR_YELLOW    14
#define CONSOLE_COLOR_ORANGE    6
#define CONSOLE_COLOR_CYAN      11
#define CONSOLE_COLOR_MAGENTA   13
#define CONSOLE_COLOR_PURPLE    5

void SetConsoleTextColor(int color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

void ResetConsoleTextColor() {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), CONSOLE_COLOR_RESET);
}

void PrintColoredText(const char* text, int color) {
    SetConsoleTextColor(color);
    std::cout << text;
    ResetConsoleTextColor();
}

void PrintColoredMessage(const std::string& prefix, const std::string& message, int color) {
    SetConsoleTextColor(color);
    std::cout << "[" << prefix << "] " << message;
    ResetConsoleTextColor();
    std::cout << std::endl;
}

void log(const std::string& message, int messageType) {
    switch (messageType) {
    case 0: // Debug
        PrintColoredMessage("DEBUG", message, CONSOLE_COLOR_RED);
        break;
    case 1: // Success
        PrintColoredMessage("SUCCESS", message, CONSOLE_COLOR_GREEN);
        break;
    case 2: // Info
        PrintColoredMessage("INFO", message, CONSOLE_COLOR_ORANGE);
        break;
    default:
        std::cout << "Invalid message type." << std::endl;
        break;
    }
}

void PrintInstructionsAroundAddress(const void* address, int instructionCount = 20) {
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

    const int instructionHalfCount = instructionCount / 2;
    const uint8_t* startAddress = static_cast<const uint8_t*>(address) - (instructionHalfCount * 15);

    for (int i = 0; i < instructionCount; ++i) {
        ZydisDecodedInstruction instruction;
        if (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, startAddress, 15, &instruction))) {
            char buffer[256];
            ZydisFormatter formatter;
            ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
            ZydisFormatterFormatInstruction(&formatter, &instruction, buffer, sizeof(buffer), reinterpret_cast<uint64_t>(startAddress));

            int textColor = CONSOLE_COLOR_RESET; // Default text color

            // Set color based on the instruction's category
            switch (instruction.meta.category) {
            case ZYDIS_CATEGORY_CALL:   textColor = CONSOLE_COLOR_GREEN;  break;
            case ZYDIS_CATEGORY_RET:    textColor = CONSOLE_COLOR_RED;    break;
                // Add more cases for other categories as needed
            }

            // Set color for specific mnemonics
            if (instruction.mnemonic == ZYDIS_MNEMONIC_ADD) {
                textColor = CONSOLE_COLOR_BLUE;
            }
            else if (instruction.mnemonic == ZYDIS_MNEMONIC_SUB) {
                textColor = CONSOLE_COLOR_YELLOW;
            }
            else if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV) {
                textColor = CONSOLE_COLOR_GREEN;
            }
            else if (instruction.mnemonic == ZYDIS_MNEMONIC_JMP) {
                textColor = CONSOLE_COLOR_ORANGE;
            }
            // Add more mnemonic cases and color assignments

            // Print the address and initial part of the output
            std::cout << "0x" << std::hex << reinterpret_cast<uint64_t>(startAddress) << ": ";

            // Find the position of the mnemonic in the buffer
            const char* mnemonicPos = strstr(buffer, ZydisMnemonicGetString(instruction.mnemonic));
            if (mnemonicPos) {
                // Print the part before the mnemonic
                std::cout.write(buffer, mnemonicPos - buffer);

                // Print the colored mnemonic
                PrintColoredText(ZydisMnemonicGetString(instruction.mnemonic), textColor);

                // Print the part after the mnemonic
                std::cout << mnemonicPos + strlen(ZydisMnemonicGetString(instruction.mnemonic));
            }
            else {
                std::cout << buffer; // Print the entire buffer as-is
            }

            std::cout << std::endl;

            startAddress += instruction.length;
        }
        else {
            std::cerr << "Failed to decode instruction at 0x" << std::hex << reinterpret_cast<uint64_t>(startAddress) << std::endl;
            break;
        }
    }
}


uintptr_t FollowCallAddress(const void* address) {
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

    const uint8_t* startAddress = static_cast<const uint8_t*>(address);

    //ZydisDecodedInstruction instruction;
    //if (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, startAddress, 15, &instruction))) {
    //    if (instruction.meta.category == ZYDIS_CATEGORY_CALL) {
    //        if (instruction.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
    //            uintptr_t targetAddress = instruction.operands[0].imm.value.u;
    //            return targetAddress;
    //        }
    //    }
    //}

    // Return 0 if no valid call instruction is found
    return (uintptr_t)startAddress;
}


std::unordered_map<ZydisMnemonic, int> mnemonicToColor = {
    { ZYDIS_MNEMONIC_MOV, CONSOLE_COLOR_BLUE },
    { ZYDIS_MNEMONIC_LEA, CONSOLE_COLOR_YELLOW },
    { ZYDIS_MNEMONIC_XCHG, CONSOLE_COLOR_GREEN },
    { ZYDIS_MNEMONIC_PUSH, CONSOLE_COLOR_ORANGE },
    { ZYDIS_MNEMONIC_POP, CONSOLE_COLOR_RED },
    { ZYDIS_MNEMONIC_ADD, CONSOLE_COLOR_BLUE },
    { ZYDIS_MNEMONIC_SUB, CONSOLE_COLOR_YELLOW },
    { ZYDIS_MNEMONIC_MUL, CONSOLE_COLOR_GREEN },
    { ZYDIS_MNEMONIC_IMUL, CONSOLE_COLOR_ORANGE },
    { ZYDIS_MNEMONIC_DIV, CONSOLE_COLOR_RED },
    { ZYDIS_MNEMONIC_IDIV, CONSOLE_COLOR_YELLOW },
    { ZYDIS_MNEMONIC_AND, CONSOLE_COLOR_CYAN },
    { ZYDIS_MNEMONIC_OR, CONSOLE_COLOR_YELLOW },
    { ZYDIS_MNEMONIC_XOR, CONSOLE_COLOR_GREEN },
    { ZYDIS_MNEMONIC_NOT, CONSOLE_COLOR_YELLOW },
    { ZYDIS_MNEMONIC_TEST, CONSOLE_COLOR_ORANGE },
    { ZYDIS_MNEMONIC_JMP, CONSOLE_COLOR_RED },
    { ZYDIS_MNEMONIC_JZ, CONSOLE_COLOR_CYAN },
    { ZYDIS_MNEMONIC_JNZ, CONSOLE_COLOR_YELLOW },
    { ZYDIS_MNEMONIC_CMP, CONSOLE_COLOR_MAGENTA },
    { ZYDIS_MNEMONIC_INC, CONSOLE_COLOR_GREEN },
    { ZYDIS_MNEMONIC_DEC, CONSOLE_COLOR_GREEN },
    { ZYDIS_MNEMONIC_SAR, CONSOLE_COLOR_YELLOW },
    { ZYDIS_MNEMONIC_NOP, CONSOLE_COLOR_RESET },   // Color for NOP
    { ZYDIS_MNEMONIC_JBE, CONSOLE_COLOR_RED },
    { ZYDIS_MNEMONIC_JB, CONSOLE_COLOR_RED },
    { ZYDIS_MNEMONIC_JLE, CONSOLE_COLOR_RED },
    { ZYDIS_MNEMONIC_JL, CONSOLE_COLOR_RED },
    { ZYDIS_MNEMONIC_LOOP, CONSOLE_COLOR_RED },
    { ZYDIS_MNEMONIC_LOOPE, CONSOLE_COLOR_RED },
    { ZYDIS_MNEMONIC_LOOPNE, CONSOLE_COLOR_RED },
    { ZYDIS_MNEMONIC_CALL, CONSOLE_COLOR_GREEN },
    { ZYDIS_MNEMONIC_RET, CONSOLE_COLOR_RED },
    { ZYDIS_MNEMONIC_POP, CONSOLE_COLOR_RED },
    // Add more mnemonic-color pairs here
};


std::unordered_map<ZydisRegister, int> registerToColor = {
    { ZYDIS_REGISTER_AL, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_AH, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_AX, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_EAX, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_RAX, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_BL, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_BH, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_BX, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_EBX, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_RBX, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_CL, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_CH, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_CX, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_ECX, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_RCX, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_DL, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_DH, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_DX, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_EDX, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_RDX, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_SIL, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_SI, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_ESI, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_RSI, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_DIL, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_DI, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_EDI, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_RDI, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_BPL, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_BP, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_EBP, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_RBP, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_SPL, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_SP, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_ESP, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_RSP, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_R8B, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_R8W, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_R8D, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_R8, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_R9B, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_R9W, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_R9D, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_R9, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_R10B, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_R10W, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_R10D, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_R10, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_R11B, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_R11W, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_R11D, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_R11, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_R12B, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_R12W, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_R12D, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_R12, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_R13B, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_R13W, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_R13D, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_R13, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_R14B, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_R14W, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_R14D, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_R14, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_R15B, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_R15W, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_R15D, CONSOLE_COLOR_YELLOW },
    { ZYDIS_REGISTER_R15, CONSOLE_COLOR_YELLOW },
};



// Function to print instructions within a function
void PrintInstructionsInsideFunction(uintptr_t function) {
    // Cast the function pointer to a byte pointer to access its memory
    const uint8_t* functionBytes = reinterpret_cast<const uint8_t*>(function);

    // Initialize Zydis decoder
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

    // Start disassembling from the function's memory
    uintptr_t startAddress = reinterpret_cast<uintptr_t>(functionBytes);
    size_t remainingSize = 0x100; // Limit the disassembly to a certain size

    for (int i = 0; i < 25; ++i) {
        ZydisDecodedInstruction instruction;
        if (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, reinterpret_cast<const void*>(startAddress), remainingSize, &instruction))) {
            char buffer[256];
            ZydisFormatter formatter;
            ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
            ZydisFormatterFormatInstruction(&formatter, &instruction, buffer, sizeof(buffer), startAddress);

            int textColor = CONSOLE_COLOR_RESET; // Default text color

            // Set color based on the instruction's category
            if (instruction.meta.category == ZYDIS_CATEGORY_CALL) {
                textColor = CONSOLE_COLOR_GREEN;
            }
            else if (instruction.meta.category == ZYDIS_CATEGORY_RET) {
                textColor = CONSOLE_COLOR_RED;
            }
            else {
                auto mnemonicColorIt = mnemonicToColor.find(instruction.mnemonic);
                if (mnemonicColorIt != mnemonicToColor.end()) {
                    textColor = mnemonicColorIt->second;
                }
            }


            // Print the address and initial part of the output
            std::cout << "0x" << std::hex << startAddress << ": ";

            // Find the position of the mnemonic in the buffer
            const char* mnemonicPos = strstr(buffer, ZydisMnemonicGetString(instruction.mnemonic));
            if (mnemonicPos) {
                std::string mnemonicString(ZydisMnemonicGetString(instruction.mnemonic));

                // Print the part before the mnemonic
                std::cout.write(buffer, mnemonicPos - buffer);

                // Print the colored mnemonic
                PrintColoredText(ZydisMnemonicGetString(instruction.mnemonic), textColor);

                // Print the part after the mnemonic
                std::cout << mnemonicPos + strlen(ZydisMnemonicGetString(instruction.mnemonic));

            }
            else {
                std::cout << buffer; // Print the entire buffer as-is
            }

            std::cout << std::endl;

            startAddress += instruction.length;
        }
        else {
            std::cerr << "Failed to decode instruction at 0x" << std::hex << startAddress << std::endl;
            break;
        }
    }
}
