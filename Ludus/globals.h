#pragma once
#include <cinttypes>
#include <Windows.h>
#include <iostream>
#include <Winternl.h>
#include <stdio.h>
#include <Tlhelp32.h>

void SetConsoleTextColor(int color);
void ResetConsoleTextColor();
void PrintColoredText(const char* text, int color);
void PrintColoredMessage(const std::string& prefix, const std::string& message, int color);
void log(const std::string& message, int messageType);
void PrintInstructionsAroundAddress(const void* address, int instructionCount = 20);
uint64_t FollowCallAddress(const void* address);
void PrintInstructionsInsideFunction(uintptr_t function);