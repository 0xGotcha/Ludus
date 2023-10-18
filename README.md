
<p align="center"><img src="https://github.com/0xGotcha/Ludus/assets/13496934/4442c452-6531-49dd-8eb0-a18741aca3c8" alt="Image Alt Text" width="500" height="500"></p>



# What is Ludus?

Ludus is a versatile binary that incorporates a wide array of functions designed to help budding reverse engineers enhance their skills in countering malware defenses aimed at debuggers, virtual machines (VMs), and analysis tools. When executed within x64dbg or your preferred debugger, this application presents a menu of options, each corresponding to a distinct functionality. Upon selection, the application reveals the assembly instructions pertaining to the chosen function, thereby facilitating the learning process of reverse engineering and circumventing malware detection mechanisms. Ludus is currently still under development and actively being worked on.

![image](https://github.com/0xGotcha/Ludus/assets/13496934/c6404c45-4582-4d07-b0fd-ad60f4a0e431)

# How to use Ludus?
- Drag Ludus into your favorite debugger
- Choose the function you would like to run
- Observe Instructions inside of the function to assist reversing
- If caught use the INFO to help assist defeating the check

# Choose the functionality 
- IsDebuggerPresent
- CheckRemoteDebuggerPresent
- ProcessFileName
- CheckWindowClassName
- NtSetInformationThread
- QueryPerformanceCounter
- GetTickCount
- HardwareDebugRegisters
- MovSS
- CloseHandleException
- SingleStepException
- Int3
- PrefixHop
- Int2D

# References
- OALabs Community
- @JunkCod3
- @future_wizard
- https://github.com/zyantific/zydis
- https://github.com/HackOvert/AntiDBG
