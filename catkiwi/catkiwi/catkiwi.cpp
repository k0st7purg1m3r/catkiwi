#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdio>
#include <thread>
#include <atomic>
#include <TlHelp32.h>

const std::string ENCRYPTED_EXT = ".pdr";
std::vector<unsigned char> g_xorKey = { 19, 55, 222, 173 };
bool g_deletePdr = false;
std::atomic<bool> g_running(true);
int g_hiveCounter = 0;

void MakeWindowTopMost() {
	HWND hwnd = GetConsoleWindow();
	if (hwnd) {
		SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
		SetForegroundWindow(hwnd);
		SetActiveWindow(hwnd);
	}
}

void KeepWindowTopMost() {
	while (g_running) {
		MakeWindowTopMost();
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	}
}

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
	char windowTitle[256];
	if (GetWindowTextA(hwnd, windowTitle, sizeof(windowTitle)) > 0) {
		std::string title(windowTitle);
		if (title.find("CatCrypt") != std::string::npos ||
			title.find("catcrypt") != std::string::npos) {

			printf("[!] Found window: %s\n", windowTitle);

			DWORD pid = 0;
			GetWindowThreadProcessId(hwnd, &pid);
			if (pid != 0) {
				printf("[!] Killing PID: %d\n", pid);
				HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
				if (hProcess) {
					TerminateProcess(hProcess, 0);
					CloseHandle(hProcess);
				}
			}
			PostMessageA(hwnd, WM_CLOSE, 0, 0);
		}
	}
	return TRUE;
}

void WindowHunterThread() {
	while (g_running) {
		EnumWindows(EnumWindowsProc, 0);
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
	}
}

bool IsWinPE() {
	HKEY hKey;
	LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\MiniNT", 0, KEY_READ, &hKey);
	if (result == ERROR_SUCCESS) {
		RegCloseKey(hKey);
		return true;
	}
	result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Control\\MiniNT", 0, KEY_READ, &hKey);
	if (result == ERROR_SUCCESS) {
		RegCloseKey(hKey);
		return true;
	}
	return false;
}

std::string LoadHive(const std::string& hivePath, const std::string& prefix) {
	std::string keyName = prefix + std::to_string(g_hiveCounter++);
	if (RegLoadKeyA(HKEY_LOCAL_MACHINE, keyName.c_str(), hivePath.c_str()) == ERROR_SUCCESS) {
		printf("[+] Loaded hive: %s -> HKLM\\%s\n", hivePath.c_str(), keyName.c_str());
		return keyName;
	}
	else {
		printf("[-] Failed to load hive: %s\n", hivePath.c_str());
		return "";
	}
}

void UnloadHive(const std::string& keyName) {
	if (!keyName.empty()) {
		if (RegUnLoadKeyA(HKEY_LOCAL_MACHINE, keyName.c_str()) == ERROR_SUCCESS) {
			printf("[+] Unloaded hive: HKLM\\%s\n", keyName.c_str());
		}
		else {
			printf("[-] Failed to unload hive: HKLM\\%s\n", keyName.c_str());
		}
	}
}

void CleanHive(const std::string& hiveRoot) {
	printf("[*] Cleaning hive: %s\n", hiveRoot.c_str());
	std::string base = hiveRoot + "\\";

	const char* runKeys[] = { "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" };
	const char* badValues[] = { "WindowsSecurityHealth", "EdgeUpdate", "*WindowsInit", "WindowsDefenderService", "CatRestorer" };
	for (const char* keyPath : runKeys) {
		HKEY hKey;
		std::string fullPath = base + keyPath;
		if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, fullPath.c_str(), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
			for (const char* val : badValues) RegDeleteValueA(hKey, val);
			RegCloseKey(hKey);
		}
	}

	const char* winlogonPath = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
	HKEY hKey;
	std::string winlogonFull = base + winlogonPath;
	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, winlogonFull.c_str(), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
		RegSetValueExA(hKey, "Shell", 0, REG_SZ, (const BYTE*)"explorer.exe", 13);
		RegSetValueExA(hKey, "Userinit", 0, REG_SZ, (const BYTE*)"C:\\Windows\\system32\\userinit.exe,", 35);
		RegDeleteValueA(hKey, "AutoRestartShell");
		RegCloseKey(hKey);
	}

	const char* ifeoPath = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
	const char* blockedProgs[] = { "cmd.exe", "powershell.exe", "pwsh.exe", "taskmgr.exe", "regedit.exe", "msconfig.exe", "mmc.exe", "taskschd.msc", "control.exe", "eventvwr.exe", "perfmon.exe", "resmon.exe", "services.msc", "compmgmt.msc", "devmgmt.msc", "diskmgmt.msc", "gpedit.msc" };
	for (const char* prog : blockedProgs) {
		std::string fullPath = base + ifeoPath + "\\" + prog;
		RegDeleteKeyA(HKEY_LOCAL_MACHINE, fullPath.c_str());
	}

	const char* policyPaths[] = { "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" };
	const char* policyValues[] = { "DisableTaskMgr", "DisableCMD", "DisableRegistryTools", "NoRun", "NoClose", "NoLogoff", "NoRestart", "NoSleep", "DisableChangePassword", "HideFastUserSwitching", "DisableLockWorkstation" };
	for (const char* path : policyPaths) {
		std::string fullPath = base + path;
		if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, fullPath.c_str(), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
			for (const char* val : policyValues) RegDeleteValueA(hKey, val);
			RegCloseKey(hKey);
		}
	}

	const char* services[] = { "SYSTEM\\CurrentControlSet\\Services\\USBSTOR", "SYSTEM\\CurrentControlSet\\Services\\cdrom" };
	DWORD startValues[] = { 3, 1 };
	for (int i = 0; i < 2; i++) {
		std::string fullPath = base + services[i];
		if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, fullPath.c_str(), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
			RegSetValueExA(hKey, "Start", 0, REG_DWORD, (const BYTE*)&startValues[i], sizeof(DWORD));
			RegCloseKey(hKey);
		}
	}

	std::string psPath = base + "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\WindowsPowerShell";
	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, psPath.c_str(), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
		DWORD enable = 1;
		RegSetValueExA(hKey, "EnableScripts", 0, REG_DWORD, (const BYTE*)&enable, sizeof(enable));
		RegDeleteValueA(hKey, "DisableCommandLine");
		RegCloseKey(hKey);
	}

	printf("[+] Hive cleaned: %s\n", hiveRoot.c_str());
}

bool EndsWith(const std::string& str, const std::string& suffix) {
	if (str.length() < suffix.length()) return false;
	return str.compare(str.length() - suffix.length(), suffix.length(), suffix) == 0;
}

std::string RemoveExtension(const std::string& path) {
	if (EndsWith(path, ENCRYPTED_EXT)) return path.substr(0, path.length() - ENCRYPTED_EXT.length());
	return path;
}

void DecryptFile(const std::string& inputPath) {
	std::ifstream in(inputPath, std::ios::binary);
	if (!in) return;
	std::vector<unsigned char> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
	in.close();
	for (size_t i = 0; i < data.size(); i++) {
		unsigned char temp = (data[i] - 105) % 256;
		data[i] = temp ^ g_xorKey[i % g_xorKey.size()];
	}
	std::string outputPath = RemoveExtension(inputPath);
	if (GetFileAttributesA(outputPath.c_str()) != INVALID_FILE_ATTRIBUTES) outputPath += ".restored";
	std::ofstream out(outputPath, std::ios::binary);
	if (out) {
		out.write(reinterpret_cast<const char*>(data.data()), data.size());
		out.close();
		if (g_deletePdr) {
			if (DeleteFileA(inputPath.c_str())) printf("[+] Restored and deleted: %s\n", inputPath.c_str());
			else printf("[+] Restored: %s\n", inputPath.c_str());
		}
		else {
			printf("[+] Restored: %s\n", inputPath.c_str());
		}
	}
}

void CrawlAndDecrypt(const std::string& dirPath) {
	std::string searchPath = dirPath + "\\*";
	WIN32_FIND_DATAA findData;
	HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);
	if (hFind == INVALID_HANDLE_VALUE) return;
	do {
		if (strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0) continue;
		std::string fullPath = dirPath + "\\" + findData.cFileName;
		if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			CrawlAndDecrypt(fullPath);
		}
		else {
			if (EndsWith(fullPath, ENCRYPTED_EXT)) DecryptFile(fullPath);
		}
	} while (FindNextFileA(hFind, &findData));
	FindClose(hFind);
}

std::vector<std::string> GetAllDrives() {
	std::vector<std::string> drives;
	DWORD mask = GetLogicalDrives();
	for (char letter = 'A'; letter <= 'Z'; letter++) {
		if (mask & (1 << (letter - 'A'))) {
			std::string drive = std::string(1, letter) + ":\\";
			UINT type = GetDriveTypeA(drive.c_str());
			if (type == DRIVE_FIXED || type == DRIVE_REMOVABLE) {
				drives.push_back(drive);
			}
		}
	}
	return drives;
}

void ProcessDrive(const std::string& drive) {
	printf("\n[*] Processing drive: %s\n", drive.c_str());

	std::string softwareHive = drive + "Windows\\System32\\config\\SOFTWARE";
	std::string systemHive = drive + "Windows\\System32\\config\\SYSTEM";

	if (GetFileAttributesA(softwareHive.c_str()) != INVALID_FILE_ATTRIBUTES) {
		std::string key = LoadHive(softwareHive, "CATKIWI_SW_");
		if (!key.empty()) {
			CleanHive("HKLM\\" + key);
			UnloadHive(key);
		}
	}
	if (GetFileAttributesA(systemHive.c_str()) != INVALID_FILE_ATTRIBUTES) {
		std::string key = LoadHive(systemHive, "CATKIWI_SY_");
		if (!key.empty()) {
			CleanHive("HKLM\\" + key);
			UnloadHive(key);
		}
	}

	std::string usersPath = drive + "Users\\*";
	WIN32_FIND_DATAA findData;
	HANDLE hFind = FindFirstFileA(usersPath.c_str(), &findData);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				if (strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0) continue;
				std::string ntuserPath = drive + "Users\\" + findData.cFileName + "\\NTUSER.DAT";
				if (GetFileAttributesA(ntuserPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
					std::string key = LoadHive(ntuserPath, "CATKIWI_USR_");
					if (!key.empty()) {
						CleanHive("HKLM\\" + key);
						UnloadHive(key);
					}
				}
			}
		} while (FindNextFileA(hFind, &findData));
		FindClose(hFind);
	}

	printf("[*] Decrypting files on %s\n", drive.c_str());
	hFind = FindFirstFileA(usersPath.c_str(), &findData);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				if (strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0) continue;
				std::string userDir = drive + "Users\\" + findData.cFileName;
				CrawlAndDecrypt(userDir);
			}
		} while (FindNextFileA(hFind, &findData));
		FindClose(hFind);
	}
}

int main() {
	SetConsoleCP(866);
	SetConsoleOutputCP(866);

	std::thread topMostThread(KeepWindowTopMost);
	std::thread hunterThread(WindowHunterThread);

	printf("=== CATKIWI 2.0 ===\n");
	bool isPE = IsWinPE();
	printf("[*] Mode: %s\n", isPE ? "WinPE" : "Windows");

	int delChoice;
	printf("Delete .pdr after decryption? 1 - Yes, 0 - No: ");
	if (scanf_s("%d", &delChoice) != 1) delChoice = 0;
	g_deletePdr = (delChoice == 1);
	printf("[*] Delete .pdr: %s\n", g_deletePdr ? "YES" : "NO");

	int c; while ((c = getchar()) != '\n' && c != EOF);
	printf("\nPress Enter to start...\n");
	getchar();

	if (isPE) {
		printf("\n[*] Scanning all drives...\n");
		std::vector<std::string> drives = GetAllDrives();
		for (const auto& drive : drives) {
			ProcessDrive(drive);
		}
	}
	else {
		printf("\n[*] Cleaning local registry and decrypting...\n");
		CleanHive("HKLM\\SOFTWARE");
		CleanHive("HKLM\\SYSTEM");
		char* userProfile = nullptr;
		size_t len = 0;
		_dupenv_s(&userProfile, &len, "USERPROFILE");
		if (userProfile) {
			std::vector<std::string> targets = {
				std::string(userProfile) + "\\Desktop",
				std::string(userProfile) + "\\Downloads",
				std::string(userProfile) + "\\Documents",
				std::string(userProfile) + "\\Pictures",
				std::string(userProfile) + "\\Music",
				std::string(userProfile) + "\\Videos"
			};
			for (const auto& target : targets) {
				if (GetFileAttributesA(target.c_str()) != INVALID_FILE_ATTRIBUTES) {
					printf("[*] Scanning: %s\n", target.c_str());
					CrawlAndDecrypt(target);
				}
			}
			free(userProfile);
		}
	}

	printf("\n[!] Done. Press Enter to exit...\n");
	getchar();

	g_running = false;
	if (topMostThread.joinable()) topMostThread.join();
	if (hunterThread.joinable()) hunterThread.join();

	return 0;
}