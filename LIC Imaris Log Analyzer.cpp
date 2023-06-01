//
// LIC_Imaris_Log_Analyzer.exe
// LIC_Imaris_Log_Analyzer.exe is a modification of the RLMReportLogGenCmdLine.exe (a command line code wrapper over unmodified RLM Log Reader). 
//
// Copyright © 2022 Tobias Wernet - Albert Ludwigs University Freiburg
// 
// original RLMReportLogGenCmdLine.exe Copyright © 2017 Intergraph® Corporation d/b/a Hexagon Safety & Infrastructure (“Hexagon”). Hexagon is part of Hexagon AB. All rights reserved.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as 
// published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty 
// of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
//
// If you wish to acquire a copy of the source code for RLMReportLogGenCmdLine.exe, go to https://github.com/hexagonSI-RMS and download a copy.
//
// You should have received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
// LIC_Imaris_Log_Analyzer.exe SUBCOMPONENT:
// 
// LIC_Imaris_Log_Analyzer.exe includes the following modified subcomponent with a separate copyright notice and the 
// following license terms. Your use of the subcomponent is subject to the terms and conditions of the following license: 
//
// RLM Log Reader classes 
//
// Copyright 2014 Steve Robinson.
//
// The RLM Log Reader code is free software: you can redistribute it and/or modify it under the terms of the 
// GNU General Public License as published by the Free Software Foundation, either version 3 of the License, 
// or (at your option) any later version.
//
// RLM Log Reader is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied 
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
//
// If you wish to acquire a copy of the source code for the RLM Log Reader code, go to 
// https://sourceforge.net/projects/rlmlogreader/ and download a copy.
//
// You should receive a copy of the GNU General Public License along with RLM Log Reader.  If not, see <http://www.gnu.org/licenses/>.
//

#include "windows.h"
#include "stdafx.h"
#include "LogData.h"
#include "Exceptions.h"
#include "resource.h"

#define PARM_OVERWRITE L"-o"
#define PARM_CONFLICT  L"-c"

#define INVALID_ARGUMENTS       -100
#define CONFLICTING_FILES       -200
#define INVALID_INDEX           -300
#define EVENT_DATA              -400
#define EVENT_DETAIL            -500
#define INVALID_PRODUCT_VERSION -600
#define INVALID_FILE_FORMAT     -700
#define UNKNOWN_ERROR           -800
#define UNABLE_TO_FIND_FILE     -900
#define UNABLE_TO_FIND_DIR      -1000

#define MAX_STR_LEN 1024

//
// Function to load resource strings.
//
void LoadStringFromResource(int id, WCHAR *szBuffer)
{
	LoadString(GetModuleHandle(NULL), id, szBuffer, MAX_STR_LEN);
}

//
// This function prints the usage info for the executable.
//
void printUsage()
{
	WCHAR resourceString[MAX_STR_LEN];

	SecureZeroMemory(resourceString, (sizeof(WCHAR) * MAX_STR_LEN));

	wprintf_s(L"\n\n");
	LoadStringFromResource(IDS_USAGE, resourceString);
	wprintf_s(resourceString);
	wprintf_s(L"\n\n");
	LoadStringFromResource(IDS_CMDLINE_NO_OPT, resourceString);
	wprintf_s(resourceString);
	wprintf_s(L"\n\n");
	LoadStringFromResource(IDS_NO_OPT_DESCR, resourceString);
	wprintf_s(resourceString);
	wprintf_s(L"\n\n");
	LoadStringFromResource(IDS_CMDLINE_OVERWRITE, resourceString);
	wprintf_s(resourceString);
	wprintf_s(L"\n\n");
	LoadStringFromResource(IDS_OVERWRITE_DESCR, resourceString);
	wprintf_s(resourceString);
	wprintf_s(L"\n\n");
	LoadStringFromResource(IDS_CMDLINE_CONFLICT, resourceString);
	wprintf_s(resourceString);
	wprintf_s(L"\n\n");
	LoadStringFromResource(IDS_CONFLICT_DESCR, resourceString);
	wprintf_s(resourceString);
	wprintf_s(L"\n\n");
	LoadStringFromResource(IDS_RETURN_CODES, resourceString);
	wprintf_s(resourceString);
	wprintf_s(L"\n\n");
	LoadStringFromResource(IDS_RETURN_CODE_STRING, resourceString);
	wprintf_s(resourceString);
	wprintf_s(L"\n\n");
}

// 
// Convert wide char to a string.
//
std::string ConvertToString(const wchar_t *s)
{
	try
	{
		wstring ws(s);
		string convStr(ws.begin(), ws.end());
		return(convStr);
	}
	catch (exception)
	{
		string blankString = "";
		return(blankString);
	}
}

int _tmain(int argc, _TCHAR* argv[])
{
	int         returnVal = 0;
	std::string inputFilePathString;
	std::string outputDirectoryString;
	std::string conflictedFileList;
	bool        bOverwrite = false;
	bool        bConflicts = false;
	bool        bGoodArgs = false;
	WCHAR       resourceString[MAX_STR_LEN];
	WCHAR       wcArgv[MAX_STR_LEN];

	//
	// Initialize
	//
	SecureZeroMemory(wcArgv, (sizeof(WCHAR)*MAX_STR_LEN));
	wcArgv[0] = L'\0'; // To pacify Visual Studio code analysis.

	//
	// Make sure we get command line parameters.
	//
	if (argc && argv)
	{
		//
		// This will process the input and write to the output folder only if
		// there are no existing results files.
		//
		if (argc == 3)
		{
			inputFilePathString = ConvertToString(argv[1]);
			if (inputFilePathString.empty())
			{
				returnVal = UNKNOWN_ERROR;
				LoadStringFromResource(IDS_INTERNAL_ERROR, resourceString);
				wprintf_s(resourceString);
				wprintf_s(L"\n\n");
				goto exitRLMLogFileReport;
			}
			outputDirectoryString = ConvertToString(argv[2]);
			if (outputDirectoryString.empty())
			{
				returnVal = UNKNOWN_ERROR;
				LoadStringFromResource(IDS_INTERNAL_ERROR, resourceString);
				wprintf_s(resourceString);
				wprintf_s(L"\n\n");
				goto exitRLMLogFileReport;
			}
			bGoodArgs = true;
		}
		//
		// This will either write the output files, overwriting any existing results,
		// or simply check for conflicts, depending on the parameter used.
		//
		else if (argc == 4)
		{
			inputFilePathString = ConvertToString(argv[1]);
			if (inputFilePathString.empty())
			{
				returnVal = UNKNOWN_ERROR;
				LoadStringFromResource(IDS_INTERNAL_ERROR, resourceString);
				wprintf_s(resourceString);
				wprintf_s(L"\n\n");
				goto exitRLMLogFileReport;
			}
			wcsncpy_s(wcArgv, argv[2], MAX_STR_LEN);
			if (0 == _wcsicmp(wcArgv, PARM_OVERWRITE))
			{
				bOverwrite = true;
			}
			else if (0 == _wcsicmp(wcArgv, PARM_CONFLICT))
			{
				bConflicts = true;
			}
			else
			{
				//
				// The given arguments were not valid
				//
				printUsage();
				returnVal = INVALID_ARGUMENTS;
				goto exitRLMLogFileReport;
			}

			outputDirectoryString = ConvertToString(argv[3]);
			if (outputDirectoryString.empty())
			{
				returnVal = UNKNOWN_ERROR;
				LoadStringFromResource(IDS_INTERNAL_ERROR, resourceString);
				wprintf_s(resourceString);
				wprintf_s(L"\n\n");
				goto exitRLMLogFileReport;
			}
			bGoodArgs = true;
		}
	}

	//
	// If the user gave a good set of calling arguments, get busy...
	//
	if (bGoodArgs)
	{
		try
		{
			//
			// This class reads the input string, parses the RLM LIC Imaris log file, generates
			// statistics and gets it read to write out (publish) to the output folder.
			// The output names are generated based on the input name. 
			//
			// This does not write the output files. that is done below.
			//
			LogData logData(inputFilePathString, outputDirectoryString);

			//
			// Check to see if output files with the same name already exist, that is
			// if we have conflicting files.
			//
			logData.checkForExistingFiles(conflictedFileList);
			if (!conflictedFileList.empty())
			{
				//
				// If results files already exist with the output name, check
				// the overwrite flag. If the user wants them overwritten, do it.
				//
				if (bOverwrite)
				{
					//
					// Write the output files.
					//
					logData.publishResults();
					logData.publishEventDataResults();
				}
				else
				{
					//
					// Either the user said not to overwrite existing output files, which
					// is the return of CONFLICTING_FILES or they are just checking for the 
					// existance of existing files of the same name. So, if output naming 
					// conflcits exist, set the return value to 1.
					//
					if (bConflicts)
					{
						returnVal = 1;
					}
					else
					{
						returnVal = CONFLICTING_FILES;
					}
				}
			}
			else
			{
				// 
				// No output file name conflicts exist, so if the user is just checking
				// for naming conflicts, set the return value to zero. Otherwise, publish
				// the results.
				//
				if (bConflicts)
				{
					returnVal = 0;
				}
				else
				{
					//
					// Write the output files.
					//
					logData.publishResults();
					logData.publishEventDataResults();
				}
			}
		}

		//
		// Handle any exceptions, print the errors and set the return codes.
		//
		catch (InvalidIndexException excpt)
		{
			printf_s("%s\n", excpt.what());
			returnVal = INVALID_INDEX;
		}
		catch (EventDataException excpt)
		{
			printf_s("%s\n", excpt.what());
			returnVal = EVENT_DATA;
		}
		catch (INEventDetailException excpt)
		{
			printf_s("%s\n", excpt.what());
			returnVal = EVENT_DETAIL;
		}
		catch (InvalidProductVersionException excpt)
		{
			printf_s("%s\n", excpt.what());
			returnVal = INVALID_PRODUCT_VERSION;
		}
		catch (CannotOpenFileException excpt)
		{
			printf_s("%s\n", excpt.what());
			returnVal = UNABLE_TO_FIND_FILE;
		}
		catch (CannotFindDirException excpt)
		{
			printf_s("%s\n", excpt.what());
			returnVal = UNABLE_TO_FIND_DIR;
		}
		catch (InvalidFileFormatException excpt)
		{
			printf_s("%s\n", excpt.what());
			returnVal = INVALID_FILE_FORMAT;
		}
		catch (exception excpt)
		{
			printf_s("%s\n", excpt.what());
			returnVal = UNKNOWN_ERROR;
		}
	}
	else
	{
		//
		// The given arguments were not valid
		//
		printUsage();
		returnVal = INVALID_ARGUMENTS;
	}

	exitRLMLogFileReport:
	// 
	// return that status to the command line.
	//
    return(returnVal);
}
