// Copyright 2014 Steve Robinson (author of the original code)
//
// and
// 
// Copyright 2022 Tobias Wernet (ALbert Ludwigs University Freiburg)
// 
// This file is part of the LIC Imaris Log Analyzer
// based on the original RLM Log Reader by Steve Robinson
//  
// LIC Imaris Log Analyzer is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// RLM Log Reader was distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with RLM Log Reader.  If not, see <http://www.gnu.org/licenses/>.

#include "Utilities.h"
#include "Exceptions.h"
#include <fstream>
#include <string>
#include <vector>
#include <boost/date_time/gregorian/gregorian.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

using namespace std;
using namespace boost::filesystem;

void loadDataFromFile(const string& filePath, vector<string>& fileData)
{
    string line;
    ifstream myfile (filePath.c_str());
    if (myfile.is_open())
    {
        while ( myfile.good() )
        {
            getline (myfile,line);

            // Remove extra line break, if present
            findReplaceAll("\r","", line);
            fileData.push_back(line);
        }
        myfile.close();
    }
    else
    {
        CannotOpenFileException cannotOpenFileException(filePath);
        throw cannotOpenFileException;
    }
}

void tokenizeString(const string& delimiter,
                    const string& str,
                    vector<string>& tokens)
{
    size_t startPos = 0;
    size_t endPos = 0;
    tokens.clear();
    bool withinQuotes = false;
    string localDelimiter = delimiter;

    do
    {
        startPos = str.find_first_not_of(localDelimiter, startPos);
        endPos = str.find_first_of(localDelimiter, startPos);

        if (startPos != string::npos)
        {
            if (str.at(startPos) == '"')
            {
                withinQuotes = true;
                startPos = startPos + 1;
                localDelimiter = "\"";
                endPos = str.find_first_of(localDelimiter, startPos);
                if (endPos != string::npos)
                    localDelimiter = delimiter;
            }

            tokens.push_back(str.substr(startPos, endPos - startPos));

            if (withinQuotes)
                endPos = endPos + 1;
                withinQuotes = false;
        }
        startPos = endPos;
    }
    while (endPos != string::npos);
}

void untokenizeString(const string& delimiter,
                      string& str,
                      const vector<string>& tokens)
{
    str.clear();
    for (size_t row = 0; row < tokens.size(); ++row)
    {
        str.append(tokens.at(row));
        if (row <= tokens.size())
        {
            str.append(delimiter);
        }
    }
}

void getUniqueItems(string& itemName, vector<string>& uniqueItems)
{
    bool duplicate = false;
    for (size_t item=0; item < uniqueItems.size(); ++item)
    {
        if (itemName == uniqueItems.at(item))
        {
            duplicate = true;
            break;
        }
    }

    if (! duplicate)
    {
        uniqueItems.push_back(itemName);
    }
}

void write2DVectorToFile(const string filePath,
                         const vector < vector<string> >& data,
                         const string delimiter)
{
    ofstream myfile;
    myfile.open (filePath.c_str());
    if (myfile.is_open())
    {
        for (size_t row = 0; row<data.size(); ++row)
        {
            size_t columnSize = data.at(row).size();
            for (size_t col = 0; col<columnSize; ++col)
            {
                myfile << data.at(row).at(col);
                if (col != columnSize-1)
                {
                    myfile << delimiter;
                }
            }
            myfile << "\n";
        }
        myfile.close();
    }
    else
    {
        CannotOpenFileException cannotOpenFileException(filePath);
        throw cannotOpenFileException;
    }
}

void findReplaceAll(const string oldPattern,
                    const string newPattern,
                    string& data)
{
    size_t found = 0;
    size_t oldPatternSize = oldPattern.size();

    while(true)
    {
        found = data.find(oldPattern, found);
        if (found != std::string::npos)
        {
            data.erase(found, oldPatternSize);
            data.insert(found, newPattern);
        }
        else
        {
            break;
        }
        ++found;
    }
}

void setVectorToZero(vector<size_t>& vector)
{
    for (size_t index=0; index<vector.size(); ++index)
    {
        vector.at(index) = 0;
    }
}

void setMatrixToZero(vector< vector<size_t> >& matrix)
{
    for (size_t row=0; row < matrix.size(); ++row)
    {
        for (size_t col=0; col < matrix.at(row).size(); ++col)
        {
            matrix.at(row).at(col) = 0;
        }
    }
}

string getFilenameFromFilepath(const string& filepath)
{
    string filename = filepath;

    size_t found = filename.find_last_of("/\\");
    filename = filename.substr(found+1);

    found = filename.find_last_of(".");
    filename = filename.substr(0, found);

    return filename;
}

ptime stringToBoostTime(string& dateString,
                        string& timeString)
{
    date boostDate(from_us_string(dateString));

    vector<string> timeVector;
    tokenizeString(":", timeString, timeVector);
    int intHours = atoi(timeVector.at(0).c_str());
    int intMinutes = atoi(timeVector.at(1).c_str());
    int intSeconds;

    if (timeVector.size() < 3)
    {
        intSeconds = 0;
    }
    else
    {
        intSeconds = atoi(timeVector.at(2).c_str());
    }
    ptime dateTime(boostDate, hours(intHours)+minutes(intMinutes)+seconds(intSeconds));
   
    return dateTime;
}

void parseDataInto2DVector(const vector<string>& rowData,
                           vector< vector<string> >& parsedData)
{
    string delimiter = " ";
    vector<string> eventLine;
    string rawLine;

    for (size_t line=0; line<rowData.size(); ++line)
    {
        tokenizeString(delimiter, rowData.at(line), eventLine);
        parsedData.push_back(eventLine);
    }
}

void getFileListInDirectory(const string& directory, vector<string>& fileList)
{
    if (is_directory(directory))
    {
        string filePath;
        directory_iterator end;

        for(directory_iterator iter(directory); iter != end; ++iter)
        {
            if (! is_directory( *iter ) )
            {
                filePath = toString(iter->path());
                findReplaceAll("\"", "", filePath);
                fileList.push_back(filePath);
            }
        }
    }
}

bool fileExists(const string& filePath)
{
    ifstream ifile(filePath.c_str());
    return (ifile.is_open());
}
