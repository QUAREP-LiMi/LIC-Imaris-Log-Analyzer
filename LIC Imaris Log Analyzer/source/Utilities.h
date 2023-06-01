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

#pragma once

#include <vector>
#include <string>
#include <boost/date_time/gregorian/gregorian.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

using namespace std;
using namespace boost::posix_time;
using namespace boost::gregorian;

void loadDataFromFile(const string& filePath, vector<string>& fileData);

void tokenizeString(const string& delimiter,
                    const string& rawEventData,
                    vector<string>& tokens);

void untokenizeString(const string& delimiter,
                    string& rawEventData,
                    const vector<string>& tokens);

void getUniqueItems(string& item, vector<string>& uniqueItems);

void write2DVectorToFile(const string filePath,
                         const vector < vector<string> >& data,
                         const string delimiter);

void findReplaceAll(const string oldPattern,
                    const string newPattern,
                    string& rawData);

void setVectorToZero(vector<size_t>& licenseCountNumbers);
void setMatrixToZero(vector< vector<size_t> >& matrix);

string getFilenameFromFilepath(const string& filepath);

ptime stringToBoostTime(string& dateString,
                        string& timeString);

string boostTimeToString(ptime& dateTime);

template <typename T>
string toString(T& value)
{
    std::stringstream sstream;
    sstream << value;
    string str = sstream.str();

    return str;
}

void parseDataInto2DVector(const vector<string>& rawData,
                           vector< vector<string> >& allData);

void getFileListInDirectory(const string& directory, vector<string>& fileList);

bool fileExists(const string& filePath);
