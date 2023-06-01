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

#include <string>
#include <vector>
#include <map>
#include <boost/date_time/gregorian/gregorian.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

using namespace std;
using namespace boost::posix_time;
using namespace boost::gregorian;

enum fileFormat
{
    Invalid,
    ReportLog,
    ISVLog
};

class LogData
{
    public:
        LogData(const string& inputFilePath, const string& outputDirectory);
        ~LogData() {}
        void checkForExistingFiles(string& conflictedFiles);
        void publishResults();
        void publishEventDataResults();
        size_t fileFormat();
    private:
        void findFileFormat();
        void setOutputPaths();
        void extractEvents();
        void getEventIndices();
        void addYearToDate();
        void standardizeLogFormatting();
        void loadEventIntoVector(const vector<string>& allDataRow,
                                 const size_t row,
                                 const vector<size_t>& indices);
        void getConcurrentUsage();
        int getCountOffset(const size_t& row);
        void gatherConcurrentUsageData(const size_t& row,
                                       const vector<string>& licenseUsageCount,
                                       const vector<size_t>& uniqueLicenseCountsByProduct,
                                       const vector<string>& maxLicenseUsageCount,
                                       const vector<string>& reservedLicenseUsageCount,
                                       const vector<string>& maxreservedLicenseCountsByProduct);
        void getUsageDurationUser();
        void getUsageDurationHost();
        void getDeniedRequests();
        size_t getIndex(const string& name, const vector<string>& list);

        void writeSummaryData(const string& outputFilePath);
        void writeTotalDurationUsers(const string& outputFilePath);
        void writeTotalDurationHosts(const string& outputFilePath);

        // Methods that tweak the log format
        // mainly for deprecated ISV quirks
        void reformatEventName(const size_t row,
                               const string newLabel);

        void reformatUserHost(const size_t row,
                              const vector<size_t>& indices);

        void reformatProductVersion(const size_t row,
                                    const size_t col,
                                    vector<string>& allDataRow);

        void reformatToken(vector<string>& allDataRow);

        void removeInDetails(const size_t row,
                              vector<string>& allDataRow);

        void removeNoGood(const size_t row,
                          vector<string>& allDataRow);

        void licenseCountAdjust(vector<size_t>& licenseCountNumbers,
                        vector<string>& licenseCountsByProduct);

        void checkForValidProductVersion(const size_t row,
                                         const size_t col,
                                         vector<string>& allDataRow);

        void checkForUnhandledINDetails(const size_t row);

        string m_inputFilePath;
        string m_inputFileName;
        string m_outputDirectory;
        enum fileFormat m_fileFormat;
        vector<string> m_outputPaths;
        vector<string> m_rawData;
        vector< vector<string> > m_allData;
        vector< vector<string> > m_eventData;
        vector< vector<string> > m_denialEvents;
        vector< vector<string> > m_shutdownEvents;
        vector< vector<string> > m_startEvents;
        vector<string> m_uniqueProducts;
        vector<string> m_uniqueUsers;
        vector<string> m_uniqueHosts;
        
        string m_eventYear;
        string m_serverName;

        size_t m_eventIndex;
        vector<size_t> m_OUTindices;
        vector<size_t> m_INindices;
        vector<size_t> m_DENYindices;
        vector<size_t> m_STARTindices;
        vector<size_t> m_SHUTindices;
        vector<size_t> m_PRODUCTindices;

        vector< vector<string> > m_usage;
        vector< vector<string> > m_usageDuration;
        vector< vector<string> > m_usageDurationh;
        vector< vector<string> > m_usageDurationu;
        vector< vector<string> > m_deniedRequest;
        vector< vector<time_duration> > m_totalDuration;
        vector< vector<time_duration> > m_totalDurationh;
        vector< vector<time_duration> > m_totalDurationu;

        size_t m_endTimeRow;
};

enum eventIndices
{
    IndexEvent,
    IndexDate,
    IndexTime,
    IndexProduct,
    IndexVersion,
    IndexUser,
    IndexHost,
    IndexCount,
    IndexHandle,
    IndexReason,
    IndexReserved,
    IndexRLimit
};

enum RepOUTEventIndices
{
    RepOUTIndexDate = 16,
    RepOUTIndexTime = 17,
    RepOUTIndexProduct = 1,
    RepOUTIndexVersion = 2,
    RepOUTIndexUser = 4,
    RepOUTIndexHost = 5,
    RepOUTIndexCount = 8,
    RepOUTIndexHandle = 10,
    RepOUTIndexReserved = 9
};
enum RepINEventIndices
{
    RepINIndexDate = 11,
    RepINIndexTime = 12,
    RepINIndexProduct = 2,
    RepINIndexVersion = 3,
    RepINIndexUser = 4,
    RepINIndexHost = 5,
    RepINIndexCount = 8,
    RepINIndexHandle = 10,
    RepINIndexReserved = 9
};
enum RepDENYEventIndices
{
    RepDENYIndexDate = 10,
    RepDENYIndexTime = 11,
    RepDENYIndexProduct = 1,
    RepDENYIndexVersion = 2,
    RepDENYIndexUser = 3,
    RepDENYIndexHost = 4,
    RepDENYIndexCount = 7,
    RepDENYIndexReason = 7
};
enum RepSTARTEventIndices
{
    RepSTARTIndexDate = 2,
    RepSTARTIndexTime = 3,
    RepSTARTIndexServer = 1
};
enum RepSHUTEventIndices
{
    RepSHUTIndexDate = 3,
    RepSHUTIndexTime = 4
};
enum 
{
    RepPRODUCTIndexProduct = 1,
    RepPRODUCTIndexVersion = 2,
    RepPRODUCTIndexCount = 4,
    RepPRODUCTIndexRLimit = 5
};
