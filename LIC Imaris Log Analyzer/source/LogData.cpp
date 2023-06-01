// Copyright 2014 Steve Robinson (author of the original code)
//
// and
// 
// Copyright 2022 Tobias Wernet (ALbert Ludwigs University Freiburg)
// 
// This file is part of the LIC Imaris Log Analyzer (LIC_Imaris_Log_Analyzer.exe)
// based on the original RLM Log Reader by Steve Robinson
// // 
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

#include "Exceptions.h"
#include "Utilities.h"

#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <assert.h>
#include <map>
#include <boost/date_time/gregorian/gregorian.hpp>
#include "LogData.h"

using namespace std;


LogData::LogData(const string& inputFilePath, const string& outputDirectory)
{
    m_inputFilePath = inputFilePath;
    m_outputDirectory = outputDirectory;
    m_inputFileName = getFilenameFromFilepath(m_inputFilePath);

    loadDataFromFile(m_inputFilePath, m_rawData);

    findFileFormat();
    setOutputPaths();
    parseDataInto2DVector(m_rawData, m_allData);
    extractEvents();
    getConcurrentUsage();

    if (m_fileFormat == ReportLog)
    {
        getUsageDurationUser(); 
        getUsageDurationHost();
        getDeniedRequests();
    }
}

// Function to get the LOG Format. Imaris License Server RLM uses the RLM "ReportLog" Format. 
// Any ISV-related code was removed for LIC Imaris Log Analyzer since it does not contain all required data
void LogData::findFileFormat()
{
    m_fileFormat = Invalid;
    size_t found;

    // Don't search the whole file when the identifying markers are near the beginning
    size_t linesToSearch = 20;
    if (m_rawData.size() < linesToSearch)
    {
        linesToSearch = m_rawData.size();
    }

    for (size_t line=0; line<m_rawData.size(); ++line)
    {
        found = m_rawData.at(line).find("RLM Report Log Format");
        if (found!=std::string::npos)
        {
            m_fileFormat = ReportLog;
            return;
        }
        // Looking for the ISV log format, which is of this form:
        //   MM/YY HH:MM (isv)
        found = m_rawData.at(line).find("/");
        if (found!=std::string::npos)
        {
            found = m_rawData.at(line).find(":");
            if (found!=std::string::npos)
            {
                found = m_rawData.at(line).find("(");
                if (found!=std::string::npos)
                {
                    found = m_rawData.at(line).find(")");
                    if (found!=std::string::npos)
                    {
                        // RLM itself has a log file that matches the form of the ISV log file, except instead
                        // of each line containing '(isv)', each line contains '(rlm)'.
                        // This log file doesn't have usage data in it, so it's not supported.
                        found = m_rawData.at(line).find("(rlm)");
                        if (found==std::string::npos)
                        {
                            m_fileFormat = ISVLog;

                            // Throw error if ISV log is detected
                            // ISV Logs not supported for LIC Imaris Log Analyzer 
                            InvalidFileFormatException invalidFileFormatException;
                            throw invalidFileFormatException;
                            return;
                        }
                    }
                }
            }
        }
    }

    // Throw error if file format is not Report Log (RLM)
    InvalidFileFormatException invalidFileFormatException;
    throw invalidFileFormatException;
}

size_t LogData::fileFormat()
{
    return m_fileFormat;
}


void LogData::extractEvents()
{
    // Call for indices (check LogData.cpp and header LogData.h)
    getEventIndices();

    string productName;
    string userName;
    string hostName;
    string denialReason;
    size_t eventRow;

    for (size_t row=0; row<m_allData.size(); ++row)
    {
        // Check for existence of date, and if so update the year
        if (m_allData.at(row).size() == 2)
        {
            vector<string> tempVector;
            tokenizeString("/", m_allData.at(row).at(0), tempVector);
            if (tempVector.size() == 3)
            {
                m_eventYear = tempVector.at(2);
            }
        }

        if (m_allData.at(row).size() > m_eventIndex)
        {
            // Load Imaris license check-out events into vector
            if (m_allData.at(row).at(m_eventIndex) == "OUT")
            {
                loadEventIntoVector(m_allData.at(row), row, m_OUTindices);
                eventRow = m_eventData.size()-1;
                productName = m_eventData.at(eventRow).at(IndexProduct);
                getUniqueItems(productName, m_uniqueProducts);
                userName = m_eventData.at(eventRow).at(IndexUser);
                getUniqueItems(userName, m_uniqueUsers);

                // extract hostnames too for OUT events
                hostName = m_eventData.at(eventRow).at(IndexHost);
                getUniqueItems(hostName, m_uniqueHosts);
                
                eventRow = m_eventData.size()-1;
                addYearToDate();
                m_endTimeRow = eventRow;
            }

            // Load Imaris license check-in events into vector
            else if (m_allData.at(row).at(m_eventIndex) == "IN")
            {
                loadEventIntoVector(m_allData.at(row), row, m_INindices);
                eventRow = m_eventData.size()-1;
                productName = m_eventData.at(m_eventData.size()-1).at(IndexProduct);
                getUniqueItems(productName, m_uniqueProducts);
                userName = m_eventData.at(eventRow).at(IndexUser);
                getUniqueItems(userName, m_uniqueUsers);
                
                // extract hostnames too for IN events
                hostName = m_eventData.at(eventRow).at(IndexHost);
                getUniqueItems(hostName, m_uniqueHosts);
                
                eventRow = m_eventData.size()-1;
                addYearToDate();
                m_endTimeRow = eventRow;
            }

            // Load Imaris license denial events into vector
            else if (m_allData.at(row).at(m_eventIndex) == "DENY")
            {
                loadEventIntoVector(m_allData.at(row), row, m_DENYindices);
                eventRow = m_eventData.size() - 1;
                productName = m_eventData.at(m_eventData.size() - 1).at(IndexProduct);
                getUniqueItems(productName, m_uniqueProducts);
                userName = m_eventData.at(eventRow).at(IndexUser);
                getUniqueItems(userName, m_uniqueUsers);
                                
                // extract hostnames too for DENY events
                hostName = m_eventData.at(eventRow).at(IndexHost);
                getUniqueItems(hostName, m_uniqueHosts);
                
                eventRow = m_eventData.size() - 1;
                addYearToDate();
                m_denialEvents.push_back(m_eventData.at(eventRow));
                m_endTimeRow = eventRow;
            }

            // Load Imaris Log Server Start events into vector
            else if (m_allData.at(row).at(m_eventIndex) == "START")
            {
                loadEventIntoVector(m_allData.at(row), row, m_STARTindices);
                eventRow = m_eventData.size()-1;
                m_serverName = m_eventData.at(eventRow).at(3);
                m_startEvents.push_back(m_eventData.at(eventRow));

                if (m_fileFormat == ReportLog)
                {
                    vector<string> tempVector;
                    tokenizeString("/", m_allData.at(row).at(RepSTARTIndexDate), tempVector);
                    m_eventYear =  tempVector.at(2);
                    m_endTimeRow = eventRow;
                }
            }

            // Load Imaris license Server Shutdown Events into vector
            else if (m_allData.at(row).at(m_eventIndex) == "SHUTDOWN")
            {
                loadEventIntoVector(m_allData.at(row), row, m_SHUTindices);
                eventRow = m_eventData.size()-1;
                addYearToDate();
                m_shutdownEvents.push_back(m_eventData.at(eventRow));
                m_endTimeRow = eventRow;
            }

            // Load product information from Imaris License Serve rinto vector
            else if (m_allData.at(row).at(m_eventIndex) == "PRODUCT")
            {
                loadEventIntoVector(m_allData.at(row), row, m_PRODUCTindices);
                eventRow = m_eventData.size()-1;
                productName = m_eventData.at(eventRow).at(1);
                getUniqueItems(productName, m_uniqueProducts);
            }
        }
    }
}


void LogData::addYearToDate()
{
    if (m_fileFormat == ReportLog)
    {
        size_t eventRow = m_eventData.size()-1;
        string currentDate = m_eventData.at(eventRow).at(IndexDate);

        // If a log event occurs within the first minute after midnight, it is logged before
        // the string that provides the new year.  This code checks for events on Jan 1 at 00:00
        // and increments the year.
        if (currentDate == "01/01")
        {
            vector<string> timeVector;
            tokenizeString(":", m_eventData.at(eventRow).at(IndexTime), timeVector);
            if (timeVector.at(0) == "00" && timeVector.at(1) == "00")
            {
                int eventYearNumber = atoi(m_eventYear.c_str());
                ++eventYearNumber;
                m_eventYear = toString(eventYearNumber);
            }
        }
        (m_eventData.at(eventRow).at(IndexDate)).append("/" + m_eventYear);
    }
}

// Event Indices (check also header LogData.h)
void LogData::getEventIndices()
{
    if (m_fileFormat == ReportLog)
    {
        m_eventIndex = 0;

        m_OUTindices.push_back(m_eventIndex);
        m_OUTindices.push_back(RepOUTIndexDate);
        m_OUTindices.push_back(RepOUTIndexTime);
        m_OUTindices.push_back(RepOUTIndexProduct);
        m_OUTindices.push_back(RepOUTIndexVersion);
        m_OUTindices.push_back(RepOUTIndexUser);
        m_OUTindices.push_back(RepOUTIndexHost);
        m_OUTindices.push_back(RepOUTIndexCount);
        m_OUTindices.push_back(RepOUTIndexHandle);
        m_OUTindices.push_back(RepOUTIndexReserved);

        m_INindices.push_back(m_eventIndex);
        m_INindices.push_back(RepINIndexDate);
        m_INindices.push_back(RepINIndexTime);
        m_INindices.push_back(RepINIndexProduct);
        m_INindices.push_back(RepINIndexVersion);
        m_INindices.push_back(RepINIndexUser);
        m_INindices.push_back(RepINIndexHost);
        m_INindices.push_back(RepINIndexCount);
        m_INindices.push_back(RepINIndexHandle);
        m_INindices.push_back(RepINIndexReserved);

        m_DENYindices.push_back(m_eventIndex);
        m_DENYindices.push_back(RepDENYIndexDate);
        m_DENYindices.push_back(RepDENYIndexTime);
        m_DENYindices.push_back(RepDENYIndexProduct);
        m_DENYindices.push_back(RepDENYIndexVersion);
        m_DENYindices.push_back(RepDENYIndexUser);
        m_DENYindices.push_back(RepDENYIndexHost);
        m_DENYindices.push_back(RepDENYIndexCount);
        m_DENYindices.push_back(RepDENYIndexReason);


        m_STARTindices.push_back(m_eventIndex);
        m_STARTindices.push_back(RepSTARTIndexDate);
        m_STARTindices.push_back(RepSTARTIndexTime);
        m_STARTindices.push_back(RepSTARTIndexServer);

        m_SHUTindices.push_back(m_eventIndex);
        m_SHUTindices.push_back(RepSHUTIndexDate);
        m_SHUTindices.push_back(RepSHUTIndexTime);

        m_PRODUCTindices.push_back(m_eventIndex);
        m_PRODUCTindices.push_back(RepPRODUCTIndexProduct);
        m_PRODUCTindices.push_back(RepPRODUCTIndexVersion);
        m_PRODUCTindices.push_back(RepPRODUCTIndexCount);
        m_PRODUCTindices.push_back(RepPRODUCTIndexRLimit);
    }    
}

void LogData::standardizeLogFormatting()
{
    size_t i = 0;
    int licenseUsageCount = 0;

    for (size_t row=0; row<m_allData.size(); ++row)
    {
        if (m_allData.at(row).size() > m_eventIndex)
        {
            if (m_allData.at(row).at(m_eventIndex) == "OUT:")
            {   
                reformatEventName(row, "OUT");
                // reformatProductVersion(row, isvOUTIndexVersion, m_allData.at(row));
                reformatUserHost(row, m_OUTindices);
            }
            else if (m_allData.at(row).at(m_eventIndex) == "IN:")
            {
                reformatEventName(row, "IN");
                // reformatProductVersion(row, isvINIndexVersion, m_allData.at(row));
                reformatUserHost(row, m_INindices);
            }
            else if (m_allData.at(row).at(m_eventIndex) == "DENIED:")
            {
                reformatEventName(row, "DENY");
                // reformatProductVersion(row, isvDENYIndexVersion, m_allData.at(row));
                reformatUserHost(row, m_DENYindices);
            }
            else if (m_allData.at(row).at(m_eventIndex) == "Server")
            {
                reformatEventName(row, "START");
            }
            else if (m_allData.at(row).at(m_eventIndex) == "Shutdown")
            {
                reformatEventName(row, "SHUTDOWN");
            }
        }
    }
}

void LogData::reformatEventName(const size_t row,
                                const string newLabel)
{
    m_allData.at(row).at(m_eventIndex) = newLabel;
}

void LogData::reformatUserHost(const size_t row,
                               const vector<size_t>& indices)
{
    vector<string> tempVector;
    size_t userIndex = indices.at(IndexUser);
    size_t hostIndex = indices.at(IndexHost);

    tokenizeString("@", m_allData.at(row).at(userIndex), tempVector);
    m_allData.at(row).erase(m_allData.at(row).begin()+userIndex);
    m_allData.at(row).insert(m_allData.at(row).begin()+userIndex, tempVector.at(0));
    m_allData.at(row).insert(m_allData.at(row).begin()+hostIndex, tempVector.at(1));
}

void LogData::reformatProductVersion(const size_t row,
                                     const size_t col,
                                     vector<string>& allDataRow)
{
    checkForValidProductVersion(row, col, allDataRow);
    string tempString = allDataRow.at(col);
    tempString.erase(0,1);
    allDataRow.at(col) = tempString;
}

void LogData::licenseCountAdjust(vector<size_t>& licenseCountNumbers,
                        vector<string>& licenseCountsByProduct)
{
    licenseCountsByProduct.clear();
    for (size_t product=0; product<licenseCountNumbers.size(); ++product)
    {
        string licenseCountString = toString(licenseCountNumbers.at(product));
        licenseCountsByProduct.push_back(licenseCountString);
    }
}

void LogData::loadEventIntoVector(const vector<string>& allDataRow,
                                  const size_t row,
                                  const vector<size_t>& indices)
{
    vector<string> eventLine;
    if (allDataRow.size() >= indices.size())
    {
        for (size_t col=0; col<indices.size(); ++col)
        {
            eventLine.push_back(allDataRow.at(indices.at(col)));
        }
        m_eventData.push_back(eventLine);
    }
    else
    {
        EventDataException eventDataException(row+1);
        throw eventDataException;
    }
}

size_t LogData::getIndex(const string& name, const vector<string>& list)
{
    for (size_t index=0; index < list.size(); ++index)
    {
        if (list.at(index) == name)
        {
            return index;
        }
    }
    InvalidIndexException invalidIndexException(name);
    throw invalidIndexException;
}

void LogData::checkForValidProductVersion(const size_t row,
                                 const size_t col,
                                 vector<string>& allDataRow)
{
    string productVersion = allDataRow.at(col);

    // Check for the "v" at the beginning of the product version
    size_t found = productVersion.find("v");
    if (found != 0)
    {
        InvalidProductVersionException invalidProductVersionException(row+1);
        throw invalidProductVersionException;
    }
}

void LogData::getConcurrentUsage()
{
    vector<string> reservedLicenseUsageCount (m_uniqueProducts.size(), "0");
    vector<string> licenseCountsByProduct(m_uniqueProducts.size(), "0");
    vector<size_t> uniqueLicenseCountsByProduct (m_uniqueProducts.size(), 0);
    vector< vector<size_t> > licenseCountByProductAndUser;
    vector<string> maxLicenseCountsByProduct (m_uniqueProducts.size(), "0");
    vector<string> maxreservedLicenseCountsByProduct(m_uniqueProducts.size(), "0");
    vector<size_t> licenseCountNumbers (m_uniqueProducts.size(), 0);
    size_t productCountIndex;
    size_t userCountIndex;

    // Initialize matrix for Imaris license count by user and product (Imaris module)
    for (size_t row=0; row < m_uniqueUsers.size(); ++row)
    {
        vector<size_t> tempCountVector;
        for (size_t col=0; col < m_uniqueProducts.size(); ++col)
        {
            tempCountVector.push_back(0);
        }
        licenseCountByProductAndUser.push_back(tempCountVector);
    }

    vector<string> tempVector;
    tempVector.push_back("Date/Time");
    for (size_t product=0; product<m_uniqueProducts.size(); ++product)
    {
        // Set CSV Headers       
        if (m_fileFormat == ReportLog)
        {
            tempVector.push_back(m_uniqueProducts.at(product) + " Floating Licenses in use");
            tempVector.push_back(m_uniqueProducts.at(product) + " Total Licenses in use");
            tempVector.push_back(m_uniqueProducts.at(product) + " Floating Licenses Limit");
            tempVector.push_back(m_uniqueProducts.at(product) + " Reserved Licenses in use");
            tempVector.push_back(m_uniqueProducts.at(product) + " Reserved Licenses Limit");
        }
    }
    m_usage.push_back(tempVector);

    for (size_t row=0; row<m_eventData.size(); ++row)
    {
        if (m_eventData.at(row).at(IndexEvent) == "OUT")
        {
            productCountIndex = getIndex(m_eventData.at(row).at(IndexProduct), m_uniqueProducts);
            userCountIndex = getIndex(m_eventData.at(row).at(IndexUser), m_uniqueUsers);

            // Total usage
            if (m_fileFormat == ReportLog)
            {
                licenseCountsByProduct.at(productCountIndex) = m_eventData.at(row).at(IndexCount);
            }
            
            // Unique usage
            ++licenseCountByProductAndUser.at(userCountIndex).at(productCountIndex);
            if (licenseCountByProductAndUser.at(userCountIndex).at(productCountIndex) == 1)
            {
                ++uniqueLicenseCountsByProduct.at(productCountIndex);
            }

            // Reserved Imaris License Usage Data
            reservedLicenseUsageCount.at(productCountIndex) = m_eventData.at(row).at(9);

            gatherConcurrentUsageData(row, licenseCountsByProduct, uniqueLicenseCountsByProduct, maxLicenseCountsByProduct, reservedLicenseUsageCount, maxreservedLicenseCountsByProduct);
        }
        else if (m_eventData.at(row).at(IndexEvent) == "IN")
        {
            productCountIndex = getIndex(m_eventData.at(row).at(IndexProduct), m_uniqueProducts);
            userCountIndex = getIndex(m_eventData.at(row).at(IndexUser), m_uniqueUsers);

            // Total usage
            if (m_fileFormat == ReportLog)
            {
                licenseCountsByProduct.at(productCountIndex) = m_eventData.at(row).at(IndexCount);
            }
            
            // Unique usage

            // Make sure we can't iterate below zero
            // (could happen if the log file started with licenses already checked out and the first event is a check-in)
            if (licenseCountByProductAndUser.at(userCountIndex).at(productCountIndex) > 0)
            {
                --licenseCountByProductAndUser.at(userCountIndex).at(productCountIndex);
            }

            if (licenseCountByProductAndUser.at(userCountIndex).at(productCountIndex) == 0 && uniqueLicenseCountsByProduct.at(productCountIndex) > 0)
            {
                --uniqueLicenseCountsByProduct.at(productCountIndex);
            }

            if (atoi(licenseCountsByProduct.at(productCountIndex).c_str()) > 0 && uniqueLicenseCountsByProduct.at(productCountIndex) == 0)
            {
                // This deals with the special case where a report log started after licenses were checked out.
                // The log has no data on who checked out the licenses, it just gives a count of what's checked out.
                // We post "1".  The actual value would be greater than or equal to that value.
                uniqueLicenseCountsByProduct.at(productCountIndex) = 1;
                gatherConcurrentUsageData(row, licenseCountsByProduct, uniqueLicenseCountsByProduct, maxLicenseCountsByProduct, reservedLicenseUsageCount, maxreservedLicenseCountsByProduct);

                // Set the unique value back down to zero.  Otherwise, a subsequent OUT event will cause the unique users to go up
                // to "2", even though we're not sure if the check-out is unique or not.
                uniqueLicenseCountsByProduct.at(productCountIndex) = 0;
            }
            else
            {
                gatherConcurrentUsageData(row, licenseCountsByProduct, uniqueLicenseCountsByProduct, maxLicenseCountsByProduct, reservedLicenseUsageCount, maxreservedLicenseCountsByProduct);
            }
        }
        else if (m_eventData.at(row).at(IndexEvent) == "SHUTDOWN")
        {
            setVectorToZero(licenseCountNumbers);
            setVectorToZero(uniqueLicenseCountsByProduct);
            setMatrixToZero(licenseCountByProductAndUser);
            licenseCountAdjust(licenseCountNumbers, licenseCountsByProduct);
            gatherConcurrentUsageData(row, licenseCountsByProduct, uniqueLicenseCountsByProduct, maxLicenseCountsByProduct, reservedLicenseUsageCount, maxreservedLicenseCountsByProduct);
        }
        else if (m_eventData.at(row).at(IndexEvent) == "PRODUCT")
        {
            string tempProduct = m_eventData.at(row).at(1);
            productCountIndex = getIndex(tempProduct, m_uniqueProducts);
            if (m_fileFormat == ReportLog)
            {
                maxLicenseCountsByProduct.at(productCountIndex) = m_eventData.at(row).at(3);
                maxreservedLicenseCountsByProduct.at(productCountIndex) = m_eventData.at(row).at(4);
            }
        }
    }
}

int LogData::getCountOffset(const size_t& row)
{
    return atoi(m_eventData.at(row).at(IndexCount).c_str());
}

void LogData::gatherConcurrentUsageData(const size_t& row,
                                        const vector<string>& licenseUsageCount,
                                        const vector<size_t>& uniqueLicenseCountsByProduct,
                                        const vector<string>& maxLicenseUsageCount,
                                        const vector<string>& reservedLicenseUsageCount,
                                        const vector<string>& maxreservedLicenseCountsByProduct)
{
    vector<string> tempVector;
    tempVector.push_back(m_eventData.at(row).at(IndexDate) + " " + m_eventData.at(row).at(IndexTime));

    for (size_t product=0; product<licenseUsageCount.size(); ++product)
    {
        tempVector.push_back(licenseUsageCount.at(product));
        tempVector.push_back(toString(uniqueLicenseCountsByProduct.at(product)));
        if (m_fileFormat == ReportLog)
        {
            tempVector.push_back(maxLicenseUsageCount.at(product));
            tempVector.push_back(reservedLicenseUsageCount.at(product));
            tempVector.push_back(maxreservedLicenseCountsByProduct.at(product));
        }
    }
    m_usage.push_back(tempVector);
}

void LogData::getUsageDurationHost()
{
    int checkInRow = -1;

    vector<string> tempVector;
    tempVector.push_back("Checkout Date/Time");
    tempVector.push_back("Checkin Date/Time");
    tempVector.push_back("Product");
    tempVector.push_back("Version");
    tempVector.push_back("User");
    tempVector.push_back("Host");
    tempVector.push_back("Duration (HH:MM:SS)");
    m_usageDurationh.push_back(tempVector);

    // Initialize matrix for total duration by host and product (Imaris module)
    for (int row=0; row < m_uniqueHosts.size(); ++row)
    {
        vector<time_duration> tempDurationVector;
        for (int col=0; col < m_uniqueProducts.size(); ++col)
        {
            time_duration td = seconds(0);
            tempDurationVector.push_back(td);
        }
        m_totalDurationh.push_back(tempDurationVector);
    }

    for (int row=0; row < m_eventData.size(); ++row)
    {
        if (m_eventData.at(row).at(IndexEvent) == "OUT")
        {
            string handle = m_eventData.at(row).at(IndexHandle);
            string product = m_eventData.at(row).at(IndexProduct);
            string userName = m_eventData.at(row).at(IndexUser);
            string hostName = m_eventData.at(row).at(IndexHost);
            
            ptime startTime = stringToBoostTime(m_eventData.at(row).at(IndexDate),
                                                m_eventData.at(row).at(IndexTime));
            ptime endTime;

            for(int newRow=row+1; newRow < m_eventData.size(); ++newRow)
            {
                if (m_eventData.at(newRow).at(IndexEvent) == "IN")
                {
                    if (m_eventData.at(newRow).at(IndexHandle) == handle)
                    {
                        endTime = stringToBoostTime(m_eventData.at(newRow).at(IndexDate),
                                                    m_eventData.at(newRow).at(IndexTime));
                        checkInRow = newRow;
                        break;
                    }
                }
                // A shutdown forces the return of any licenses so it will be the checkin time of 
                // any checked out licenses
                if (m_eventData.at(newRow).at(IndexEvent) == "SHUTDOWN")
                {
                    endTime = stringToBoostTime(m_eventData.at(newRow).at(IndexDate),
                                                m_eventData.at(newRow).at(IndexTime));
                    checkInRow = newRow;
                    break;
                }
            }

            if (checkInRow == -1)
            {
                endTime = stringToBoostTime(m_eventData.at(m_endTimeRow).at(IndexDate),
                                            m_eventData.at(m_endTimeRow).at(IndexTime));
            }
            time_duration usageDuration = endTime - startTime;
            m_totalDurationh.at(getIndex(hostName, m_uniqueHosts)).at(getIndex(product, m_uniqueProducts)) += usageDuration;
            
            string usageDurationString = toString(usageDuration);
            vector<string> tempVector;
            string dateTimeCheckOut = m_eventData.at(row).at(IndexDate) + " " + m_eventData.at(row).at(IndexTime);

            tempVector.push_back(dateTimeCheckOut);
            if (checkInRow != -1)
            {
                string dateTimeCheckIn = m_eventData.at(checkInRow).at(IndexDate) + " " + m_eventData.at(checkInRow).at(IndexTime);
                tempVector.push_back(dateTimeCheckIn);
            }
            else
            {
                tempVector.push_back("(Still checked out)");
            }
            tempVector.push_back(m_eventData.at(row).at(IndexProduct));
            tempVector.push_back(m_eventData.at(row).at(IndexVersion));
            tempVector.push_back(m_eventData.at(row).at(IndexUser));
            tempVector.push_back(m_eventData.at(row).at(IndexHost));
            tempVector.push_back(usageDurationString);
                      
            m_usageDurationh.push_back(tempVector);
            checkInRow = -1;
        }
    }
}

void LogData::getUsageDurationUser()
{
    int checkInRow = -1;

    vector<string> tempVector;
    tempVector.push_back("Checkout Date/Time");
    tempVector.push_back("Checkin Date/Time");
    tempVector.push_back("Product");
    tempVector.push_back("Version");
    tempVector.push_back("User");
    tempVector.push_back("Host");
    tempVector.push_back("Duration (HH:MM:SS)");
    m_usageDurationu.push_back(tempVector);

    // Initialize matrix for total duration by user and product (Imaris module)
    for (int row = 0; row < m_uniqueUsers.size(); ++row)
    {
        vector<time_duration> tempDurationVector;
        for (int col = 0; col < m_uniqueProducts.size(); ++col)
        {
            time_duration td = seconds(0);
            tempDurationVector.push_back(td);
        }
        m_totalDurationu.push_back(tempDurationVector);
    }

    for (int row = 0; row < m_eventData.size(); ++row)
    {
        if (m_eventData.at(row).at(IndexEvent) == "OUT")
        {
            string handle = m_eventData.at(row).at(IndexHandle);
            string product = m_eventData.at(row).at(IndexProduct);
            string userName = m_eventData.at(row).at(IndexUser);
            string hostName = m_eventData.at(row).at(IndexHost);
            ptime startTime = stringToBoostTime(m_eventData.at(row).at(IndexDate),
                m_eventData.at(row).at(IndexTime));
            ptime endTime;

            for (int newRow = row + 1; newRow < m_eventData.size(); ++newRow)
            {
                if (m_eventData.at(newRow).at(IndexEvent) == "IN")
                {
                    if (m_eventData.at(newRow).at(IndexHandle) == handle)
                    {
                        endTime = stringToBoostTime(m_eventData.at(newRow).at(IndexDate),
                            m_eventData.at(newRow).at(IndexTime));
                        checkInRow = newRow;
                        break;
                    }
                }
                // A shutdown forces the return of any licenses so it will be the checkin time of 
                // any checked out licenses
                if (m_eventData.at(newRow).at(IndexEvent) == "SHUTDOWN")
                {
                    endTime = stringToBoostTime(m_eventData.at(newRow).at(IndexDate),
                        m_eventData.at(newRow).at(IndexTime));
                    checkInRow = newRow;
                    break;
                }
            }

            if (checkInRow == -1)
            {
                endTime = stringToBoostTime(m_eventData.at(m_endTimeRow).at(IndexDate),
                    m_eventData.at(m_endTimeRow).at(IndexTime));
            }
            time_duration usageDuration = endTime - startTime;
            m_totalDurationu.at(getIndex(userName, m_uniqueUsers)).at(getIndex(product, m_uniqueProducts)) += usageDuration;
            
            string usageDurationString = toString(usageDuration);
            vector<string> tempVector;
            string dateTimeCheckOut = m_eventData.at(row).at(IndexDate) + " " + m_eventData.at(row).at(IndexTime);

            tempVector.push_back(dateTimeCheckOut);
            if (checkInRow != -1)
            {
                string dateTimeCheckIn = m_eventData.at(checkInRow).at(IndexDate) + " " + m_eventData.at(checkInRow).at(IndexTime);
                tempVector.push_back(dateTimeCheckIn);
            }
            else
            {
                tempVector.push_back("(Still checked out)");
            }

            tempVector.push_back(m_eventData.at(row).at(IndexProduct));
            tempVector.push_back(m_eventData.at(row).at(IndexVersion));
            tempVector.push_back(m_eventData.at(row).at(IndexUser));
            tempVector.push_back(m_eventData.at(row).at(IndexHost));
            tempVector.push_back(usageDurationString);
            m_usageDurationu.push_back(tempVector);

            checkInRow = -1;
        }
    }
}

// Denied License Requests
void LogData::getDeniedRequests()
{
    int checkInRow = -1;

    vector<string> tempVector;
    tempVector.push_back("Request");
    tempVector.push_back("Product");
    tempVector.push_back("Version");
    tempVector.push_back("User");
    tempVector.push_back("Host");
    tempVector.push_back("Reason");
    m_deniedRequest.push_back(tempVector);

    for (size_t row = 0; row < m_eventData.size(); ++row)
    {
        if (m_eventData.at(row).at(IndexEvent) == "DENY")
        {
            vector<string> tempVectorx;
            string dateTimeDenied = m_eventData.at(row).at(IndexDate) + " " + m_eventData.at(row).at(IndexTime);
           
            tempVectorx.push_back(dateTimeDenied);
            tempVectorx.push_back(m_eventData.at(row).at(IndexProduct));
            tempVectorx.push_back(m_eventData.at(row).at(IndexVersion));
            tempVectorx.push_back(m_eventData.at(row).at(IndexUser));
            tempVectorx.push_back(m_eventData.at(row).at(IndexHost));
            tempVectorx.push_back(m_eventData.at(row).at(IndexCount));
            m_deniedRequest.push_back(tempVectorx);

            checkInRow = -1;
        }
    }
}

// Data Summary (TXT File) for quick evaluation
void LogData::writeSummaryData(const string& outputFilePath)
{
    ofstream myfile;
    myfile.open (outputFilePath.c_str());

    if (myfile.is_open())
    {
        myfile << "Log Data Summary For:" << "\n" << m_inputFilePath << "\n\n";
        myfile << "Server Name: " << m_serverName << "\n\n";

        size_t numberOfStarts = m_startEvents.size();
        myfile << "Server Start(s): (" << numberOfStarts << " Total)\n";
        for (size_t row = 0; row < numberOfStarts; ++row)
        {
            for (size_t col = 1; col < m_startEvents.at(row).size(); ++col)
            {
                myfile << m_startEvents.at(row).at(col) << " ";
            }
            myfile << "\n";
        }
        myfile << "\n";

        size_t numberOfShutdowns = m_shutdownEvents.size();
        myfile << "Server Shutdown(s): (" << numberOfShutdowns << " Total)\n";
        for (size_t row = 0; row < numberOfShutdowns; ++row)
        {
            for (size_t col = 1; col < m_shutdownEvents.at(row).size(); ++col)
            {
                myfile << m_shutdownEvents.at(row).at(col) << " ";
            }
            myfile << "\n";
        }
        myfile << "\n";

        size_t numberOfProducts = m_uniqueProducts.size();
        myfile << "Product(s): (" << numberOfProducts << " Total)\n";
        for (size_t row = 0; row < numberOfProducts; ++row)
        {
            myfile << m_uniqueProducts.at(row) << "\n";
        }
        myfile << "\n";

        size_t numberOfUsers = m_uniqueUsers.size();
        myfile << "Users(s): (" << numberOfUsers << " Total)\n";
        for (size_t row = 0; row < numberOfUsers; ++row)
        {
            myfile << m_uniqueUsers.at(row) << "\n";
        }
        myfile << "\n";

       size_t numberOfHosts = m_uniqueHosts.size();
        myfile << "Host(s): (" << numberOfHosts << " Total)\n";
        for (size_t row = 0; row < numberOfHosts; ++row)
        {
            myfile << m_uniqueHosts.at(row) << "\n";
        }
        myfile << "\n";
        
        // Removed Denied Events from Summary since Imaris generates a lot of denied license requests in LIC setting
        // 
        // size_t numberOfDenials = m_denialEvents.size();
        // myfile << "Denials(s): (" << numberOfDenials << " Total)\n";
        // for (size_t row = 0; row < numberOfDenials; ++row)
        // {
        //     for (size_t col = 1; col < 6; ++col)
        //     {
        //         myfile << m_denialEvents.at(row).at(col) << " ";
        //     }
        //     myfile << "\n";
        // }
        myfile.close();
    }
    else
    {
        CannotOpenFileException cannotOpenFileException(outputFilePath);
        throw cannotOpenFileException;
    }
}

void LogData::writeTotalDurationHosts(const string& outputFilePath)
{
    ofstream myfile;
    myfile.open (outputFilePath.c_str());

    if (myfile.is_open())
    {
        myfile << "Host,";
        size_t columnSize = m_uniqueProducts.size();
        for (size_t col=0; col < m_uniqueProducts.size(); ++col)
        {
            myfile << m_uniqueProducts.at(col) << " Duration (HH:MM:SS)";
            if (col != columnSize-1)
            {
                myfile << ",";
            }
        }
        myfile << "\n";

        for (size_t row=0; row < m_uniqueHosts.size(); ++row)
        {
            vector<time_duration> tempDurationVector;
            myfile << m_uniqueHosts.at(row) << ",";
            
            size_t columnSize = m_uniqueProducts.size();
            for (size_t col=0; col < columnSize; ++col)
            {
                string usageDurationString = toString(m_totalDurationh.at(row).at(col));
                myfile << usageDurationString;
                if (col != columnSize-1)
                {
                    myfile << ",";
                }
            }
            myfile << "\n";
        }
        myfile.close();
    }
    else
    {
        CannotOpenFileException cannotOpenFileException(outputFilePath);
        throw cannotOpenFileException;
    }
}

void LogData::writeTotalDurationUsers(const string& outputFilePath)
{
    ofstream myfile;
    myfile.open (outputFilePath.c_str());

    if (myfile.is_open())
    {
        myfile << "User,";
        size_t columnSize = m_uniqueProducts.size();
        for (size_t col = 0; col < m_uniqueProducts.size(); ++col)
        {
            myfile << m_uniqueProducts.at(col) << " Duration (HH:MM:SS)";
            if (col != columnSize - 1)
            {
                myfile << ",";
            }
        }
        myfile << "\n";

        for (size_t row = 0; row < m_uniqueUsers.size(); ++row)
        {
            vector<time_duration> tempDurationVector;
            myfile << m_uniqueUsers.at(row) << ",";

            size_t columnSize = m_uniqueProducts.size();
            for (size_t col = 0; col < columnSize; ++col)
            {
                string usageDurationString = toString(m_totalDurationu.at(row).at(col));
                myfile << usageDurationString;
                if (col != columnSize - 1)
                {
                    myfile << ",";
                }
            }
            myfile << "\n";
        }

        myfile.close();
    }
    else
    {
        CannotOpenFileException cannotOpenFileException(outputFilePath);
        throw cannotOpenFileException;
    }
}

void LogData::setOutputPaths()
{
    m_outputPaths.push_back(m_outputDirectory + "/" + m_inputFileName + "_LIC_Imaris_License_Summary.txt");
    m_outputPaths.push_back(m_outputDirectory + "/" + m_inputFileName + "_LIC_Imaris_Processed_Log_File.txt");
    m_outputPaths.push_back(m_outputDirectory + "/" + m_inputFileName + "_LIC_Imaris_Concurrent_License_Usage.csv");
    if (m_fileFormat == ReportLog)
    {
        m_outputPaths.push_back(m_outputDirectory + "/" + m_inputFileName + "_LIC_Imaris_License_Activity.csv");
        m_outputPaths.push_back(m_outputDirectory + "/" + m_inputFileName + "_LIC_Imaris_Total_Duration_Hosts.csv");
        m_outputPaths.push_back(m_outputDirectory + "/" + m_inputFileName + "_LIC_Imaris_Total_Duration_Users.csv");
        m_outputPaths.push_back(m_outputDirectory + "/" + m_inputFileName + "_LIC_Imaris_Denied_License_Requests.csv");
    }
}

void LogData::checkForExistingFiles(string& conflictedFileList)
{
    for (size_t file=0; file < m_outputPaths.size(); ++file)
    {
        if (fileExists(m_outputPaths.at(file)))
        {
            conflictedFileList.append(m_outputPaths.at(file));
            conflictedFileList.append("\n");
        }
    }
}

void LogData::publishResults()
{
    writeSummaryData(m_outputPaths.at(0));
    
    
     write2DVectorToFile(m_outputPaths.at(2), m_usage, ",");
    

    if (m_fileFormat == ReportLog)
    {
        write2DVectorToFile(m_outputPaths.at(3), m_usageDurationh, ",");
        write2DVectorToFile(m_outputPaths.at(6), m_deniedRequest, ",");
        writeTotalDurationHosts(m_outputPaths.at(4));
        writeTotalDurationUsers(m_outputPaths.at(5));
     }
}

void LogData::publishEventDataResults()
{
    write2DVectorToFile(m_outputPaths.at(1), m_eventData, " ");
}
